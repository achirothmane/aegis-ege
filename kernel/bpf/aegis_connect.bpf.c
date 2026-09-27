// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/types.h>

#include "include/aegis_abi.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static __u64 (*bpf_ktime_get_ns)(void) =
	(void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_cgroup_id)(void) =
	(void *)BPF_FUNC_get_current_cgroup_id;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct aegis_scope_key);
	__type(value, struct aegis_decision_capsule);
} aegis_capsules SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, struct aegis_scope_fence_key);
	__type(value, struct aegis_scope_fence_state);
} aegis_fences SEC(".maps");

enum aegis_stat_index {
	AEGIS_STAT_ALLOW = 0,
	AEGIS_STAT_MISSING_FENCE = 1,
	AEGIS_STAT_MISSING_CAPSULE = 2,
	AEGIS_STAT_BOOT_MISMATCH = 3,
	AEGIS_STAT_AUTHORITY_MISMATCH = 4,
	AEGIS_STAT_DECISION_SUPERSEDED = 5,
	AEGIS_STAT_REVOKED = 6,
	AEGIS_STAT_EXPIRED = 7,
	AEGIS_STAT_BLOCKED = 8,
	AEGIS_STAT_MAX = 9,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, AEGIS_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} aegis_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} aegis_ev_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct aegis_evidence_accounting);
} aegis_ev_acct SEC(".maps");

static __always_inline void bump_stat(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&aegis_stats, &index);
	if (value)
		*value += 1;
}

static __always_inline void emit_evidence(
	struct aegis_scope_key *scope,
	struct aegis_decision_capsule *capsule,
	struct aegis_scope_fence_state *fence,
	__u32 verdict,
	__u32 reason)
{
	__u32 zero = 0;
	struct aegis_evidence_accounting *accounting =
		bpf_map_lookup_elem(&aegis_ev_acct, &zero);
	if (!accounting)
		return;

	__u64 sequence = __sync_fetch_and_add(&accounting->sequence, 1) + 1;
	struct aegis_evidence_event *event =
		bpf_ringbuf_reserve(&aegis_ev_events, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&accounting->lost, 1);
		return;
	}

	event->sequence = sequence;
	event->observed_at_mono_ns = bpf_ktime_get_ns();
	event->cgroup_id = scope->cgroup_id;
	event->action_class = scope->action_class;
	event->verdict = verdict;
	event->reason = reason;
	event->address_family = scope->address_family;
	event->destination_port = scope->destination_port;
	event->protocol = scope->protocol;
	event->abi_version = AEGIS_EVIDENCE_EVENT_VERSION;
	event->event_type = AEGIS_EVIDENCE_EVENT_ENFORCEMENT;

#pragma unroll
	for (int i = 0; i < 4; i++)
		((__u32 *)event->destination_addr)[i] = scope->destination_addr[i];

	if (capsule) {
		event->authority_term = capsule->authority_term;
		event->decision_epoch = capsule->decision_epoch;
		event->revocation_epoch = capsule->revocation_epoch;
#pragma unroll
		for (int i = 0; i < 32; i++)
			event->decision_id_hash[i] = capsule->decision_id_hash[i];
	} else {
		event->authority_term = fence ? fence->authority_term : 0;
		event->decision_epoch = fence ? fence->decision_epoch : 0;
		event->revocation_epoch = fence ? fence->revocation_epoch : 0;
#pragma unroll
		for (int i = 0; i < 32; i++)
			event->decision_id_hash[i] = 0;
	}

	bpf_ringbuf_submit(event, 0);
	__sync_fetch_and_add(&accounting->emitted, 1);
}

static __always_inline int hash_equal(const __u8 *a, const __u8 *b)
{
#pragma unroll
	for (int i = 0; i < 32; i++) {
		if (a[i] != b[i])
			return 0;
	}
	return 1;
}

static __always_inline __u32 port_to_host(__u32 raw)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	return (__u32)__builtin_bswap16((__u16)raw);
#else
	return (__u32)((__u16)raw);
#endif
}

static __always_inline struct aegis_decision_capsule *
lookup_capsule(struct aegis_scope_key *exact)
{
	struct aegis_decision_capsule *capsule =
		bpf_map_lookup_elem(&aegis_capsules, exact);
	if (capsule)
		return capsule;

	struct aegis_scope_key wildcard = {};
	wildcard.cgroup_id = exact->cgroup_id;
	wildcard.action_class = exact->action_class;
	return bpf_map_lookup_elem(&aegis_capsules, &wildcard);
}

static __always_inline int enforce_connect(struct bpf_sock_addr *ctx)
{
	__u64 now = bpf_ktime_get_ns();
	struct aegis_scope_key scope = {};
	scope.cgroup_id = bpf_get_current_cgroup_id();
	scope.action_class = AEGIS_ACTION_NETWORK_CONNECT;
	scope.address_family = ctx->user_family;
	scope.destination_port = port_to_host(ctx->user_port);
	scope.protocol = ctx->protocol;

	if (ctx->user_family == AEGIS_AF_INET) {
		scope.destination_addr[0] = ctx->user_ip4;
	} else if (ctx->user_family == AEGIS_AF_INET6) {
#pragma unroll
		for (int i = 0; i < 4; i++)
			scope.destination_addr[i] = ctx->user_ip6[i];
	} else {
		bump_stat(AEGIS_STAT_BLOCKED);
		emit_evidence(&scope, 0, 0, AEGIS_VERDICT_DENY, AEGIS_STAT_BLOCKED);
		return 0;
	}

	struct aegis_scope_fence_key fence_key = {
		.cgroup_id = scope.cgroup_id,
		.action_class = scope.action_class,
	};
	struct aegis_scope_fence_state *fence =
		bpf_map_lookup_elem(&aegis_fences, &fence_key);
	if (!fence) {
		bump_stat(AEGIS_STAT_MISSING_FENCE);
		emit_evidence(&scope, 0, 0, AEGIS_VERDICT_DENY, AEGIS_STAT_MISSING_FENCE);
		return 0;
	}

	struct aegis_decision_capsule *capsule = lookup_capsule(&scope);
	if (!capsule) {
		bump_stat(AEGIS_STAT_MISSING_CAPSULE);
		emit_evidence(&scope, 0, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_MISSING_CAPSULE);
		return 0;
	}

	if (!hash_equal(capsule->boot_id_hash, fence->boot_id_hash)) {
		bump_stat(AEGIS_STAT_BOOT_MISMATCH);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_BOOT_MISMATCH);
		return 0;
	}
	if (capsule->authority_term != fence->authority_term) {
		bump_stat(AEGIS_STAT_AUTHORITY_MISMATCH);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_AUTHORITY_MISMATCH);
		return 0;
	}
	if (capsule->decision_epoch != fence->decision_epoch) {
		bump_stat(AEGIS_STAT_DECISION_SUPERSEDED);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_DECISION_SUPERSEDED);
		return 0;
	}
	if (capsule->revocation_epoch != fence->revocation_epoch) {
		bump_stat(AEGIS_STAT_REVOKED);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_REVOKED);
		return 0;
	}

	if (!capsule->deadline_mono_ns || now > capsule->deadline_mono_ns) {
		bump_stat(AEGIS_STAT_EXPIRED);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_EXPIRED);
		return 0;
	}
	if (capsule->decision != AEGIS_DECISION_ALLOW) {
		bump_stat(AEGIS_STAT_BLOCKED);
		emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_DENY, AEGIS_STAT_BLOCKED);
		return 0;
	}

	bump_stat(AEGIS_STAT_ALLOW);
	emit_evidence(&scope, capsule, fence, AEGIS_VERDICT_ALLOW, AEGIS_STAT_ALLOW);
	return 1;
}

SEC("cgroup/connect4")
int aegis_connect4(struct bpf_sock_addr *ctx)
{
	return enforce_connect(ctx);
}

SEC("cgroup/connect6")
int aegis_connect6(struct bpf_sock_addr *ctx)
{
	return enforce_connect(ctx);
}

char LICENSE[] SEC("license") = "GPL";
