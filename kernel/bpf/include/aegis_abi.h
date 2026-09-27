#ifndef AEGIS_EGE_KERNEL_ABI_H
#define AEGIS_EGE_KERNEL_ABI_H

#include <linux/types.h>

#define AEGIS_ABI_VERSION 1

#define AEGIS_ACTION_NETWORK_CONNECT 1

#define AEGIS_DECISION_BLOCK 0
#define AEGIS_DECISION_ALLOW 1

#define AEGIS_AF_WILDCARD 0
#define AEGIS_AF_INET 2
#define AEGIS_AF_INET6 10

#define AEGIS_EVIDENCE_EVENT_VERSION 1
#define AEGIS_EVIDENCE_EVENT_ENFORCEMENT 1

#define AEGIS_VERDICT_DENY 0
#define AEGIS_VERDICT_ALLOW 1

struct aegis_scope_key {
	__u64 cgroup_id;
	__u32 action_class;
	__u32 address_family;
	__u32 destination_addr[4];
	__u32 destination_port;
	__u32 protocol;
};

struct aegis_scope_fence_key {
	__u64 cgroup_id;
	__u32 action_class;
	__u32 reserved;
};

struct aegis_scope_fence_state {
	__u8 boot_id_hash[32];
	__u64 authority_term;
	__u64 decision_epoch;
	__u64 revocation_epoch;
};

struct aegis_decision_capsule {
	__u8 decision_id_hash[32];
	__u8 subject_hash[32];
	__u8 action_hash[32];
	__u8 policy_hash[32];
	__u8 evidence_hash[32];
	__u8 boot_id_hash[32];
	__u64 authority_term;
	__u64 decision_epoch;
	__u64 revocation_epoch;
	__u64 installed_at_mono_ns;
	__u64 deadline_mono_ns;
	__u32 decision;
	__u32 constraints;
};

struct aegis_evidence_event {
	__u64 sequence;
	__u64 observed_at_mono_ns;
	__u64 cgroup_id;
	__u64 authority_term;
	__u64 decision_epoch;
	__u64 revocation_epoch;
	__u8 decision_id_hash[32];
	__u32 action_class;
	__u32 verdict;
	__u32 reason;
	__u32 address_family;
	__u32 destination_addr[4];
	__u32 destination_port;
	__u32 protocol;
	__u32 abi_version;
	__u32 event_type;
};

struct aegis_evidence_accounting {
	__u64 sequence;
	__u64 emitted;
	__u64 lost;
};

_Static_assert(sizeof(struct aegis_scope_key) == 40, "aegis_scope_key ABI drift");
_Static_assert(sizeof(struct aegis_scope_fence_key) == 16, "aegis_scope_fence_key ABI drift");
_Static_assert(sizeof(struct aegis_scope_fence_state) == 56, "aegis_scope_fence_state ABI drift");
_Static_assert(sizeof(struct aegis_decision_capsule) == 240, "aegis_decision_capsule ABI drift");
_Static_assert(sizeof(struct aegis_evidence_event) == 128, "aegis_evidence_event ABI drift");
_Static_assert(sizeof(struct aegis_evidence_accounting) == 24, "aegis_evidence_accounting ABI drift");

#endif
