// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/types.h>

#include "include/aegis_taint_abi.h"

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

struct super_block {
	__u32 s_dev;
} __attribute__((preserve_access_index));

struct inode {
	struct super_block *i_sb;
	unsigned long i_ino;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct dentry {
	struct inode *d_inode;
} __attribute__((preserve_access_index));

struct task_struct {
	int pid;
	int tgid;
} __attribute__((preserve_access_index));

struct taint_emit_input {
	__u64 cgroup_id;
	__u64 file_device;
	__u64 file_inode;
	__u64 labels;
	__u32 tgid;
	__u32 related_tgid;
	__u32 event_type;
	__u32 operation;
};

static void *(*bpf_map_lookup_elem)(const void *map, const void *key) =
	(void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(const void *map, const void *key,
				   const void *value, __u64 flags) =
	(void *)BPF_FUNC_map_update_elem;
static __u64 (*bpf_ktime_get_ns)(void) =
	(void *)BPF_FUNC_ktime_get_ns;
static __u64 (*bpf_get_current_pid_tgid)(void) =
	(void *)BPF_FUNC_get_current_pid_tgid;
static __u64 (*bpf_get_current_cgroup_id)(void) =
	(void *)BPF_FUNC_get_current_cgroup_id;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *unsafe_ptr) =
	(void *)BPF_FUNC_probe_read_kernel;
static void *(*bpf_ringbuf_reserve)(void *ringbuf, __u64 size, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_reserve;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) =
	(void *)BPF_FUNC_ringbuf_submit;

#define BPF_CORE_READ_INTO(dst, src, field) \
	bpf_probe_read_kernel((dst), sizeof(*(dst)), \
		__builtin_preserve_access_index(&((src)->field)))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 32768);
	__type(key, struct aegis_taint_file_key);
	__type(value, __u64);
} aegis_tsrc SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);
	__type(value, __u64);
} aegis_tprobe SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct aegis_taint_probe_key);
	__type(value, __u64);
} aegis_tprobe_r SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, struct aegis_taint_file_key);
	__type(value, __u64);
} aegis_ftaint SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);
	__type(value, __u64);
} aegis_ptaint SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u32);
} aegis_tcgroups SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} aegis_tallow SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);
	__type(value, __u64);
} aegis_tfail SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} aegis_tdirty SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} aegis_tarmed SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} aegis_tevents SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct aegis_taint_accounting);
} aegis_tacct SEC(".maps");

static __always_inline __u32 current_tgid(void)
{
	return (__u32)(bpf_get_current_pid_tgid() >> 32);
}

static __always_inline __u32 current_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid();
}

static __always_inline int protected_cgroup(__u64 cgroup_id)
{
	__u32 *enabled = bpf_map_lookup_elem(&aegis_tcgroups, &cgroup_id);
	return enabled && *enabled;
}

static __always_inline void mark_failure(__u64 cgroup_id)
{
	__u64 one = 1;
	__u64 *count = bpf_map_lookup_elem(&aegis_tfail, &cgroup_id);
	if (count)
		__sync_fetch_and_add(count, 1);
	else
		bpf_map_update_elem(&aegis_tfail, &cgroup_id, &one, BPF_ANY);
}

static __always_inline void emit_event(const struct taint_emit_input *input)
{
	__u32 zero = 0;
	struct aegis_taint_accounting *accounting =
		bpf_map_lookup_elem(&aegis_tacct, &zero);
	if (!accounting)
		return;

	__u64 sequence = __sync_fetch_and_add(&accounting->sequence, 1) + 1;
	struct aegis_taint_event *event =
		bpf_ringbuf_reserve(&aegis_tevents, sizeof(*event), 0);
	if (!event) {
		__sync_fetch_and_add(&accounting->lost, 1);
		return;
	}

	event->sequence = sequence;
	event->observed_at_mono_ns = bpf_ktime_get_ns();
	event->cgroup_id = input->cgroup_id;
	event->file_device = input->file_device;
	event->file_inode = input->file_inode;
	event->labels = input->labels;
	event->tgid = input->tgid;
	event->related_tgid = input->related_tgid;
	event->event_type = input->event_type;
	event->operation = input->operation;
	event->abi_version = AEGIS_TAINT_ABI_VERSION;
	event->reserved = 0;

	bpf_ringbuf_submit(event, 0);
	__sync_fetch_and_add(&accounting->emitted, 1);
}

static __always_inline int file_key_from_inode(
	struct inode *inode,
	struct aegis_taint_file_key *key)
{
	struct super_block *sb = 0;
	unsigned long ino = 0;
	__u32 dev = 0;

	if (!inode || !key)
		return -1;
	if (BPF_CORE_READ_INTO(&ino, inode, i_ino))
		return -1;
	if (BPF_CORE_READ_INTO(&sb, inode, i_sb) || !sb)
		return -1;
	if (BPF_CORE_READ_INTO(&dev, sb, s_dev))
		return -1;

	key->device = dev;
	key->inode = (__u64)ino;
	return 0;
}

static __always_inline int file_key_from_file(
	struct file *file,
	struct aegis_taint_file_key *key)
{
	struct inode *inode = 0;

	if (!file || !key)
		return -1;
	if (BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode)
		return -1;
	return file_key_from_inode(inode, key);
}

static __always_inline int file_key_from_dentry(
	struct dentry *dentry,
	struct aegis_taint_file_key *key)
{
	struct inode *inode = 0;

	if (!dentry || !key)
		return -1;
	if (BPF_CORE_READ_INTO(&inode, dentry, d_inode) || !inode)
		return -1;
	return file_key_from_inode(inode, key);
}

static __always_inline int source_lifetime_armed(void)
{
	__u32 zero = 0;
	__u32 *armed = bpf_map_lookup_elem(&aegis_tarmed, &zero);
	return armed && *armed;
}

static __always_inline void invalidate_source_continuity(
	__u64 file_device,
	__u64 file_inode,
	__u64 labels)
{
	__u32 zero = 0;
	__u64 *dirty = bpf_map_lookup_elem(&aegis_tdirty, &zero);
	if (dirty)
		__sync_fetch_and_add(dirty, 1);

	struct taint_emit_input invalidated = {
		.cgroup_id = bpf_get_current_cgroup_id(),
		.file_device = file_device,
		.file_inode = file_inode,
		.labels = labels,
		.tgid = current_tgid(),
		.event_type = AEGIS_TAINT_EVENT_SOURCE_INVALIDATED,
		.operation = AEGIS_TAINT_OP_IDENTITY_CHANGE,
	};
	emit_event(&invalidated);
}

static __always_inline void invalidate_source_identity(
	const struct aegis_taint_file_key *key)
{
	if (!key)
		return;

	__u64 *labels = bpf_map_lookup_elem(&aegis_tsrc, key);
	if (!labels || !*labels)
		return;

	invalidate_source_continuity(key->device, key->inode, *labels);
}

static __always_inline void invalidate_source_topology(void)
{
	if (!source_lifetime_armed())
		return;
	invalidate_source_continuity(0, 0, 0);
}

static __always_inline int union_process_taint(
	__u64 cgroup_id,
	__u32 tgid,
	__u64 labels,
	const struct aegis_taint_file_key *file_key,
	__u32 event_type)
{
	if (!labels)
		return 0;

	__u64 next = labels;
	__u64 *existing = bpf_map_lookup_elem(&aegis_ptaint, &tgid);
	if (existing)
		next |= *existing;

	if (bpf_map_update_elem(&aegis_ptaint, &tgid, &next, BPF_ANY)) {
		mark_failure(cgroup_id);
		struct taint_emit_input failed = {
			.cgroup_id = cgroup_id,
			.file_device = file_key ? file_key->device : 0,
			.file_inode = file_key ? file_key->inode : 0,
			.labels = labels,
			.tgid = tgid,
			.event_type = AEGIS_TAINT_EVENT_PROPAGATION_FAILURE,
			.operation = AEGIS_TAINT_OP_READ,
		};
		emit_event(&failed);
		return -13;
	}

	struct taint_emit_input propagated = {
		.cgroup_id = cgroup_id,
		.file_device = file_key ? file_key->device : 0,
		.file_inode = file_key ? file_key->inode : 0,
		.labels = next,
		.tgid = tgid,
		.event_type = event_type,
		.operation = AEGIS_TAINT_OP_READ,
	};
	emit_event(&propagated);
	return 0;
}

SEC("lsm/file_permission")
int aegis_fperm(__u64 *ctx)
{
	/*
	 * BPF LSM is a tracing-style program type: R1 is the trampoline context,
	 * not the first LSM argument. Keep the exported BPF entry point in the
	 * canonical single-context form (equivalent to libbpf's BPF_PROG macro)
	 * and decode file_permission(file, mask, ret) from that context.
	 */
	struct file *file = (struct file *)ctx[0];
	int mask = (int)ctx[1];
	int ret = (int)ctx[2];

	if (ret)
		return ret;

	__u64 cgroup_id = bpf_get_current_cgroup_id();

	struct aegis_taint_file_key file_key = {};
	if (file_key_from_file(file, &file_key)) {
		/*
		 * A source-identity probe is armed only by trusted userspace for the
		 * current Linux thread. If the kernel cannot derive the file identity
		 * while that probe is armed, fail the controlled enrollment read.
		 */
		__u32 tid = current_tid();
		__u64 *probe_token = bpf_map_lookup_elem(&aegis_tprobe, &tid);
		if (probe_token && (mask & AEGIS_TAINT_MAY_READ))
			return -13;
		if (!protected_cgroup(cgroup_id))
			return 0;
		mark_failure(cgroup_id);
		struct taint_emit_input failed = {
			.cgroup_id = cgroup_id,
			.tgid = current_tgid(),
			.event_type = AEGIS_TAINT_EVENT_PROPAGATION_FAILURE,
		};
		emit_event(&failed);
		return -13;
	}

	__u32 tid = current_tid();
	__u64 *probe_token = bpf_map_lookup_elem(&aegis_tprobe, &tid);
	if (probe_token && (mask & AEGIS_TAINT_MAY_READ)) {
		struct aegis_taint_probe_key probe_key = {
			.tid = tid,
			.device = file_key.device,
			.inode = file_key.inode,
		};
		__u64 token = *probe_token;
		if (bpf_map_update_elem(
				&aegis_tprobe_r,
				&probe_key,
				&token,
				BPF_ANY))
			return -13;
	}

	if (!protected_cgroup(cgroup_id))
		return 0;

	__u32 tgid = current_tgid();

	if (mask & AEGIS_TAINT_MAY_WRITE) {
		__u64 *process_labels = bpf_map_lookup_elem(&aegis_ptaint, &tgid);
		if (process_labels && *process_labels) {
			__u64 next = *process_labels;
			__u64 *file_labels = bpf_map_lookup_elem(&aegis_ftaint, &file_key);
			if (file_labels)
				next |= *file_labels;
			if (bpf_map_update_elem(&aegis_ftaint, &file_key, &next, BPF_ANY)) {
				mark_failure(cgroup_id);
				struct taint_emit_input failed = {
					.cgroup_id = cgroup_id,
					.file_device = file_key.device,
					.file_inode = file_key.inode,
					.labels = next,
					.tgid = tgid,
					.event_type = AEGIS_TAINT_EVENT_PROPAGATION_FAILURE,
					.operation = AEGIS_TAINT_OP_WRITE,
				};
				emit_event(&failed);
				return -13;
			}
			struct taint_emit_input propagated = {
				.cgroup_id = cgroup_id,
				.file_device = file_key.device,
				.file_inode = file_key.inode,
				.labels = next,
				.tgid = tgid,
				.event_type = AEGIS_TAINT_EVENT_PROPAGATED_WRITE,
				.operation = AEGIS_TAINT_OP_WRITE,
			};
			emit_event(&propagated);
		}
	}

	if (mask & AEGIS_TAINT_MAY_READ) {
		__u64 labels = 0;
		__u64 *source_labels = bpf_map_lookup_elem(&aegis_tsrc, &file_key);
		if (source_labels)
			labels |= *source_labels;
		__u64 *file_labels = bpf_map_lookup_elem(&aegis_ftaint, &file_key);
		if (file_labels)
			labels |= *file_labels;

		struct taint_emit_input observed = {
			.cgroup_id = cgroup_id,
			.file_device = file_key.device,
			.file_inode = file_key.inode,
			.labels = labels,
			.tgid = tgid,
			.event_type = AEGIS_TAINT_EVENT_FILE_READ_OBSERVED,
			.operation = AEGIS_TAINT_OP_READ,
		};
		emit_event(&observed);

		if (labels) {
			__u32 event_type = source_labels ?
				AEGIS_TAINT_EVENT_SOURCE_READ :
				AEGIS_TAINT_EVENT_PROPAGATED_READ;
			int rc = union_process_taint(
				cgroup_id, tgid, labels, &file_key, event_type);
			if (rc)
				return rc;
		}
	}

	return 0;
}

SEC("lsm/inode_rename")
int aegis_trename(__u64 *ctx)
{
	struct dentry *old_dentry = (struct dentry *)ctx[1];
	struct dentry *new_dentry = (struct dentry *)ctx[3];
	int ret = (int)ctx[4];

	if (ret)
		return ret;

	struct aegis_taint_file_key key = {};
	if (!file_key_from_dentry(old_dentry, &key))
		invalidate_source_identity(&key);

	key.device = 0;
	key.inode = 0;
	if (!file_key_from_dentry(new_dentry, &key))
		invalidate_source_identity(&key);

	return 0;
}

SEC("lsm/inode_unlink")
int aegis_tunlink(__u64 *ctx)
{
	struct dentry *dentry = (struct dentry *)ctx[1];
	int ret = (int)ctx[2];

	if (ret)
		return ret;

	struct aegis_taint_file_key key = {};
	if (!file_key_from_dentry(dentry, &key))
		invalidate_source_identity(&key);

	return 0;
}

SEC("lsm/sb_mount")
int aegis_tmount(__u64 *ctx)
{
	int ret = (int)ctx[5];
	if (ret)
		return ret;
	invalidate_source_topology();
	return 0;
}

SEC("lsm/sb_umount")
int aegis_tumount(__u64 *ctx)
{
	int ret = (int)ctx[2];
	if (ret)
		return ret;
	invalidate_source_topology();
	return 0;
}

SEC("lsm/sb_remount")
int aegis_tremount(__u64 *ctx)
{
	int ret = (int)ctx[2];
	if (ret)
		return ret;
	invalidate_source_topology();
	return 0;
}

SEC("lsm/move_mount")
int aegis_tmove(__u64 *ctx)
{
	int ret = (int)ctx[2];
	if (ret)
		return ret;
	invalidate_source_topology();
	return 0;
}

SEC("lsm/sb_pivotroot")
int aegis_tpivot(__u64 *ctx)
{
	int ret = (int)ctx[2];
	if (ret)
		return ret;
	invalidate_source_topology();
	return 0;
}

SEC("raw_tracepoint/sched_process_fork")
int aegis_fork(struct bpf_raw_tracepoint_args *ctx)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	if (!protected_cgroup(cgroup_id))
		return 0;

	__u32 parent_tgid = current_tgid();
	struct task_struct *child = (struct task_struct *)ctx->args[1];
	int child_tgid_raw = 0;
	if (!child || BPF_CORE_READ_INTO(&child_tgid_raw, child, tgid) ||
	    child_tgid_raw <= 0) {
		mark_failure(cgroup_id);
		struct taint_emit_input failed = {
			.cgroup_id = cgroup_id,
			.tgid = parent_tgid,
			.event_type = AEGIS_TAINT_EVENT_PROPAGATION_FAILURE,
			.operation = AEGIS_TAINT_OP_FORK,
		};
		emit_event(&failed);
		return 0;
	}
	__u32 child_tgid = (__u32)child_tgid_raw;

	__u64 *labels = bpf_map_lookup_elem(&aegis_ptaint, &parent_tgid);
	if (!labels || !*labels)
		return 0;

	__u64 inherited = *labels;
	if (bpf_map_update_elem(&aegis_ptaint, &child_tgid, &inherited, BPF_ANY)) {
		mark_failure(cgroup_id);
		struct taint_emit_input failed = {
			.cgroup_id = cgroup_id,
			.labels = inherited,
			.tgid = parent_tgid,
			.related_tgid = child_tgid,
			.event_type = AEGIS_TAINT_EVENT_PROPAGATION_FAILURE,
			.operation = AEGIS_TAINT_OP_FORK,
		};
		emit_event(&failed);
		return 0;
	}

	struct taint_emit_input propagated = {
		.cgroup_id = cgroup_id,
		.labels = inherited,
		.tgid = parent_tgid,
		.related_tgid = child_tgid,
		.event_type = AEGIS_TAINT_EVENT_FORK_PROPAGATION,
		.operation = AEGIS_TAINT_OP_FORK,
	};
	emit_event(&propagated);
	return 0;
}

static __always_inline int enforce_taint_egress(void)
{
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	if (!protected_cgroup(cgroup_id))
		return 1;

	__u32 tgid = current_tgid();
	__u64 labels = 0;
	__u64 *process_labels = bpf_map_lookup_elem(&aegis_ptaint, &tgid);
	if (process_labels)
		labels = *process_labels;

	/*
	 * A protected cgroup is not ready for taint-governed egress until trusted
	 * userspace has initialized its propagation-failure counter. Missing
	 * uncertainty state therefore fails closed.
	 */
	__u32 zero = 0;
	__u64 *source_dirty = bpf_map_lookup_elem(&aegis_tdirty, &zero);
	__u64 *failures = bpf_map_lookup_elem(&aegis_tfail, &cgroup_id);
	if (!source_dirty || *source_dirty || !failures || *failures) {
		struct taint_emit_input denied = {
			.cgroup_id = cgroup_id,
			.labels = labels,
			.tgid = tgid,
			.event_type = AEGIS_TAINT_EVENT_EGRESS_DENY,
			.operation = AEGIS_TAINT_OP_CONNECT,
		};
		emit_event(&denied);
		return 0;
	}

	__u64 allowed = 0;
	__u64 *allowed_ptr = bpf_map_lookup_elem(&aegis_tallow, &cgroup_id);
	if (allowed_ptr)
		allowed = *allowed_ptr;

	if (labels & ~allowed) {
		struct taint_emit_input denied = {
			.cgroup_id = cgroup_id,
			.labels = labels,
			.tgid = tgid,
			.event_type = AEGIS_TAINT_EVENT_EGRESS_DENY,
			.operation = AEGIS_TAINT_OP_CONNECT,
		};
		emit_event(&denied);
		return 0;
	}

	struct taint_emit_input allowed_event = {
		.cgroup_id = cgroup_id,
		.labels = labels,
		.tgid = tgid,
		.event_type = AEGIS_TAINT_EVENT_EGRESS_ALLOW,
		.operation = AEGIS_TAINT_OP_CONNECT,
	};
	emit_event(&allowed_event);
	return 1;
}

SEC("cgroup/connect4")
int aegis_tconn4(struct bpf_sock_addr *ctx)
{
	(void)ctx;
	return enforce_taint_egress();
}

SEC("cgroup/connect6")
int aegis_tconn6(struct bpf_sock_addr *ctx)
{
	(void)ctx;
	return enforce_taint_egress();
}

char LICENSE[] SEC("license") = "GPL";
