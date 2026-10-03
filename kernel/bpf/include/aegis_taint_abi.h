#ifndef AEGIS_EGE_TAINT_ABI_H
#define AEGIS_EGE_TAINT_ABI_H

#include <linux/types.h>

#define AEGIS_TAINT_ABI_VERSION 1

#define AEGIS_TAINT_OP_READ 1
#define AEGIS_TAINT_OP_WRITE 2
#define AEGIS_TAINT_OP_FORK 3
#define AEGIS_TAINT_OP_CONNECT 4
#define AEGIS_TAINT_OP_IDENTITY_CHANGE 5

#define AEGIS_TAINT_EVENT_SOURCE_READ 1
#define AEGIS_TAINT_EVENT_PROPAGATED_READ 2
#define AEGIS_TAINT_EVENT_PROPAGATED_WRITE 3
#define AEGIS_TAINT_EVENT_FORK_PROPAGATION 4
#define AEGIS_TAINT_EVENT_PROPAGATION_FAILURE 5
#define AEGIS_TAINT_EVENT_EGRESS_ALLOW 6
#define AEGIS_TAINT_EVENT_EGRESS_DENY 7
#define AEGIS_TAINT_EVENT_FILE_READ_OBSERVED 8
#define AEGIS_TAINT_EVENT_SOURCE_INVALIDATED 9

#define AEGIS_TAINT_MAY_WRITE 2
#define AEGIS_TAINT_MAY_READ 4

struct aegis_taint_file_key {
	__u64 device;
	__u64 inode;
};

struct aegis_taint_probe_key {
	__u32 tid;
	__u32 reserved;
	__u64 device;
	__u64 inode;
};

struct aegis_taint_event {
	__u64 sequence;
	__u64 observed_at_mono_ns;
	__u64 cgroup_id;
	__u64 file_device;
	__u64 file_inode;
	__u64 labels;
	__u32 tgid;
	__u32 related_tgid;
	__u32 event_type;
	__u32 operation;
	__u32 abi_version;
	__u32 reserved;
};

struct aegis_taint_accounting {
	__u64 sequence;
	__u64 emitted;
	__u64 lost;
};

_Static_assert(sizeof(struct aegis_taint_file_key) == 16, "aegis_taint_file_key ABI drift");
_Static_assert(sizeof(struct aegis_taint_probe_key) == 24, "aegis_taint_probe_key ABI drift");
_Static_assert(sizeof(struct aegis_taint_event) == 72, "aegis_taint_event ABI drift");
_Static_assert(sizeof(struct aegis_taint_accounting) == 24, "aegis_taint_accounting ABI drift");

#endif
