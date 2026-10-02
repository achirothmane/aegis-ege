#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /absolute/path/to/aegis_taint.bpf.o" >&2
  exit 2
fi

artifact="$1"
repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "native VM test must run as root inside the guest" >&2
  exit 1
fi

mkdir -p /sys/fs/bpf /sys/kernel/security /sys/fs/cgroup
if ! mountpoint -q /sys/fs/bpf; then
  mount -t bpf bpf /sys/fs/bpf
fi
if ! mountpoint -q /sys/kernel/security; then
  mount -t securityfs securityfs /sys/kernel/security
fi
if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" != "cgroup2fs" ]]; then
  mount -t cgroup2 none /sys/fs/cgroup
fi

echo "guest_kernel=$(uname -r)"
echo "guest_cmdline=$(cat /proc/cmdline)"
echo "guest_lsm=$(cat /sys/kernel/security/lsm)"

if ! grep -Eq '(^|,)bpf(,|$)' /sys/kernel/security/lsm; then
  echo "BPF LSM is not active in the VM; native proof cannot run" >&2
  exit 1
fi
if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  echo "kernel BTF is unavailable in the VM" >&2
  exit 1
fi
if [[ ! -w /sys/fs/cgroup ]]; then
  echo "cgroup v2 root is not writable in the VM" >&2
  exit 1
fi
if [[ ! -r "$artifact" ]]; then
  echo "taint BPF artifact is not visible inside the VM: $artifact" >&2
  exit 1
fi

export AEGIS_TAINT_BPF_OBJECT="$artifact"
go test -count=1 -tags=taintnative \
  -run "^(TestNativeTaintReadForkFileAndEgress|TestTaintNativeHelper)$" \
  -v ./internal/kernelfabric
