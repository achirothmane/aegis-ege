#!/usr/bin/env bash
set -u

supported=true
reasons=()

note_failure() {
  supported=false
  reasons+=("$1")
}

if [[ "$(id -u)" -ne 0 ]] && ! command -v sudo >/dev/null 2>&1; then
  note_failure "root-or-sudo-unavailable"
fi

if ! mountpoint -q /sys/fs/bpf 2>/dev/null; then
  if ! sudo mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
    note_failure "bpffs-unavailable"
  fi
fi

if ! mountpoint -q /sys/kernel/security 2>/dev/null; then
  if ! sudo mount -t securityfs securityfs /sys/kernel/security 2>/dev/null; then
    note_failure "securityfs-unavailable"
  fi
fi

if [[ ! -r /sys/kernel/security/lsm ]]; then
  note_failure "lsm-list-unavailable"
else
  lsm_list="$(cat /sys/kernel/security/lsm)"
  if ! grep -Eq '(^|,)bpf(,|$)' <<<"$lsm_list"; then
    note_failure "bpf-lsm-not-enabled"
  fi
fi

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  note_failure "kernel-btf-unavailable"
fi

if [[ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null || true)" != "cgroup2fs" ]]; then
  note_failure "cgroup-v2-unavailable"
fi

if ! sudo test -w /sys/fs/cgroup 2>/dev/null; then
  note_failure "cgroup-v2-not-writable"
fi

if [[ "$supported" == "true" ]]; then
  status="SUPPORTED"
else
  status="UNSUPPORTED"
fi

echo "native_taint_environment=$status"
echo "kernel=$(uname -r)"
if [[ -r /sys/kernel/security/lsm ]]; then
  echo "lsm=$(cat /sys/kernel/security/lsm)"
fi
if ((${#reasons[@]})); then
  printf 'reason=%s\n' "${reasons[@]}"
fi
echo "supported=$supported"

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "supported=$supported" >>"$GITHUB_OUTPUT"
  echo "status=$status" >>"$GITHUB_OUTPUT"
  {
    echo "reasons<<EOF"
    printf '%s\n' "${reasons[@]}"
    echo "EOF"
  } >>"$GITHUB_OUTPUT"
fi
