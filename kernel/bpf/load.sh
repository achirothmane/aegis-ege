#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 <aegis_connect.bpf.o> <cgroup-v2-path> [bpffs-root]" >&2
  exit 2
fi

OBJ="$1"
CGROUP_PATH="$2"
ROOT="${3:-/sys/fs/bpf/aegis-ege}"
PROG_DIR="$ROOT/programs"
MAP_DIR="$ROOT/maps"

if [[ ! -f "$OBJ" ]]; then
  echo "BPF object not found: $OBJ" >&2
  exit 1
fi
if [[ ! -d "$CGROUP_PATH" ]]; then
  echo "cgroup path not found: $CGROUP_PATH" >&2
  exit 1
fi
if ! mountpoint -q /sys/fs/bpf; then
  echo "bpffs must already be mounted at /sys/fs/bpf" >&2
  exit 1
fi
if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool is required" >&2
  exit 1
fi

mkdir -p "$PROG_DIR" "$MAP_DIR"

bpftool prog loadall "$OBJ" "$PROG_DIR" pinmaps "$MAP_DIR"

bpftool cgroup attach "$CGROUP_PATH" connect4 pinned "$PROG_DIR/aegis_connect4" multi
bpftool cgroup attach "$CGROUP_PATH" connect6 pinned "$PROG_DIR/aegis_connect6" multi

echo "Aegis kernel enforcement attached."
echo "Programs: $PROG_DIR"
echo "Maps:     $MAP_DIR"
