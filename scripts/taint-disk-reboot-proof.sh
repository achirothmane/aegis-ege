#!/usr/bin/env bash
set -euo pipefail

RECORD="${AEGIS_TAINT_DISK_REBOOT_STATE:-internal/kernelfabric/testdata/taint_disk_reboot_record.json}"
KEY="${AEGIS_TAINT_DISK_REBOOT_KEY:-internal/kernelfabric/testdata/taint_disk_reboot_record.pub}"
KERNEL="${AEGIS_TAINT_DISK_REBOOT_KERNEL:-ghcr.io/cilium/ci-kernels:stable-selftests}"
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"

mkdir -p "$(dirname "$RECORD")" "$(dirname "$KEY")"
RECORD="$(realpath -m "$RECORD")"
KEY="$(realpath -m "$KEY")"
rm -f "$RECORD" "$KEY"

run_phase() {
  local phase="$1"
  sudo -E env \
    "PATH=$PATH" \
    "CGO_ENABLED=0" \
    "AEGIS_TAINT_DISK_REBOOT_PHASE=$phase" \
    "AEGIS_TAINT_DISK_REBOOT_STATE=$RECORD" \
    "AEGIS_TAINT_DISK_REBOOT_KEY=$KEY" \
    "$VIMTO" \
      -kernel "$KERNEL" -- \
      go test -count=1 -tags=taintnative \
        -run "^TestNativeTaintDiskBackedRebootBoundary$" \
        -v ./internal/kernelfabric
}

echo "== boot A: persist signed committed recovery record and kernel state =="
run_phase before

if [[ ! -s "$RECORD" || ! -s "$KEY" ]]; then
  echo "boot A did not persist durable recovery evidence" >&2
  exit 1
fi

echo "== boot B: keep disk record historical-only and rebuild authority from fresh evidence =="
run_phase after

rm -f "$RECORD" "$KEY"
echo "disk-backed reboot recovery proof passed"
