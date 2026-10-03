#!/usr/bin/env bash
set -euo pipefail

STATE="${AEGIS_TAINT_REBOOT_STATE:-internal/kernelfabric/testdata/taint_host_reboot_state.json}"
mkdir -p "$(dirname "$STATE")"
STATE="$(realpath -m "$STATE")"

KERNEL="${AEGIS_TAINT_REBOOT_KERNEL:-ghcr.io/cilium/ci-kernels:stable-selftests}"
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"

mkdir -p "$(dirname "$STATE")"
rm -f "$STATE"
rm -rf "$STATE.history"

run_phase() {
  local phase="$1"

  sudo -E env \
    "PATH=$PATH" \
    "CGO_ENABLED=0" \
    "AEGIS_TAINT_REBOOT_PHASE=$phase" \
    "AEGIS_TAINT_REBOOT_STATE=$STATE" \
    "$VIMTO" \
      -kernel "$KERNEL" -- \
      go test -count=1 -tags=taintnative \
        -run "^TestNativeTaintHostRebootBoundary$" \
        -v ./internal/kernelfabric
}

echo "== boot A: establish boot-bound authority and real bpffs pin =="
run_phase before

if [[ ! -s "$STATE" ]]; then
  echo "boot A did not persist reboot handoff state" >&2
  exit 1
fi

echo "== boot B: reset old authority, re-enroll fresh source, restore effect authority, and persist history =="
run_phase after

if [[ ! -s "$STATE.history/head.json" ]]; then
  echo "boot B did not persist durable recovery history" >&2
  exit 1
fi

echo "== boot C: verify durable history without resurrecting Boot-B authority =="
run_phase history

rm -f "$STATE"
rm -rf "$STATE.history"

echo "host reboot trust-reset, fresh re-enrollment, and durable recovery history proof passed"
