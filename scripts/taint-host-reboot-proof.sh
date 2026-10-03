#!/usr/bin/env bash
set -euo pipefail

STATE="${AEGIS_TAINT_REBOOT_STATE:-internal/kernelfabric/testdata/taint_host_reboot_state.json}"
KERNEL="${AEGIS_TAINT_REBOOT_KERNEL:-ghcr.io/cilium/ci-kernels:stable-selftests}"
VIMTO="${VIMTO:-$(go env GOPATH)/bin/vimto}"

mkdir -p "$(dirname "$STATE")"
rm -f "$STATE"

run_phase() {
  local phase="$1"
  sudo -E env     "PATH=$PATH"     "CGO_ENABLED=0"     "$VIMTO"       -kernel "$KERNEL" --       env         "AEGIS_TAINT_REBOOT_PHASE=$phase"         "AEGIS_TAINT_REBOOT_STATE=$STATE"         go test -count=1 -tags=taintnative           -run "^TestNativeTaintHostRebootBoundary$"           -v ./internal/kernelfabric
}

echo "== boot A: establish boot-bound authority and real bpffs pin =="
run_phase before

if [[ ! -s "$STATE" ]]; then
  echo "boot A did not persist reboot handoff state" >&2
  exit 1
fi

echo "== boot B: require trust reset and fresh boot authority =="
run_phase after

rm -f "$STATE"

echo "host reboot trust-reset proof passed"
