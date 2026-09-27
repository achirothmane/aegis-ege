#!/usr/bin/env bash
set -euo pipefail

cat >&2 <<'EOF'
Unsigned BPF loading through kernel/bpf/load.sh is disabled.

Use the signed bootstrap path instead:
  1. aegis-bpf-sign       (offline/build authority)
  2. aegis-bpf-loader     (target host)

See docs/signed-bpf-loader-bootstrap.md.
EOF

exit 1
