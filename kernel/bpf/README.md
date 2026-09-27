# Kernel enforcement adapter

This directory contains the first kernel adapter for Aegis-EGE's enforcement fabric.

It compiles two cgroup socket-address programs:

- `cgroup/connect4`
- `cgroup/connect6`

Both programs are fail-closed. Once attached to a protected cgroup, an outbound connect is allowed only when a matching DecisionCapsule and current scope fence agree on:

- boot instance;
- authority term;
- decision epoch;
- revocation epoch;
- local monotonic lease deadline;
- ALLOW decision.

The program first checks an exact destination scope and then a cgroup-wide wildcard scope.

## Build

```bash
make -C kernel/bpf
```

## Signed load and attach

Direct unsigned loading is disabled. Root privileges and a mounted bpffs are required, but the artifact must first be authorized by a release signer.

Generate keys and sign the compiled object:

```bash
go run ./cmd/aegis-bpf-keygen \
  -private-out release-signing.key \
  -public-out release-signing.pub

go run ./cmd/aegis-bpf-sign \
  -artifact kernel/bpf/build/aegis_connect.bpf.o \
  -private-key release-signing.key \
  -out aegis-bpf-bootstrap.signed.json
```

Generate a separate host attestation key and bootstrap:

```bash
go run ./cmd/aegis-bpf-keygen \
  -private-out host-attestation.key \
  -public-out host-attestation.pub

sudo go run ./cmd/aegis-bpf-loader \
  -artifact kernel/bpf/build/aegis_connect.bpf.o \
  -manifest aegis-bpf-bootstrap.signed.json \
  -trust-key release-signing.pub \
  -attestation-key host-attestation.key \
  -cgroup /sys/fs/cgroup/<protected-cgroup> \
  -receipt aegis-bpf-bootstrap.receipt.json
```

The legacy `kernel/bpf/load.sh` exits non-zero so signature verification cannot be bypassed accidentally.

The loader pins programs under:

```text
/sys/fs/bpf/aegis-ege/programs
```

and maps under:

```text
/sys/fs/bpf/aegis-ege/maps
```

Userspace installs scope fences and DecisionCapsules through the pinned maps. The Go package `internal/kernelfabric` provides a bpftool-backed `KernelStore` for those updates.

The object also pins:

```text
/sys/fs/bpf/aegis-ege/maps/aegis_ev_events
/sys/fs/bpf/aegis-ege/maps/aegis_ev_acct
```

`EvidenceReader` consumes the ring buffer and compares its observed sequence with the kernel accounting map. Ring-buffer reservation failures increment the kernel `lost` counter and consume a sequence number, making evidence loss detectable even under backpressure.

This is the cgroup network adapter only. XDP and BPF-LSM are separate enforcement adapters and are not implied by this directory.


For the trust model, TOCTOU staging, post-load verification, partial-attach rollback, and local-attestation boundary, see [../../docs/signed-bpf-loader-bootstrap.md](../../docs/signed-bpf-loader-bootstrap.md).
