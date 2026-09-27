# Signed BPF Loader Bootstrap

This layer closes the unsigned-loader gap in the Kernel Enforcement Fabric.

The governing rule is:

> A BPF object is not eligible for attach merely because it exists on disk. The loader must verify a signed authorization manifest, verify the exact artifact bytes, verify the loaded kernel objects, and emit a signed bootstrap receipt bound to the current host boot.

## Roles

Two Ed25519 key roles are intentionally separate.

### Release signer

The release signer authorizes a specific compiled BPF artifact.

It signs:

```text
artifact SHA-256
artifact size
kernel ABI version
validity window
expected program names/types/attach types
expected map names/types
```

The release private key belongs in an offline or build-authority environment. It is not required on the target host.

### Host attestor

The host attestor signs what the target host actually loaded.

Its receipt binds:

```text
signed manifest digest
release signer key id
artifact digest and size
boot-id hash
kernel release
kernel lockdown observation
bpffs root
target cgroup
loaded program ids/names/types/tags
loaded map ids/names/types/shapes
completion time
```

The host attestation private key is local to the target host and must be stored with mode `0600` or stricter.

## Trust flow

```text
build aegis_connect.bpf.o
        |
        v
release signer
        |
        v
SignedBootstrapManifest
        |
        +----------------------------+
        |                            |
        v                            v
target host                    trusted release public key
        |                            |
        +------------+---------------+
                     v
              aegis-bpf-loader
                     |
          verify manifest signature
                     |
          stage + hash exact bytes
                     |
          capture host snapshot
                     |
          bpftool loadall + pinmaps
                     |
          inspect every expected pin
                     |
          attach connect4/connect6
                     |
          sign BootstrapReceipt
                     v
          SignedBootstrapReceipt
```

## Canonical signatures

Manifest and receipt signatures use separate domain-separated canonical payloads:

```text
aegis-ege/bpf-bootstrap-manifest/v1\0
aegis-ege/bpf-bootstrap-receipt/v1\0
```

Lists are normalized before signing so equivalent manifests do not depend on input order.

## Artifact TOCTOU protection

The loader does not hash the original object and later load the same mutable pathname.

Instead it:

1. opens the supplied object;
2. copies it into a private temporary directory;
3. hashes the bytes while copying;
4. verifies signed size + SHA-256;
5. fsyncs the staged file;
6. changes it to read-only mode;
7. loads that staged path through bpftool;
8. removes the staging directory after bootstrap.

This closes the ordinary unprivileged verify-then-swap gap between artifact verification and load.

## Post-load verification

The signed manifest describes the kernel objects expected after load.

Before any cgroup attach, the loader queries every pinned object with JSON bpftool output and verifies:

### Programs

```text
pin name
kernel program id != 0
program name
program type
non-empty program tag
attach type
```

### Maps

```text
map id != 0
map name
map type
key size
value size
max entries
```

A mismatch prevents attach.

## BPF object-name gate

Linux BPF object names are limited to 15 characters. The manifest validator rejects longer kernel program/map names.

The evidence maps therefore use explicit kernel-safe names:

```text
aegis_ev_events
aegis_ev_acct
```

rather than relying on silent truncation.

## Partial attach rollback

The first network adapter requires both:

```text
connect4
connect6
```

If one attach succeeds and a later attach fails, the loader detaches the already-attached programs in reverse order.

This avoids leaving the target cgroup in a silently half-protected state.

## Legacy unsigned path

`kernel/bpf/load.sh` is intentionally disabled.

It exits non-zero and directs operators to the signed bootstrap commands. Keeping the old direct `bpftool prog loadall` path would make signature enforcement optional and therefore meaningless.

## Commands

### Generate release-signing keys

```bash
go run ./cmd/aegis-bpf-keygen \
  -private-out release-signing.key \
  -public-out release-signing.pub
```

### Sign a compiled object

```bash
go run ./cmd/aegis-bpf-sign \
  -artifact kernel/bpf/build/aegis_connect.bpf.o \
  -private-key release-signing.key \
  -out aegis-bpf-bootstrap.signed.json
```

### Generate a separate host-attestation key

Run the key generator again with different output files:

```bash
go run ./cmd/aegis-bpf-keygen \
  -private-out host-attestation.key \
  -public-out host-attestation.pub
```

### Verified bootstrap on the target host

Root privileges, bpftool, cgroup v2, and a mounted bpffs are required.

```bash
sudo go run ./cmd/aegis-bpf-loader \
  -artifact kernel/bpf/build/aegis_connect.bpf.o \
  -manifest aegis-bpf-bootstrap.signed.json \
  -trust-key release-signing.pub \
  -attestation-key host-attestation.key \
  -cgroup /sys/fs/cgroup/<protected-cgroup> \
  -receipt aegis-bpf-bootstrap.receipt.json
```

The loader resolves bpftool once to an absolute executable path before crossing the bootstrap boundary.

## Initial-bootstrap semantics

This v1 loader is deliberately **initial-load only**.

If a signed manifest expects a program or map pin that already exists, bootstrap fails instead of deleting or overwriting it.

Hot upgrade requires a separate upgrade protocol with map compatibility, old/new program coexistence, attach replacement semantics, and rollback. It must not be simulated by deleting existing pins.

## Deployment invariant

The loader cannot stop an unrelated orchestrator from starting a workload before protection is attached.

Therefore deployment must enforce:

```text
no workload activation
until
SignedBootstrapReceipt exists and verifies
```

The receipt is the handoff artifact between bootstrap and workload activation.

## Attestation boundary

This is **local cryptographic attestation**, not hardware-rooted remote attestation.

It proves, relative to:

- the trusted release public key;
- the host attestation private key;
- the loader/bpftool/kernel trusted computing base;

what signed artifact was accepted and what kernel objects were observed at bootstrap time.

It does **not** yet provide:

```text
TPM quote
PCR binding
IMA measurement-log verification
fs-verity enforcement
Secure Boot proof
remote verifier challenge/nonce
hardware-backed host identity
```

Those belong to the next attestation layer and should not be implied by this v1 receipt.

## Threat model

This layer is designed to stop or expose:

- unsigned BPF artifacts;
- artifact replacement after signing;
- manifest tampering;
- expired bootstrap authorization;
- wrong program/map types after load;
- unsafe partial attach;
- accidental reuse of the legacy unsigned loader;
- kernel object-name truncation mismatches.

It does not claim to survive a fully privileged attacker that can replace the loader, bpftool, kernel, trusted public key, and host attestation key simultaneously.
