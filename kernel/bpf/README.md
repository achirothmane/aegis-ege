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


## Experimental taint evidence adapter

`aegis_taint.bpf.c` is a separate experimental artifact for the Muse-class
M01-M03 hardening work. It does **not** replace the signed network DecisionCapsule
adapter and it is not yet part of the production bootstrap manifest.

The artifact compiles four programs:

- `lsm/file_permission` — observes configured sensitive-source reads and
  propagates taint through file reads/writes;
- `tracepoint/sched/sched_process_fork` — propagates the parent's process taint
  to a child process;
- `cgroup/connect4`;
- `cgroup/connect6` — fail closed when a protected cgroup has propagation
  uncertainty or when the current process carries labels not admitted by that
  cgroup's taint allow-mask.

The kernel transports an opaque 64-bit label set. It does not embed meanings
such as "private" or "secret"; userspace profile code maps bit positions to
semantic labels and fails closed on unmapped bits.

Pinned-map names reserved by the experiment are:

```text
aegis_tsrc      configured sensitive file identities -> labels
aegis_ftaint    propagated file identities -> labels
aegis_ptaint    process TGID -> labels
aegis_tcgroups  protected cgroup IDs
aegis_tallow    admitted egress label mask per cgroup
aegis_tfail     propagation uncertainty count per cgroup
aegis_tevents   ring-buffer evidence stream
aegis_tacct     stream loss accounting
```

Propagation is monotonic. A tainted process write unions labels into the file;
a later reader unions file labels into its process state. A fork copies the
parent's current label set. If a process/file propagation map update fails, the
adapter records propagation uncertainty; protected egress requires an initialized
zero-valued uncertainty entry and denies when the counter is non-zero.

### Claim boundary

CI compiles the BPF-LSM/tracepoint/cgroup object with `clang -target bpf` and
the Go side mirrors/decodes its fixed ABI.

The repository now also contains a signed two-phase install path:

```text
aegis-taint-bpf-sign
  -> exact signed taint manifest

aegis-taint-bpf-loader
  -> verify signature + digest + exact ELF surface
  -> load and attach all four hooks
  -> pin programs/maps/links
  -> signed local bootstrap receipt
  -> cgroup still NOT protected

aegis-taint-plan
  -> resolve regular-file device/inode identities without following symlinks
  -> emit explicit source-label/allow-mask plan

aegis-taint-activate
  -> verify signed bootstrap receipt + current boot + pinned links
  -> initialize source labels / allow-mask / uncertainty counter
  -> set protected-cgroup flag LAST
```

This improves crash safety: a partial install is inert for the target cgroup.
Activation has one explicit final effect boundary, and its state can be observed
after a lost reply via the protected-cgroup map.

It does **not** yet prove:

- that a real target Linux kernel enables BPF LSM and accepts all four programs;
- a privileged native end-to-end file-read/fork/file/connect attack schedule;
- that fork/file/connect hooks completely mediate a hostile workload;
- that a process cannot escape by changing cgroups/namespaces or by exploiting
  an unmodelled IPC path;
- safe lifetime cleanup for TGID/inode reuse without weakening fail-closed
  behavior.

Until the privileged native attach-and-attack test passes, M01-M03 remain
kernel-artifact + signed-install candidates and executable semantic tests, not
production Linux taint claims.
