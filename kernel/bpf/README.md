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

The artifact compiles eleven programs:

- `lsm/file_permission` — observes configured sensitive-source reads and
  propagates taint through file reads/writes;
- `raw_tracepoint/sched_process_fork` — propagates the parent's process taint
  to a child process;
- `lsm/inode_rename`;
- `lsm/inode_unlink` — invalidate source-identity continuity when a registered
  source inode participates in rename/replacement or unlink;
- `lsm/sb_mount`, `lsm/sb_umount`, `lsm/sb_remount`, `lsm/move_mount`,
  `lsm/sb_pivotroot` — once source lifetime is armed, conservatively invalidate
  source continuity on mount-topology mutation attempts that can change what a
  bound source path resolves to without touching the enrolled inode;
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
aegis_tprobe     armed source-enrollment thread TID -> random probe token
aegis_tprobe_r   kernel-observed (TID, device, inode) -> probe token
aegis_tcgroups  protected cgroup IDs
aegis_tallow    admitted egress label mask per cgroup
aegis_tfail     propagation uncertainty count per cgroup
aegis_tdirty    global source-identity invalidation counter
aegis_tarmed    source-lifetime topology guard arm state
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
the Go side mirrors/decodes its fixed ABI. Protected egress now also requires
`aegis_tdirty == 0`; registered-source rename/replacement/unlink and armed
mount-topology mutation attempts move source identity continuity to fail-closed
DIRTY.

The repository now also contains a signed two-phase install path:

```text
aegis-taint-bpf-sign
  -> exact signed taint manifest

aegis-taint-bpf-loader
  -> verify signature + digest + exact ELF surface
  -> load and attach all eleven hooks
  -> pin programs/maps/links
  -> signed local bootstrap receipt
  -> cgroup still NOT protected

aegis-taint-plan
  -> open each regular source without following symlinks
  -> arm a random per-thread kernel identity probe
  -> perform one controlled read on the already-open fd
  -> collect every device/inode identity observed by BPF-LSM
  -> disarm before activation
  -> emit explicit source-label/allow-mask plan

aegis-taint-activate
  -> verify signed bootstrap receipt + current boot + pinned links
  -> install enrolled source identities while target cgroup is still inactive
  -> arm mount-topology source-lifetime invalidation
  -> kernel-probe every bound source path again
  -> require exact enrolled/current identity-set equality
  -> require source-identity DIRTY counter == 0
  -> initialize allow-mask / propagation uncertainty
  -> set protected-cgroup flag LAST
```

This improves crash safety: a partial install is inert for the target cgroup.
Activation has one explicit final effect boundary, and its state can be observed
after a lost reply via the protected-cgroup map.

The privileged native workflow now boots a BPF selftests kernel when the
GitHub-hosted kernel lacks BPF-LSM. It mounts a real OverlayFS source fixture,
kernel-enrolls the merged-path secret before activation, then proves
read/fork/file/connect enforcement end-to-end. In the proof run, userspace
`stat(2)` exposed one overlay identity while the LSM observed both the overlay
and underlying identity; both were enrolled and the later read tainted the
process.

The native harness also attacks the enrollment/activation boundary. After an
initial enrollment of device 38/inode 6 (with the corresponding underlying
identity), it atomically replaces the source before activation. Activation
re-probes the bound path, observes inode 12 instead, rejects the stale plan, and
only succeeds after explicit re-enrollment of the new kernel identity set.

A second enrolled lower-layer file exercises OverlayFS copy-up. Its enrolled
kernel identities were device 37/inode 7 and device 38/inode 7. After copy-up,
the underlying identity moved to device 37/inode 14 while the OverlayFS virtual
identity remained device 38/inode 7. The dirty counter stayed zero and the
clean child became tainted through the stable enrolled overlay identity before
its connect was denied.

Finally, the harness atomically replaces the active source again. The enrolled
userspace inode 12 becomes inode 13. The rename guard advances
`aegis_tdirty` (two registered identities were invalidated in this run), and a
clean child remains unable to egress even though the replacement inode itself
was never enrolled.

A separate privileged schedule bind-mounts a different regular file directly
onto an enrolled source path after activation. The original inode is neither
renamed nor unlinked, but the armed `sb_mount` lifetime guard advances
`aegis_tdirty`. A clean child reads the substituted file and remains untainted,
yet its connect is denied because source-path continuity is no longer provable.
This closes the tested mount-substitution laundering path without pretending
that `(device,inode)` is an eternal source identity.

It does **not** yet prove:

- source continuity across every filesystem-specific copy-up implementation,
  mount namespace propagation edge case, or source-lifetime cleanup schedule;
- allocator-level same-number inode reuse as a directly forced native schedule;
  the current bounded guarantee is that registered-source unlink/rename makes
  continuity DIRTY before such reuse can be trusted;
- that fork/file/connect hooks completely mediate a hostile workload;
- that a process cannot escape by changing cgroups/namespaces or by exploiting
  an unmodelled IPC path;
- safe lifetime cleanup for TGID/inode reuse without weakening fail-closed
  behavior.

The native result earns a bounded claim: a regular sensitive source can be
registered from the identities the loaded LSM actually observes, including a
tested OverlayFS merged-path read, without activating the target cgroup first.
The enrollment -> activation mutation window is revalidated at commit time,
the tested OverlayFS copy-up preserves taint through a stable enrolled virtual
identity, and post-activation replacement/unlink-style identity invalidation is
fail-closed rather than silently treating a new inode as clean.
Production-complete Linux taint containment remains outside this claim.
