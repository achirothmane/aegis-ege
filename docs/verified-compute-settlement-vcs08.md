# VCS-08 — Live Aegis Execution Root Producer

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-07 proved that performance measurements must be rooted in an execution provenance authority distinct from the performance signer.

VCS-08 removes the last synthetic root used by that proof:

> build TrustedExecutionRoot from live Aegis runtime evidence rather than caller-invented digests.

## Live inputs

The producer consumes existing Aegis artifacts and live Linux observations:

    SignedWorkloadActivationReceipt v2
    SignedRuntimeTrustLease
    current WorkloadLifecycleState
    live LinuxProcessIdentity
    live cgroup inode identity
    SHA-256 of /proc/<pid>/exe

The activation receipt is verified with the host attestor key. The runtime trust lease is verified with the lifecycle authority key and must still be valid at the evaluation time.

## Cross-binding requirements

The producer fails closed unless all of the following agree:

- DeviceID across lifecycle, activation, and runtime-trust lease;
- WorkloadID across lifecycle, activation, runtime-trust lease, and compute profile;
- lifecycle generation and lifecycle epoch;
- activation receipt digest;
- current runtime-trust lease digest and lease epoch;
- runtime-trust expiry;
- signed Aegis WorkloadSpecDigest and compute WorkloadDigest;
- activation/runtime cgroup identity and live observed cgroup inode;
- activation process identity and live process identity;
- runtime-trust boot ID hash and live process boot ID;
- compute ArtifactDigest and SHA-256 of the live executable bytes.

## Produced VCS-07 root

On success VCS-08 produces:

    TrustedExecutionRoot
      activation_receipt_digest
      process_identity_digest
      cgroup_identity_digest
      boot_measurement_digest

The first three fields are derived directly from verified/current Aegis and Linux artifacts.

The fourth field is currently an **attestation-lineage digest** over:

    verified runtime-trust lease digest
    remote attestation decision digest committed by that lease
    bootstrap digest
    runtime policy digest
    runtime-trust boot ID hash
    runtime-trust lease epoch
    monotonic installed/deadline boot-ns values
    remote verification time
    runtime-trust expiry

This is deliberately not described as a direct PCR7 measurement.

## Why the PCR7 claim is bounded

Aegis now has a TPM monotonic root that detects measured-boot PCR drift, but that state currently lives inside the server implementation and is not an exported kernelfabric artifact.

VCS-08 therefore does not pierce the server boundary or duplicate TPM semantics inside compute settlement.

The current claim is:

> the compute execution root is live-bound to Aegis's signed runtime-trust lineage and current Linux boot/process/cgroup/artifact identity.

A later step may export a narrow measured-boot commitment from the generic runtime layer and replace/extend the attestation-lineage digest without teaching compute settlement about TPM PCR numbers.

## Live Linux proof

The VCS-08 test does not fabricate a process identity.

It observes the running CI test process through /proc and cgroup v2, hashes the actual executable bytes, constructs signed Aegis activation/runtime-trust artifacts around those live observations, and feeds the resulting root through the full VCS-07 settlement path.

Positive path:

    live /proc process
          +
    live cgroup inode
          +
    actual executable SHA-256
          +
    signed activation receipt
          +
    signed current runtime-trust lease
          ↓
    TrustedExecutionRoot
          ↓
    VCS-07 rooted measurement provenance
          ↓
    SETTLED

## Executable falsification cases

VCS-08 rejects:

- live process identity substitution;
- cgroup identity substitution;
- executable artifact substitution;
- stale runtime-trust lease digest in lifecycle state;
- runtime-trust epoch mismatch;
- expired runtime-trust lease;
- boot identity mismatch;
- compute profile bound to a different WorkloadSpecDigest;
- tampered activation receipt.

All failures occur before VCS-07 is allowed to treat the root as trusted.

## Boundary

VCS-08 adds only:

    internal/computesettlement/live_root.go
    internal/computesettlement/live_root_linux.go
    internal/computesettlement/live_root_linux_test.go
    docs/verified-compute-settlement-vcs08.md

No change is made to kernel, governedaction, internal/outcome, internal/ege, kernelfabric, or server.

That is intentional: VCS-08 consumes existing generic runtime evidence instead of moving compute semantics into the enforcement fabric.

## Complexity Dividend

    VCS-01  outcome reconciliation
    VCS-02  evidence independence
    VCS-03  attested hardware continuity
    VCS-04  metered quantity continuity
    VCS-05  performance quality continuity
    VCS-06  workload/profile measurement binding
    VCS-07  runtime-rooted measurement provenance
    VCS-08  live Aegis execution-root production

The held-out compute domain now consumes real Aegis runtime primitives without requiring a compute-specific kernel change.
