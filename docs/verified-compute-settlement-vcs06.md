# VCS-06 — Workload-Bound Performance / Benchmark Integrity

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-05 proved that a contract-bound performance envelope can distinguish SETTLED, CREDIT_DUE, DISPUTED, and UNKNOWN without promoting NCCL, tokens/sec, or other performance semantics into the governance kernel.

VCS-06 asks the next question:

> Did the performance evidence measure the exact workload/profile that the buyer contracted for?

## Threat being falsified

A provider may have a valid, fast benchmark that is not the purchased workload:

    contract requires workload W
    provider measures benchmark B
    B performs above floor
    W would perform below floor

VCS-06 requires that benchmark B cannot be used to settle workload W merely because the metric value is good.

## Workload performance profile

The compute adapter defines the exact performance identity as:

    workload_id
    workload_digest
    artifact_digest
    benchmark_profile_digest
    runtime_config_digest
    input_profile_digest

The canonical profile is hashed into a workload_profile_digest.

This can represent differences such as model artifact, benchmark harness, batch/precision/runtime configuration, and input profile without requiring the governance kernel to understand any of those domains.

## Signed measurement attestation

Each performance source signs an attestation over:

    source
    evidence_digest
    subject
    lease_id
    receipt_id
    contract_digest
    workload_profile_digest
    metric
    unit
    started_at
    finished_at
    measured_at

The profile binding is therefore not a caller-supplied label added after measurement. Rewriting the workload/profile after signing invalidates the signature.

## Composition rule

VCS-06 runs strictly after the previous layers:

    hardware continuity
          ↓
    independent evidence
          ↓
    metered quantity
          ↓
    performance quality
          ↓
    signed workload/profile binding
          ↓
    commercial disposition

If VCS-04 or VCS-05 already reached DISPUTED or another prior result before performance could be established, workload evidence cannot upgrade that result.

## Executable cases

### Exact contracted workload

Both independent performance sources sign measurements for the exact contracted workload profile and all prior layers pass.

Result: **SETTLED**.

### Easy benchmark substitution

The performance value is excellent, but the signed measurement binds a different workload_digest and benchmark_profile_digest.

Result: **UNKNOWN**.

The system cannot establish that the purchased workload was measured.

### Artifact substitution

The workload ID is nominally the same but artifact_digest differs.

Result: **UNKNOWN**.

### Runtime configuration substitution

The workload and artifact match, but runtime_config_digest differs, representing a change such as batch size or precision.

Result: **UNKNOWN**.

### Old receipt replay

A valid signed measurement references a different execution receipt.

Result: **UNKNOWN**.

### Post-signature profile rewrite

A signed measurement is modified after signing to claim the expected profile.

Result: **UNKNOWN** because signature verification fails.

### Evidence substitution

The measurement is re-signed over an evidence digest that does not match the performance stream already admitted through the independent evidence path.

Result: **UNKNOWN**.

### Bound underperformance

When the exact contracted workload is bound correctly and both sources prove performance below the contract floor, the existing VCS-05 result remains **CREDIT_DUE**.

## Reused design pattern

Aegis already binds runtime workload admission to a WorkloadSpecDigest in the kernel-fabric path.

VCS-06 reuses the architectural pattern, not the implementation dependency. Compute settlement owns its own WorkloadPerformanceProfile because a commercial GPU workload profile is not the same semantic object as a Linux workload launch specification.

This preserves the architecture rule:

    same invariant pattern
    !=
    same domain representation

## Kernel boundary

VCS-06 changes only:

    internal/computesettlement/
    docs/

It does not modify kernel, governedaction, internal/outcome, internal/ege, kernelfabric, or server code.

The universal kernel still does not know model names, benchmark frameworks, batch sizes, precision formats, input corpora, or artifact formats.

## Claim boundary

VCS-06 proves cryptographic binding between a performance measurement and the declared contracted workload profile.

It does **not** prove that the measurement producer truthfully observed that workload internally. A compromised or dishonest measurement authority could sign a false statement.

A stronger later proof would require one or more of:

- workload-rooted device/process measurement;
- independently observed workload artifact identity;
- hardware/TEE/TPM binding of workload identity;
- benchmark-harness provenance;
- challenge-based or randomized measurement protocols;
- independent reproduction of the workload result.

The bounded VCS-06 claim is:

> Performance evidence for a different workload, artifact, benchmark profile, runtime configuration, input profile, receipt, or evidence digest cannot be silently reused to settle the contracted workload.

## Complexity Dividend

The held-out compute domain now exercises:

    VCS-01  outcome reconciliation
    VCS-02  evidence independence
    VCS-03  attested hardware continuity
    VCS-04  metered quantity continuity
    VCS-05  performance quality continuity
    VCS-06  workload/profile measurement binding

No workload-performance-specific primitive is promoted into the governance kernel.
