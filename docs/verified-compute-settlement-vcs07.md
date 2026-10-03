# VCS-07 — Workload-Rooted Measurement Provenance

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-06 proved that signed performance evidence cannot be reused across a different workload profile, artifact, benchmark profile, runtime configuration, input profile, receipt, or evidence digest.

VCS-07 addresses the remaining trust gap:

> a performance measurement authority can sign a false statement claiming that it measured the contracted workload.

## Separation of authorities

VCS-07 separates two roles:

    Measurement Authority
      signs the performance statement

    Execution Provenance Authority
      signs the runtime execution lineage
      and binds each measurement to that lineage

The performance signer acting alone is therefore insufficient to establish workload provenance.

## Trusted execution root

The compute adapter receives exact runtime-owned commitments:

    activation_receipt_digest
    process_identity_digest
    cgroup_identity_digest
    boot_measurement_digest

These are opaque to compute settlement.

In a production adapter they can be derived from existing Aegis workload activation/runtime-trust evidence, Linux process identity, cgroup identity, TPM/IMA or another platform measurement path.

## Signed execution provenance

The independent provenance authority signs:

    subject
    lease_id
    receipt_id
    contract_digest
    workload_profile_digest
    executable_artifact_digest
    activation_receipt_digest
    process_identity_digest
    cgroup_identity_digest
    boot_measurement_digest
    hardware_attestation_digest
    observed_at

The settlement path verifies that this statement matches all of:

- the VCS-06 contracted workload profile;
- the exact contracted artifact;
- the trusted runtime execution root;
- the current VCS-03 completion hardware attestation;
- the current lease and execution receipt;
- an observation inside the execution interval.

## Measurement-to-execution binding

VCS-07 does not stop at verifying one execution provenance statement.

The provenance authority separately signs one binding for every VCS-06 signed measurement:

    measurement_attestation_digest
    execution_provenance_digest
    evidence_digest
    source
    lease_id
    receipt_id

This closes an important substitution boundary:

    valid measurement M1
       ↓
    execution root binds M1
       ↓
    performance signer creates new valid M2
       ↓
    M2 cannot reuse M1's execution binding

## Executable falsification cases

### Exact rooted execution

Contracted profile, trusted runtime root, current hardware lineage, signed execution provenance, and both independently measured performance statements all match.

Result: **SETTLED**.

### Correct profile label, wrong runtime artifact

The measurement says the correct workload profile, but runtime provenance reports a different executable artifact.

Result: **UNKNOWN**.

### Trusted process identity mismatch

The signed provenance reports a process identity different from the runtime-owned expected process identity.

Result: **UNKNOWN**.

### Old receipt provenance

A valid execution provenance statement refers to another execution receipt.

Result: **UNKNOWN**.

### Different hardware lineage

The execution provenance is not bound to the current VCS-03 completion hardware attestation.

Result: **UNKNOWN**.

### Measurement rewritten after execution binding

The measurement signer changes only an opaque measurement identifier and re-signs. VCS-06 still considers the new measurement semantically valid, but its signed digest no longer matches the provenance authority's binding.

Result: **UNKNOWN**.

### Binding points to a different execution provenance

Result: **UNKNOWN**.

### Missing execution binding

One otherwise valid performance measurement has no provenance-authority binding.

Result: **UNKNOWN**.

### Measurement authority impersonates provenance authority

A valid performance-signing key signs the execution provenance and bindings, but verification expects the independent provenance authority.

Result: **UNKNOWN**.

### Rooted underperformance

When the exact execution lineage is established and both independent sources prove sustained underperformance, the VCS-05 result remains **CREDIT_DUE**.

## Relationship to existing Aegis primitives

Aegis already has executable primitives for:

- workload activation receipts;
- Linux process identity using boot ID + process start time + executable device/inode;
- cgroup identity;
- remote TPM/IMA attestation;
- runtime trust leases;
- attested hardware identity.

VCS-07 deliberately reuses these as an architectural source of opaque commitments rather than importing Linux or TPM semantics into compute settlement.

The rule remains:

    same trust relation
    != 
    same domain representation

## Kernel boundary

VCS-07 changes only:

    internal/computesettlement/
    docs/

No workload provenance, process, cgroup, TPM, IMA, model, benchmark, or GPU semantic is promoted into the universal governance kernel.

## Claim boundary

VCS-07 proves that a performance measurement signer acting alone cannot manufacture a workload identity that conflicts with the independently trusted execution-root commitments.

It does **not** prove that the provenance authority itself is honest or that every opaque digest was collected by hardware-rooted instrumentation.

A stronger deployment claim requires the execution-root inputs to be sourced from real runtime enforcement/attestation paths whose authority is independent of the performance producer.

The bounded claim is:

> A performance measurement cannot silently settle unless its signed digest is bound by an independently trusted execution-provenance authority to the exact runtime root, contracted workload/artifact, current hardware lineage, lease, and receipt.

## Complexity Dividend

    VCS-01  outcome reconciliation
    VCS-02  evidence independence
    VCS-03  attested hardware continuity
    VCS-04  metered quantity continuity
    VCS-05  performance quality continuity
    VCS-06  workload/profile measurement binding
    VCS-07  runtime-rooted measurement provenance

VCS-07 adds only compute-domain provenance composition. The kernel remains unchanged.
