# VCS-09 — Generic Measured-Boot Commitment Export

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-08 produced a live execution root from signed Aegis workload/runtime-trust artifacts plus live Linux process, cgroup, boot-ID, and executable observations.

Its remaining limitation was explicit: `BootMeasurementDigest` represented an Aegis runtime-attestation lineage, not a direct generic export of the hardware-rooted measured-boot state enforced by the TPM monotonic root.

VCS-09 closes that boundary without teaching compute settlement about TPM internals.

## Generic runtime contract

`kernelfabric` now defines:

    PlatformMeasurementSource
        CurrentPlatformMeasurement(ctx)
            -> PlatformMeasurementCommitment

The exported commitment contains only:

    version
    evidence_class
    commitment_digest
    platform_identity_digest
    verified_generation

It does **not** expose:

- PCR numbers;
- TPM handles;
- PCR values;
- firmware/event-log structure;
- NV index details;
- endorsement-key object formats;
- compute/GPU semantics.

## TPM implementation

`TPMNVMonotonicRoot` implements the generic source.

Before returning any commitment it executes the existing `recoverLocked` path, which checks:

    TPM NV counter freshness
    committed/pending state recovery
    rollback resistance
    current endorsement-derived device identity
    current measured-boot identity

If current measured boot differs from the enrolled TPM-root state, export fails closed.

## Stable measurement identity

The generic `CommitmentDigest` binds:

    evidence class
    platform identity digest
    measured-boot identity digest

`VerifiedGeneration` records which monotonic root generation was checked, but it is deliberately not part of the stable boot commitment.

This prevents unrelated capability-root advances from changing the identity of an otherwise unchanged measured boot.

Freshness is enforced at export time by the source's monotonic root checks.

## VCS composition

VCS-09 does not replace the VCS-08 runtime lineage.

It composes:

    VCS-08 attestation-lineage digest
                +
    generic measured-boot commitment
                ↓
    hardware-rooted BootMeasurementDigest

That combined digest becomes the `TrustedExecutionRoot.BootMeasurementDigest` consumed unchanged by VCS-07.

Therefore the settlement path remains:

    hardware measured boot
            ↓
    generic PlatformMeasurementCommitment
            +
    signed runtime-trust lineage
            +
    live process / cgroup / executable
            ↓
    TrustedExecutionRoot
            ↓
    workload-rooted measurement provenance
            ↓
    SETTLED | CREDIT_DUE | DISPUTED | UNKNOWN

## Executable proof

The TPM simulator proof verifies that:

- a provisioned TPM monotonic root exports a valid generic measured-boot commitment;
- the commitment represents the current verified TPM-root device + measured-boot state;
- extending measured-boot PCR state causes generic export to fail closed with the existing measured-boot drift error;
- an unrelated monotonic capability-root generation advance changes `VerifiedGeneration` but does not change the stable measured-boot `CommitmentDigest`.

The compute proof verifies that:

- VCS-08 live Linux root can be composed with a generic measured-boot source;
- the resulting hardware-rooted digest differs from the software/runtime-lineage-only digest;
- changing measured-boot commitment changes the VCS execution root;
- generation-only change does not change unchanged boot identity;
- missing/failed platform source fails closed;
- non-measured-boot evidence class is rejected;
- the resulting hardware-rooted execution root still passes the complete VCS-07 settlement path to `SETTLED`.

## Important identity boundary

`Aegis DeviceID` and the TPM monotonic root's endorsement-derived `PlatformIdentityDigest` are currently different identity namespaces.

VCS-09 does **not** pretend they are equal.

The claim is therefore:

> the VCS execution root now consumes a current hardware-rooted measured-boot commitment from a trusted generic platform source, composed with the already verified Aegis runtime lineage.

It does not yet prove a cryptographic equality relation between the enrolled Aegis `DeviceID` namespace and the TPM monotonic-root platform identity namespace.

That is a separate invariant and a natural next falsification target.

## Boundary

VCS-09 adds a small generic runtime primitive:

    internal/kernelfabric/platform_measurement.go

and one TPM implementation:

    internal/server/tpm_monotonic_root.go

Compute-specific composition remains in:

    internal/computesettlement/platform_measurement.go

No PCR, TPM, NV, firmware, model, GPU, benchmark, billing, or settlement semantic enters the universal governance kernel.

## Complexity Dividend

    VCS-01  outcome reconciliation
    VCS-02  evidence independence
    VCS-03  attested hardware continuity
    VCS-04  metered quantity continuity
    VCS-05  performance quality continuity
    VCS-06  workload/profile measurement binding
    VCS-07  runtime-rooted measurement provenance
    VCS-08  live Aegis execution-root production
    VCS-09  generic hardware measured-boot commitment

The held-out compute domain now consumes a hardware-rooted platform measurement through a generic runtime contract rather than a compute-specific TPM integration.
