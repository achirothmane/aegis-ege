# VCS-10 — Enrollment Device ↔ Hardware Root Identity Binding

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-09 proved that Verified Compute Settlement can consume a current hardware-rooted measured-boot commitment through a generic runtime contract.

Its remaining identity gap was explicit:

> Aegis `DeviceID` and the TPM platform identity were separate namespaces.

VCS-10 closes that gap by making both enrollment and the live hardware-root export converge on the same canonical TPM identity: the SHA-256 digest of the endorsement key SubjectPublicKeyInfo (EK SPKI).

## Why this is not string equality

The TPM monotonic root already had an internal device identity derived from the TPM endorsement-primary Name.

The remote enrollment protocol independently records:

    EnrolledTPMIdentity.EKSPKISHA256

Those are both legitimate TPM identities, but they are different representations and therefore must not be compared directly.

VCS-10 preserves the internal TPM Name identity for monotonic-root custody and rollback protection, while the generic platform export now uses the canonical EK SPKI digest expected by the enrollment protocol.

## Hardware identity bridge

The generic runtime layer now defines:

    EnrolledDevicePlatformBinding
        DeviceID
        EnrollmentHardwareIdentityDigest
        PlatformIdentityDigest
        PlatformMeasurementDigest
        BindingDigest

Binding succeeds only when:

    expected DeviceID
        = enrolled DeviceID

and:

    EnrolledTPMIdentity.EKSPKISHA256
        = PlatformMeasurementCommitment.PlatformIdentityDigest

The measured-boot commitment must also be a valid `MEASURED_BOOT` platform measurement.

## TPM platform export

`TPMNVMonotonicRoot.CurrentPlatformMeasurement` still performs all VCS-09 freshness and rollback checks first.

After those checks it derives the endorsement-key public key from the live TPM, encodes the key as X.509 SubjectPublicKeyInfo, hashes that DER with SHA-256, and exports the result as `PlatformIdentityDigest`.

The TPM root's internal endorsement-primary Name digest remains unchanged and continues to protect root-state custody.

Therefore the same physical TPM now has two deliberately separate identity roles:

    internal TPM Name digest
        -> root custody / copied-state rejection

    EK SPKI SHA-256
        -> enrollment ↔ platform identity continuity

## VCS composition

VCS-10 extends VCS-09:

    live Aegis DeviceID
            +
    enrolled TPM EK SPKI
            +
    current platform EK SPKI
            +
    current measured boot
            ↓
    EnrolledDevicePlatformBinding
            ↓
    device-bound BootMeasurementDigest
            ↓
    VCS-07 execution provenance
            ↓
    settlement

The device/platform binding digest is composed into `TrustedExecutionRoot.BootMeasurementDigest` rather than carried as informational metadata.

## Executable falsification cases

### Exact enrolled device and TPM

The Aegis DeviceID matches the enrollment record and the enrollment EK SPKI matches the current platform measurement identity.

Result: the device-bound hardware root can pass the complete VCS-07 path to **SETTLED**.

### Borrowed TPM root

The Aegis DeviceID is correct, but the current platform measured-boot commitment comes from a different TPM EK.

Result: **rejected before settlement**.

### Device namespace substitution

The TPM EK matches but the enrollment record belongs to a different Aegis DeviceID.

Result: **rejected before settlement**.

### Platform measurement changes

The same enrolled TPM identity produces a different measured-boot commitment.

The resulting downstream execution root changes, so an old provenance binding cannot silently represent the new boot state.

### Independent EK derivation proof

A TPM simulator test creates the endorsement primary, independently reconstructs its ECC public key, serializes it as X.509 SPKI, hashes it, and verifies that the generic platform export returns exactly that digest.

## Claim boundary

VCS-10 consumes `EnrolledTPMIdentity` as trusted enrollment state produced by the existing TPM credential-activation and AK-signed enrollment protocol.

The `EnrolledTPMIdentity` record itself is not yet a standalone signed durable enrollment receipt.

Therefore the bounded claim is:

> Given the trusted Aegis enrollment record, a workload running under DeviceID D cannot use a measured-boot root from TPM T unless D was enrolled to the same TPM EK SPKI identity exported by T.

A stronger later proof can make the enrollment identity record independently durable and signed so the DeviceID ↔ TPM identity relation survives storage substitution and recovery without relying on trusted local enrollment state.

## Boundary

Generic identity binding:

    internal/kernelfabric/device_platform_binding.go

TPM canonical identity export:

    internal/server/tpm_monotonic_root.go

VCS composition:

    internal/computesettlement/device_binding.go

No GPU, model, billing, PCR-index, NV-index, or contract semantic enters the universal governance kernel.

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
    VCS-10  enrolled DeviceID ↔ hardware-root identity continuity

At VCS-10, the compute domain now carries identity continuity from enrollment DeviceID through TPM hardware root, measured boot, live process/artifact, performance, metering, and settlement without adding compute semantics to the generic governance core.
