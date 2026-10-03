# VCS-11 — Signed Durable Enrollment Identity Receipt

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-10 bound an Aegis `DeviceID` to the same TPM EK SPKI identity exported by the live hardware-rooted measured-boot source.

Its remaining durability gap was explicit:

> `EnrolledTPMIdentity` was trusted stored state rather than a standalone signed, rollback-resistant enrollment receipt.

VCS-11 closes that gap.

## Why signature alone is insufficient

A previously valid enrollment receipt remains correctly signed after it becomes stale.

Therefore this is not enough:

    signed receipt R1
        ↓
    signed receipt R2 supersedes R1
        ↓
    writable disk rolled back to R1
        ↓
    signature on R1 still verifies

VCS-11 requires both:

    signed enrollment receipt
            +
    monotonic exact-head anchor outside the writable receipt volume

## Generic monotonic head primitive

`kernelfabric` now exposes the domain-agnostic:

    DurableHeadAnchorState {
        sequence
        head_digest
    }

    DurableHeadAnchor {
        Current()
        CompareAndAdvance(expected, next)
    }

The existing TPM NV history anchor is reused through this generic contract; the taint-history-specific interface remains an alias for compatibility.

## Signed enrollment receipt

`EnrollmentIdentityReceipt` binds:

    receipt_id
    sequence
    previous_receipt_digest
    DeviceID
    EKSPKISHA256
    canonical digest of the complete EnrolledTPMIdentity
    enrolled_at
    issued_at

The canonical identity digest includes the enrollment identity's:

- DeviceID;
- AK attestation parameters;
- EK SPKI digest;
- EK certificate digest when present;
- bootstrap attestor public key;
- TPM manufacturer/vendor/firmware metadata;
- enrollment time.

The receipt is signed by an Ed25519 enrollment authority and has its own signed-receipt digest.


## Ceremony-bound issuance

VCS-11 does not treat an arbitrary signed `EnrolledTPMIdentity` as proof that enrollment happened.

The authoritative completion path is:

    TPM credential activation
            +
    AK signature over the enrollment challenge transcript
            ↓
    CompleteTPMEnrollment
            ↓
    exact EnrolledTPMIdentity
            ↓
    signed EnrollmentIdentityReceipt
            ↓
    DurableHeadAnchor CompareAndAdvance
            ↓
    committed current receipt

`CompleteAndCommitTPMEnrollmentReceipt` performs this sequence as the authoritative **initial-enrollment** path. The receipt ID is the TPM enrollment ceremony's `EnrollmentID`. Credential activation expiry is evaluated against verifier time, so an old proof cannot revive itself by replaying its historical completion timestamp. After that freshness check, the identity's enrollment time is normalized to the proof's stable `CompletedAt` (which must lie inside the challenge window and not in the verifier's future), making the canonical identity digest stable across retry. If credential activation, transcript verification, signature validation, or durable-head advancement fails, the function does not return a completed durable enrollment. A retry of the same already-committed ceremony is idempotent and returns the exact existing R1 rather than creating R2.

The function intentionally refuses a different successor enrollment once a current receipt exists. Hardware replacement / re-enrollment requires a separate governed successor authorization path; VCS-11 does not silently make the enrollment signing key alone sufficient policy.

The executable TPM simulator proof verifies the negative and retry boundaries: a proof with the wrong activation secret cannot create or advance any durable enrollment receipt, while replay of the same valid committed ceremony leaves the durable head at sequence 1.

## Crash-safe durable store

The anchored store uses:

    write signed receipt to .pending + fsync
                ↓
    monotonic anchor CAS to exact new digest
                ↓
    promote .pending to current + fsync directory

Recovery distinguishes the critical crash boundaries.

### Crash before anchor advance

Pending receipt exists but the anchor still names the previous head.

Result: pending receipt is discarded; previous committed receipt remains authoritative.

### Crash after anchor advance but before promote

The anchor names the pending receipt digest.

Result: recovery promotes the exact pending receipt and reconstructs the current state.

### Whole-volume rollback

The writable volume is restored to an older, valid, correctly signed receipt while the monotonic anchor remains at the newer head.

Result: **rollback detected and rejected**.

### Same-sequence replacement

A different correctly signed receipt is substituted at the same local sequence.

Result: its digest differs from the anchored exact head and is rejected.

## TPM proof

A TPM simulator test provisions a dedicated `TPMNVHistoryAnchor` as a generic durable head anchor:

    append R1
        ↓
    snapshot writable receipt volume
        ↓
    append R2
        ↓
    restart anchor/store
        ↓
    R2 recovers as current
        ↓
    restore exact R1 writable snapshot
        ↓
    TPM anchor still commits R2
        ↓
    R1 rejected

This demonstrates rollback rejection after restart using hardware-backed monotonic state.

## VCS composition

VCS-11 extends VCS-10.

The settlement path reads the current receipt only through the anchored receipt source, verifies its enrollment-authority signature, verifies that it binds the exact `EnrolledTPMIdentity` used by VCS-10, and then composes the signed receipt digest into:

    TrustedExecutionRoot.BootMeasurementDigest

The resulting chain is:

    enrollment authority
            ↓
    signed enrollment identity receipt
            ↓
    TPM monotonic exact-head anchor
            ↓
    DeviceID = enrolled TPM EK
            ↓
    live TPM EK + measured boot
            ↓
    live process / cgroup / executable
            ↓
    workload performance + metering
            ↓
    execution provenance
            ↓
    settlement

## Executable VCS cases

### Current durable enrollment receipt

Current signed receipt matches the exact enrolled identity and monotonic anchor.

Result: full VCS-07 path can reach **SETTLED**.

### Rolled-back but valid receipt

R2 is anchored, but local storage is restored to valid signed R1.

Result: rejected before settlement.

### Receipt for different enrolled identity

The receipt is validly signed but binds another EK identity.

Result: rejected.

### Wrong enrollment authority

The current receipt was signed by another key than the configured enrollment authority.

Result: rejected.

## Claim boundary

VCS-11 proves:

> the enrollment identity consumed by settlement must be the exact current signed receipt committed by an independent monotonic exact-head anchor; an older or substituted validly signed receipt cannot silently regain authority after restart or writable-volume rollback.

VCS-11 does not define the organizational policy for authorizing re-enrollment or hardware replacement. A successor receipt can advance the chain only when signed by the configured enrollment authority; quorum or human approval policy for that authority is a separate governance layer.

## Boundary

Generic primitives:

    internal/kernelfabric/durable_head_anchor.go
    internal/kernelfabric/enrollment_identity_receipt.go
    internal/kernelfabric/enrollment_identity_store.go

TPM reuse:

    TPMNVHistoryAnchor implements DurableHeadAnchor

Compute composition:

    internal/computesettlement/durable_enrollment.go

No GPU, billing, TPM PCR-index, or domain-specific settlement semantic enters the universal governance kernel.

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
    VCS-11  signed durable anti-rollback enrollment identity

At VCS-11 the held-out compute domain carries enrollment identity continuity through durable signed state, hardware-rooted monotonic freshness, measured boot, live execution, performance, metering, and settlement.
