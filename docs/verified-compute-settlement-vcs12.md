# VCS-12 — Governed Successor Enrollment across Hardware Replacement

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-11 made the initial DeviceID ↔ TPM enrollment identity a signed durable anti-rollback fact.

Its remaining replacement boundary was explicit:

> a different enrollment ceremony must not be able to create a VCS-12-admissible governed R2 merely because the enrollment signer accepts it.

VCS-12 closes that boundary by requiring successor enrollment to inherit the exact durable predecessor head through the existing quorum-backed TPM continuity-transfer protocol before R2 can be committed.

## Governing invariant

    enrollment signer alone
        != permission to create a VCS-12-admissible governed successor

    continuity transfer signer alone
        != permission to replace hardware

    fresh destination TPM alone
        != permission to replace hardware

Instead:

    current R1
      +
    exact R1 durable head
      +
    quorum-backed TPM-A -> TPM-B continuity transfer
      +
    independently attested TPM-B
      +
    live TPM-B EK identity
      +
    valid TPM-B enrollment ceremony
      +
    signed successor-governance authorization
        ↓
    R2

## Two different decisions

VCS-12 deliberately separates:

1. **continuity proof** — the exact predecessor head survived the hardware move; and
2. **successor authorization** — this specific hardware move and this specific enrollment ceremony may create the next enrollment receipt.

The TPM continuity-transfer authorization therefore is not treated as the enrollment-replacement authorization itself.

## Generic successor authorization

The kernel-facing contract binds:

- Aegis DeviceID;
- exact predecessor receipt digest and sequence;
- predecessor EK SPKI identity;
- exact successor enrollment ID;
- exact successor enrollment-request digest;
- successor EK SPKI identity;
- exact signed TPM continuity-transfer authorization digest;
- exact destination-attestation digest;
- source and destination TPM device identities;
- destination measured-boot identity and generation;
- Genesis-bound history and ownership quorum policy hashes;
- validity window.

The authorization is signed by a successor-governance authority that must be distinct from the enrollment signer, continuity-transfer signer, and destination-attestation authority in the VCS-12 execution path.

## Enrollment receipt v2

Initial R1 remains the existing v1 receipt.

A governed successor is emitted as:

    EnrollmentIdentityReceipt v2 {
        sequence = predecessor + 1
        previous_receipt_digest = exact predecessor
        successor_authorization_digest = exact governed authorization
        DeviceID
        successor EK SPKI
        exact enrolled identity digest
        enrolled_at
        issued_at
    }

v1 receipt digests remain byte/domain compatible. VCS-12 does not reinterpret existing R1 records.

A v2 receipt cannot be appended through the ordinary enrollment store path. The store rejects direct v2 append and requires `AppendGovernedSuccessor`, which verifies the independent successor-governance signature, exact predecessor receipt, predecessor and successor EK identities, receipt issuance window, and authorization digest before the durable-head CAS. This prevents the enrollment signer alone from advancing the governed v2 lineage.

## Same physical destination proof

Existing continuity transfer identifies TPM-B by TPM Name and measured boot.

Enrollment identifies the TPM by EK SPKI.

VCS-12 joins those namespaces on the live destination TPM itself:

    transfer destination TPM Name
          =
    live TPMNVHistoryAnchor device identity

    transfer measured boot
          =
    live TPM measured boot

    successor enrollment EK SPKI
          =
    live TPM EK SPKI

The destination migration lineage stored in TPM-B must also retain the exact transfer authorization, destination attestation, and both quorum policy hashes.

This prevents a continuity proof for TPM-B from being combined with an enrollment ceremony performed by TPM-C.

## Owned conjunctive prerequisite

The successor receipt store must use the existing:

    OwnedConjunctiveTaintRecoveryHistoryAnchor

which requires all three facts to agree:

    local TPM-B exact head
      +
    external history quorum exact head
      +
    ownership quorum says TPM-B is active

A plain local TPM anchor is not sufficient for VCS-12.

## Executable cases

### Fresh TPM-B without transferred R1

TPM-B is real and its enrollment ceremony is valid, but ownership/head continuity still belongs to TPM-A.

Result: **DENY** and TPM-B remains sequence zero.

### Transferred R1 + different EK

The exact R1 head has moved to TPM-B, but the successor enrollment authorization is rewritten to another EK identity.

Result: **DENY** and the durable head remains R1.

### Exact governed successor

The exact R1 head is transferred to TPM-B, ownership quorum activates TPM-B, live TPM Name / measured boot / EK all match, the TPM-B credential-activation + AK transcript ceremony succeeds, and the exact successor authorization is valid.

Result:

    R1
      ↓ exact transferred head
    TPM-B
      ↓ governed successor
    R2

### Retry

Repeating the same ceremony and authorization after R2 already committed returns the exact existing R2 and does not create R3.

### Legacy signed R2

A correctly enrollment-signed v1 R2 without governed successor lineage may still satisfy lower VCS-11 durability semantics, but it cannot satisfy the VCS-12 execution-root contract.

Result: **DENY**.

## Settlement composition

VCS-12 adds a successor-aware execution-root capture.

It requires the current durable receipt to be v2 and verifies the exact signed successor authorization. The authorization digest is then composed into the downstream boot-measurement root in addition to being committed by the receipt digest.

Authorization freshness is consumed at the R1 -> R2 transition. Later settlement verifies the authorization signature and checks it against the enrollment-signed R2 issuance time; it does not require the short-lived authorization window to remain open forever. Therefore an already committed governed R2 remains verifiable after the authorization expires.

The chain becomes:

    initial enrollment R1
          ↓
    exact durable head
          ↓
    TPM-A -> TPM-B quorum continuity
          ↓
    governed successor authorization
          ↓
    TPM-B credential activation + AK transcript
          ↓
    R2
          ↓
    live TPM-B EK + measured boot
          ↓
    live process / cgroup / executable
          ↓
    performance + metering
          ↓
    execution provenance
          ↓
    settlement

## Claim boundary

VCS-12 proves that a successor enrollment consumed by the VCS-12 settlement path cannot be created merely by replacing local enrollment state or by presenting another valid TPM enrollment. The exact predecessor receipt must survive through the governed TPM continuity path, the destination TPM must own that exact head under the quorum witnesses, and the successor ceremony must bind to that same live TPM.

This version does not yet prove:

- simultaneous quorum rotation during the same successor transition;
- recovery after loss of both local TPM state and governed witness majority;
- organizational human/quorum policy above the successor-governance signing authority.

Those remain separate higher boundaries.

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
    VCS-12  governed successor enrollment across hardware replacement
