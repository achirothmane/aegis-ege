# VCS-13 — Genesis-Bound Successor Governance Authority

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-12 proved that a replacement TPM cannot become a governed successor merely because the enrollment signer accepts it. Its remaining authority gap was that the successor-governance verification key itself was supplied by the caller.

VCS-13 removes that configuration authority.

## Governing invariant

    runtime-selected governance key
        != successor authority

Instead:

    verified Genesis manifest
          ↓
    exact capability-envelope hash
          ↓
    enrollment_successor_governance policy
          ↓
    exact Ed25519 governance authority
          ↓
    successor authorization v2
          ↓
    governed R2

## Authorization v2

The successor authorization now commits:

- governance Genesis epoch;
- exact Genesis capability-envelope hash;
- canonical successor-governance policy hash;
- all VCS-12 predecessor, TPM, transfer, witness, and enrollment bindings.

V1 remains verifiable with its original signing and digest domains. VCS-13 commit and settlement paths require v2.

## Fail-closed boundaries

- a raw public key from runtime configuration cannot satisfy VCS-13;
- changing one byte of the capability envelope changes the Genesis-pinned envelope hash and is rejected;
- substituting the governance public key requires a different capability envelope and therefore a different governed Genesis state;
- a valid authorization signed by a key not selected by the Genesis binding is rejected;
- authorization epoch / envelope / policy substitution is rejected before R2 commit;
- settlement re-verifies the same Genesis governance binding recorded by the signed authorization.

## Claim boundary

VCS-13 pins the successor-governance authority to one verified Genesis epoch. It does not yet define continuity when that authority itself rotates across Genesis epochs. Cross-Genesis successor-governance rotation remains a separate transition problem.
