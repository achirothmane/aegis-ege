# Authorized TPM recovery-history continuity transfer v2

A replacement TPM must not be allowed to reset recovery history to sequence zero, but legitimate hardware replacement still needs a bounded continuation protocol.

The transfer preserves the exact recovery-history head while changing which TPM is authorized to represent it.

```text
TPM-A owns Hn
      +
Genesis-bound history quorum = Hn
      +
Genesis-bound ownership quorum = TPM-A
      +
independent destination attestation = TPM-B / measured boot
      ↓
signed continuity-transfer authorization
      ↓
ownership quorum → QUIESCED
      ↓
neither TPM-A nor TPM-B is active
      ↓
re-read exact history quorum = Hn
      ↓
import exact Hn into TPM-B exact-head NV
      ↓
ownership quorum → TPM-B
      ↓
TPM-A retired
TPM-B continues from Hn
```

## Authorization binding

The signed authorization binds:

- source TPM device and measured-boot identities;
- exact source TPM companion-state digest and generation;
- exact recovery-history sequence and head digest;
- source ownership epoch;
- destination TPM device and measured-boot identities;
- exact fresh destination state digest and generation;
- destination counter and exact-head NV indexes;
- history witness ID and Genesis-governed quorum policy hash;
- ownership witness ID and Genesis-governed quorum policy hash;
- exact independent destination-attestation digest;
- validity window.

Changing witness membership, threshold, witness trust manifests, or destination attestation therefore changes the signed authorization relation.

## Independent destination attestation

The transfer signer cannot declare TPM-B trustworthy by itself.

A distinct attestation authority signs the destination identity and measured-boot identity. The continuity authorization commits to the exact signed attestation digest.

The transfer path rejects:

- the same key used for transfer and destination attestation;
- a destination-attestation digest different from the authorized digest;
- a different migration/transfer ID;
- a TPM device identity different from the live destination;
- a measured-boot identity different from the live destination.

These checks happen before the destination counter or ownership quorum changes.

## Why QUIESCED exists

A direct A → B ownership swap permits a race where A advances history after B was prepared.

The ownership quorum therefore first moves to a deterministic synthetic identity derived from the exact signed transfer commitment. Neither physical TPM matches this identity.

Only after quiescence is the history quorum re-read. If the exact sequence/head no longer matches Hn, the transfer stops fail-closed rather than activating B at stale history.

## Genesis-bound quorum identity

Both witness roles use `journal.QuorumHeadStore`, whose membership, threshold, and per-member trust-manifest hashes are derived from the Genesis-pinned capability envelope.

The transfer authorization records each quorum policy hash. A same-name quorum reconstructed under a different policy cannot satisfy the authorization.

Split-quorum repair is similarly bounded: `ConvergeAuthorizedTransition` may converge only a finite caller-supplied SOURCE → QUIESCED → FINAL chain, rejects any readable third state, and preserves the same Genesis policy hash in the aggregate store version.

## Destination import

TPM-B starts as a fresh sequence-zero history anchor.

The authorized migration transition writes:

```text
local generation = G + 1
history sequence = n
history head     = Hn
predecessor      = TPM-A
source state     = digest(source state)
authorization    = digest(signed transfer)
attestation      = digest(signed destination attestation)
history policy   = Genesis-bound quorum policy hash
ownership policy = Genesis-bound quorum policy hash
```

The exact-head NV is committed before the monotonic counter. Existing exact-head crash recovery handles interruption around those commits.

## Interrupted final ownership

If TPM-B import succeeds but final ownership quorum activation is interrupted, replicas may temporarily be split across SOURCE, QUIESCED, and FINAL.

No strict majority means no active owner. Both TPMs remain unusable through the owned-anchor interface.

Retrying the same authorization may converge only the exact authorized chain and only after verifying that TPM-B is already prepared at the exact Hn and the independent history quorum still reports Hn.

## Executable proof

The proof suite covers:

1. H1 → H2 on TPM-A.
2. Fresh TPM-B cannot become active merely because it exists.
3. Policy-hash substitution is rejected before TPM-B or ownership state changes.
4. Collapsing transfer and attestation authority to one key is rejected before state changes.
5. Exact H2 is imported into TPM-B and durable migration lineage records both quorum policies and destination attestation.
6. TPM-A becomes inadmissible after final ownership activation.
7. H3 continues from H2 through TPM-B.
8. Interrupted final ownership leaves both TPMs fail-closed.
9. Retrying the exact authorization converges only the authorized SOURCE → QUIESCED → FINAL states.
10. Any readable quorum state outside that chain is rejected.

## Claim boundary

This proves authorized continuity across TPM replacement under:

- a trustworthy source history record;
- the same governed external witness infrastructure;
- Genesis-bound quorum membership and threshold;
- an independently trusted destination-attestation authority;
- protected destination TPM NV authorization.

It does not yet prove safe migration when the external witness set itself must rotate across a Genesis epoch, nor disaster recovery when both local TPM state and the governed witness majority are lost.
