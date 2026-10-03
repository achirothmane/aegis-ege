# Anchored journal identity and historical trust

At `536ce01e0ca5009ac4e32440681fbab8f428ff83`, the generic file-journal
constructor generated a random JournalID whenever both local files were absent.
An external witness could retain the original nonempty head while the same
constructor enrolled a different empty history and reported it valid. The
checked-in baseline regression executes this counterexample against that exact
source revision in CI.

The witness machinery was detecting rollback **within** a namespace. The relying
context was not pinning which namespace was permitted to continue its history.

## Executable boundary

Externally anchored journals now have two explicit entry points:

- `CreateAnchoredFileJournal`: first provisioning of a pinned JournalID, with
  absent local files and an absent external head. An existing witness head,
  including a sequence-zero head, forbids this operation.
- `OpenAnchoredFileJournal`: verify the existing pinned history. It never writes
  local files or enrolls witness state. Missing custody fails closed.

The pin comes from trusted relying-context configuration. Reading the pin out of
the anchor being verified defeats the boundary. Signing-key possession,
filesystem path, and process restart are not history identities. The configured
identity remains stable across signer rotation and exact-file relocation.

Verification compares the local JournalID to the pin **before** consulting the
witness. It then compares the witness's JournalID, sequence, digest and key to
the exact local head. A signed foreign history cannot choose its own witness
namespace. The legacy random-identity constructor rejects external witnesses.

Provisioning is distinct from continuity recovery. Failure before external
commit leaves partial local state untrusted and blocks automatic enrollment.
Failure after a successful external commit with a lost reply can be recovered
by verifying the exact retained pair through `OpenAnchoredFileJournal`.
Witness CAS resolves two concurrent first-creation attempts for the same ID.

## Two independent dimensions

`Verification.HistoricalTrust` assesses custody at the time of verification:

| Assessment | Meaning |
| --- | --- |
| `TRUSTED_HISTORY` | The configured identity pin, local integrity and current external head agree. |
| `UNTRUSTED_HISTORY` | A configured verification requirement cannot presently be proved. |
| `UNVERIFIED_HISTORY` | Local integrity passes without independent continuity verification. |

The existing `Verification.Valid` retains its configured-check meaning. It is
insufficient by itself to establish historical trust. `VerifyFiles` is a local
integrity check and cannot earn `TRUSTED_HISTORY`.

The operational claims in journal entries are not rewritten by these
assessments. A recorded `CLOSED` claim can have `UNTRUSTED_HISTORY` after witness
loss. A recorded `UNKNOWN` claim can have `TRUSTED_HISTORY`. Witness loss blocks
append, and restoring the exact witness head restores a new point-in-time trust
assessment without changing the recorded outcome. No assessment is a perpetual
proof or permission to retry an effect.

## Constitutional scope and proof limits

This closes an I4 historical-continuity gap by requiring identity continuity
before accepting the existing sequence/digest proof. Reset refusal is an
obligation of I4, supported by existing non-equivocation and append-only
mechanisms; it does not require an additional constitutional invariant.

These tests prove refusal under local history loss, signed history substitution,
foreign witness identity, witness outage/loss, interrupted writes, lost commit
acknowledgement, concurrent creation, relocation and signer rotation. The existing
KinD M10 proof additionally checks reset refusal against a retained native
Kubernetes ConfigMap head.

Historical trust is relative to the configured trust boundary. This change does
not authenticate configuration by itself or prove that a selected witness is
independent, durable or immune to rollback. Those are obligations of the relying
context and witness profile; the existing Genesis/quorum machinery supplies
stronger profiles. Loss of both local and external custody is not recoverable
through `Open`. Provisioning authority must not be available to a runtime as an
automatic fallback or used to re-enroll an existing lineage whose custody is
lost. File relocation proves exact history continuity, not a new principal's
execution authority or governed succession.
