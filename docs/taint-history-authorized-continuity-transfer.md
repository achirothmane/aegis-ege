# Authorized TPM recovery-history continuity transfer

A replacement TPM must not be allowed to reset recovery history to sequence zero, but legitimate hardware replacement still needs a safe path forward.

The transfer protocol preserves the exact recovery-history truth while changing which TPM is allowed to represent it.

```text
TPM-A owns Hn
      +
history witness quorum = Hn
      +
ownership witness = TPM-A
      ↓
signed continuity-transfer authorization
      ↓
ownership witness → QUIESCED
      ↓
neither TPM-A nor TPM-B is active
      ↓
re-check exact history witness = Hn
      ↓
import exact Hn into TPM-B
      ↓
ownership witness → TPM-B
      ↓
TPM-A is retired
TPM-B continues at Hn
```

## Why there is a quiesced phase

A direct A → B ownership swap creates a race: the source might advance history after the destination snapshot was prepared but before ownership changes.

The protocol therefore introduces a deterministic quiesced ownership identity derived from the signed authorization digest.

Once the strict-majority ownership witness moves to that state, neither physical TPM matches the active identity. Properly configured recovery-history writers fail closed during that interval.

Only then is the external history witness checked again. If its exact sequence or head digest changed before quiescence, the authorization is stale and the system remains closed instead of activating an older destination head.

## Authorization binding

The signed transfer authorization binds:

- source device identity and measured-boot identity;
- exact source TPM history state digest and generation;
- exact source recovery-history sequence and head digest;
- exact source ownership witness epoch;
- destination device and measured-boot identity;
- exact fresh destination TPM state digest and generation;
- destination counter and exact-head NV indexes;
- history witness and ownership witness identities;
- validity window.

The signed authorization itself is hashed into a stable transfer commitment. That commitment is written into the destination TPM state lineage and into the ownership witness transition.

## Destination import

The destination TPM is provisioned as an empty anchor first.

The transfer then imports the exact source history head as a migration transition:

```text
destination fresh:
  local generation = G
  history sequence = 0

authorized import:
  local generation = G+1
  history sequence = n
  history head     = Hn
  predecessor      = TPM-A
  source state     = digest(source-state)
  authorization    = digest(signed-transfer)
```

The TPM exact-head NV area and monotonic counter are both advanced. Existing crash recovery recognizes this migration transition, so an interruption after the exact-head write or counter increment can still be recovered deterministically.

## Interrupted finalization

If destination import succeeds but the final ownership quorum update is interrupted:

```text
ownership = QUIESCED
TPM-B     = Hn
TPM-A     = Hn
```

both devices still fail closed because neither matches the quiesced active identity.

Retrying the same signed authorization recognizes the already prepared destination and resumes only the final ownership step.

## Source retirement

After the ownership quorum commits TPM-B:

```text
ownership active device = TPM-B
```

TPM-A can still physically contain Hn, but it is no longer an admissible recovery-history authority.

An old process holding TPM-A therefore cannot append a new receipt through the owned anchor contract.

## Executable proof

The proof suite covers two paths.

The first establishes H1 → H2 on TPM-A, transfers H2 to an independently seeded TPM-B, verifies TPM-A is rejected, then appends H3 through TPM-B.

The second makes two ownership witnesses reject only the final ownership epoch. The protocol reaches the quiesced state, both TPMs are denied, and retrying the exact authorization completes the transfer without changing the history head.

## Claim boundary

This v1 proves the transfer mechanics and fail-closed handoff when recovery-history operations use the owned-anchor profile.

It does not claim safety for callers that intentionally bypass the ownership witness and invoke the lower-level local TPM anchor directly. Production wiring must therefore treat the owned anchor as the admissible recovery-history interface once cross-host transfer is enabled.
