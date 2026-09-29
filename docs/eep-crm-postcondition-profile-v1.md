# EEP CRM intended-postcondition profile v1

Profile: `aegis.eep/crm-postcondition/v1`  
Outcome artifact: `aegis.eep/crm-outcome/v0alpha2`

This profile defines what the current synthetic CRM executor is allowed to claim
after a customer-update attempt.

It replaces the old rule:

```text
before_digest != after_digest  -> APPLIED
```

That rule was unsound because an unrelated field such as `updated_at` could
change while the requested field remained unchanged.

## Intended effect

For the current `crm.customer_update` / `update_customer` profile, the
intended postcondition is:

> every top-level field present in the signed customer-update patch is observed
> on the exact bound customer with the requested JSON value.

The evaluator considers only those requested fields. Unrelated fields may
change without contributing to success.

Field evidence records JSON-pointer paths plus expected/observed value digests.
Raw requested or observed values are not copied into the outcome artifact.

## Three independent outcome dimensions

The outcome keeps request acceptance, observation quality and intended
postcondition separate.

### Request acceptance

| Value | Meaning |
|---|---|
| `NOT_DISPATCHED` | No PATCH was sent because the intended state already held. |
| `ACCEPTED` | The destination returned a successful 2xx response. |
| `UNKNOWN` | A request may have reached the destination, but acceptance was not established. |

### Observation status

| Value | Meaning |
|---|---|
| `PRE_MUTATION` | The bound pre-mutation read already satisfied the requested state. |
| `OBSERVED_STABLE` | The final two of three bounded post-mutation reads agreed on the requested fields. |
| `UNAVAILABLE` | Required post-mutation observation could not be obtained. |
| `CONTRADICTORY` | The bounded observations did not stabilize on the requested fields. |
| `WRONG_TARGET` | The observed customer identity did not match the signed target. |

### Intended-postcondition result

| Result | Required evidence |
|---|---|
| `ALREADY_SATISFIED` | The exact bound pre-mutation state satisfied every requested field; no mutation was dispatched. |
| `VERIFIED` | Stable post-mutation observation satisfied every requested field. |
| `PARTIAL` | Stable observation satisfied some but not all requested fields. |
| `UNSATISFIED` | Stable observation satisfied none of the requested fields. |
| `UNKNOWN` | Observation was unavailable, contradictory or wrong-target. |

A 2xx response is never enough for `VERIFIED`.
A changed whole-state digest is never enough for `VERIFIED`.

## Already-satisfied state

If the bound precondition read already satisfies the entire patch, the attempt
is closed as `ALREADY_SATISFIED` without sending PATCH.

This is a verified state claim, not a claim that this executor caused the state.

## Bounded delayed completion

After a mutation attempt, the current profile performs three bounded reads.
The final two requested-field evaluations must agree before the observation is
called stable.

This allows one delayed first read:

```text
old -> desired -> desired  => VERIFIED
```

but preserves uncertainty for unstable evidence:

```text
desired -> old -> desired  => UNKNOWN / CONTRADICTORY
```

The profile does not claim that three reads are universally sufficient for all
providers. A provider requiring a different observation horizon needs a
different reviewed profile.

## Lost response

If PATCH may have committed but its response is lost, C06 keeps the attempt as a
possible effect.

C07 may later close that attempt only when stable observation establishes the
intended postcondition. The resulting outcome still records:

```text
request_acceptance = UNKNOWN
result             = VERIFIED
```

This does not assert that the uncertain request caused the observed state. It
states only that the intended postcondition is currently verified on the bound
target.

If stable observation instead shows `PARTIAL` or `UNSATISFIED`, the attempt
remains an unresolved possible effect because request acceptance is still
unknown.

## Exact target binding

Both pre-mutation and post-mutation customer observations must contain an
`id` equal to the signed customer target.

Destination id and account id remain governed by the C06 execution profile.
A wrong customer read cannot satisfy this postcondition oracle even when the
requested field values happen to match.

## Outcome integrity

`VerifyOutcome` validates both the artifact digest and legal combinations of
the three dimensions.

Examples:

- `VERIFIED + UNAVAILABLE` is invalid;
- `PARTIAL + NOT_DISPATCHED` is invalid;
- `ALREADY_SATISFIED + ACCEPTED` is invalid;
- `UNKNOWN + OBSERVED_STABLE` is invalid.

Recomputing the outcome integrity digest cannot turn one of these impossible
combinations into valid evidence.

## Migration

`aegis.eep/crm-outcome/v0alpha1` used whole-state digest difference as its
success oracle. Those artifacts remain historical records but do not satisfy
the C07 intended-postcondition guarantee.

New current-profile outcomes use
`aegis.eep/crm-outcome/v0alpha2` and carry the postcondition profile version.

The external validation recorded before C07 does not retroactively prove
intended-field verification.

## Non-goals

This is a CRM-domain postcondition evaluator, not:

- a universal outcome enum or service;
- generic causal inference;
- generic compensation;
- proof that all eventual-consistency windows fit three reads;
- proof that observation can always resolve an ambiguous request.

When evidence cannot support a stronger statement, the profile keeps
`PARTIAL`, `UNSATISFIED` or `UNKNOWN` instead of manufacturing success.
