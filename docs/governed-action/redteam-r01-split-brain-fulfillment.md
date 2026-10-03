# Red-Team Reality R01 — Split-Brain Fulfillment

Status: ADVERSARIAL EXPERIMENT — MUST NOT CHANGE THE FROZEN v1 ORACLE TO PASS

## Purpose

Attempt to falsify candidate-kernel-contract-v1 with a compound consequential action whose external effects cross independent failure and authority boundaries.

This experiment is not a new architectural layer and is not normative. A failure is evidence. Do not repair a failing trace by editing the frozen v1 oracle.

## Invented reality

Logical action:

`FulfillOrder(order-731)`

External effects:

1. `E1 inventory.reserve(order-731)` — PostgreSQL-backed reservation.
2. `E2 payment.capture(order-731, amount)` — provider A; effect may survive caller death and acknowledgement may be lost.
3. `E3 shipment.create(order-731)` — provider B; independently durable.

The business invariant is intentionally stronger than any individual effect:

`FULFILLED(order) => EXACT(E1) && EXACT(E2) && EXACT(E3) && SAME_ACTION_LINEAGE && CURRENT_AUTHORITY_AT_EACH_REQUIRED_BOUNDARY`

No equality of final values may substitute for exact effect lineage.

## Attack schedule R01-A

1. Admit action against current state and authority.
2. Durably establish custody for E1/E2/E3 lineage.
3. Commit E1.
4. Dispatch E2.
5. Provider A accepts E2.
6. Lose the E2 response.
7. Kill worker before a conclusive observation.
8. Revoke/expire the original authority.
9. Start a takeover worker.
10. Provider A is unobservable for 20 minutes.
11. Deliver an old provider-A webhook.
12. Deliver the same webhook again.
13. Wake the stale worker; it attempts E3.
14. Independently reverse E1 outside the action lineage.
15. Apply an unrelated payment event with the same amount, making aggregate balance look correct (semantic ABA).
16. Restore provider A read API with evidence that conflicts with one earlier observation.

## Required truthful behavior under the frozen semantics

- Lost acknowledgement after possible provider acceptance MUST NOT become NOT_EXECUTED.
- E2 MUST retain possible-effect identity/custody and blind replay MUST be blocked.
- A stale worker MUST NOT gain permission to create E3 after takeover merely because it resumed.
- Expired/revoked authority MUST NOT be silently reused for a later consequential boundary.
- Duplicate/old observations MUST NOT create a second effect identity or manufacture certainty.
- Equality of aggregate payment state after semantic ABA MUST NOT prove that exact E2 succeeded.
- Independent reversal of E1 MUST invalidate any claim that the compound action is FULFILLED.
- Conflicting observations MUST NOT be collapsed into false VERIFIED success.
- The system MUST NOT claim compound success merely because each effect has, at some time, had a locally plausible success observation.

## Falsification question

Can the frozen v1 kernel represent the compound action truthfully using its existing ActionRef, EffectIdentity, ExecutionAttempt, custody, state-binding, authority, observation, fencing and disposition semantics, without inventing a new normative relation?

### PASS

PASS only if an implementation can preserve all three exact effect lineages, block unsafe replay/stale execution, retain truthful uncertainty, and refuse compound success after E1 reversal or semantic ABA without changing the frozen oracle.

### COUNTEREXAMPLE

Record a counterexample if truthful handling requires a previously unstated normative concept such as a new compound-effect relation, transaction/compensation semantic, or aggregate-success rule.

A counterexample is not permission to patch Kernel v1. It establishes a boundary of the current claim and must enter change control separately.

## Anti-cheating constraints

- No oracle edits.
- No converting provider uncertainty into failure or success.
- No treating same amount/value as same effect.
- No hidden global transaction spanning PostgreSQL and providers.
- No assumption that compensation restores history.
- No deny-all implementation: E1/E2/E3 must remain executable on the clean control trace.
- No domain-specific rule may be smuggled into generic kernel semantics.

## Control trace

A clean trace with current authority, durable custody, exact lineage, conclusive observations and no concurrent reversal must permit E1 -> E2 -> E3 and close only after the declared postcondition is observed.

## Decision record

The experiment must end in exactly one of:

- `SURVIVES_R01` — existing frozen semantics are sufficient and executable evidence demonstrates it.
- `COUNTEREXAMPLE_R01` — truthful execution requires a normative relation absent from v1.
- `INCONCLUSIVE_R01` — the harness cannot distinguish the claims; strengthen the experiment, not the oracle.
