# Frozen reproduction specification v1
## Semantic domain
Fix a governing subject, exact logical effect, target, generation/epoch, enforcing boundary, and an evaluated attempt q containing exact attempt AND executor identity. Let e be an actual committed physical effect, t_e its actual physical commitment point, t_o an observation point after commitment.
A(e): relevant governed authority for the actual effect's subject, action/effect, target, generation/epoch and enforcing boundary was valid at t_e. This does not say q caused e. Multiple different actors may be authorized for the same exact scope.
C(e,q): e was caused by exactly q's attempt and executor. Equivalent state and equal logical effect key from another attempt do not establish C.
P(e,q,t_o): an independently chosen, fixed current predicate is satisfied at t_o. It does not include authority or causal origin by definition.
No-effect states have undefined commit authority and are excluded from committed-effect comparisons.
## Fixed surrounding contract
The exact identities, scope, policy, target and observation time are independently fixed. One physical effect is identified; cardinality, evidence integrity, trust roots, independent claim selection, current-observer truthfulness and history continuity are surrounding obligations. Do not turn their failures into new truth axes silently.
EXACT_EFFECT asks whether this exact physical effect was authorized at its actual commitment, caused by this evaluated attempt/executor, and satisfies the independently chosen current predicate at observation, with the surrounding obligations met. A snapshot need not equal present truth.
## Open mutable domain
Governed authorization may be revoked/restored; technical write permission can exist outside the governed boundary. Two authorized candidates may produce the same logical effect. Targets may change after commitment. Historical cause persists after current-state change. Start without the effect. Use realistic transitions, not assignments of independent A/C/P answer bits.
## Required falsification questions
Can A be a total Boolean function of (C,P)? Can C be a function of (A,P)? Can P be a function of (A,C)? For each, discover pairs with equal retained projection before examining the omitted coordinate. Enumerate all sixteen functions of a retained pair. Independently discover reachable committed-effect corners; no expected corner set is supplied.
## Restricted profiles to evaluate without supplied expected answers
1. Every destination writer validates exact active authority and current epoch/generation atomically with commit; revocation serializes with commit; no bypass.
2. Initially absent effect; only this exact attempt/executor can create it; exclude preexisting or foreign origin; trusted complete mediation.
3. Exact effect is a durable permanently retained immutable event; the independently selected predicate is permanent existence; no erase/expiry/compensation.
4. Mutable target, erasable immutable event, and immutable bytes with an independently selected expiring-validity predicate.
5. Compose the preceding restrictions where meaningful.
Report reachable sets, invariant coordinates, remaining functional dependencies and traces. Do not change predicates within an experiment.
## Deliberate disagreement search
Vary ordering, adjacent commit/revoke, restoration, generations, multiple attempts including SAME attempt with DIFFERENT executor, deduplication, lost acknowledgement, retries, target mutation/restoration, deletion, expiry, old observation, and exact historical evidence with changed present state.
Search for identical semantic A/C/P with different correct EXACT_EFFECT decisions. First classify any difference as fixed-domain violation, identity/cardinality ambiguity, trust, freshness, history, or claim-policy dependency before proposing another axis.
## Anti-smuggling questions
Independently classify: authorized causal receipt; state containing verified origin; still-current receipt; unified business-effect record; atomic transaction; sole-writer store (one writer may serve multiple attempts).
Use DERIVATION (including explicitly conditional predicate preservation), SUBSTRATE DISCHARGE, REPRESENTATION COLLAPSE, SEMANTIC SMUGGLING. Explain expansions and boundaries. Do not infer origin from deduplication.
## Isolation and evidence
Do not inspect any repository, Cycle 7 implementation, helper, fixture, constructor, oracle or report. Only this specification and language/SQLite standard libraries are input. Write source, reproducible commands, machine-readable results, minimal traces, and limits. Never import production/runtime packages. Keep evidence facts separate from a producer's claim. This is specification-only software independence, not an independent external human laboratory.
