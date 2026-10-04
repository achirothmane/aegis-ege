# Independent event/history experiment

This standalone JavaScript model was constructed from the frozen specification only. It starts with no effect. Attempts start with exact attempt/executor dispatch identity; physical commitment references that dispatch. Governed revocation, restoration and epoch events precede or follow commitment. Target, retention and clock events determine an independently fixed observation-time predicate. No transition assigns A/C/P answer bits. No repository, prior implementation, helper, fixture or result corpus was inspected.

## Reproduction

Run `node checks.js` for tests. Run `node chronicle.js --out ./rerun` to create results and witness files in a chosen directory, or `node chronicle.js --stdout` for JSON. The commands use only files in this experiment directory and Node standard libraries.

## Reachability and functions

All rows were discovered by breadth-first closure of the finite event state graph. A/C/P are interpreted afterward from each shortest retained history. No-effect states have null coordinates and are excluded. Corner order is A,C,P. Invariant coordinates are scoped to the stated restrictions. Functional dependencies are total Boolean functions on a retained pair, with behavior off the reachable retained inputs unconstrained. The numbers below are all surviving truth-table masks from 0 through 15; the full JSON includes all rejected functions and counterexamples.

| Profile | Reachable committed corners | Invariants | Surviving masks for omitted coordinate |
|---|---|---|---|
| open-multiple-mutable | 000, 001, 010, 011, 100, 101, 110, 111 | none | A: none; C: none; P: none |
| open-exclusive-mutable | 010, 011, 110, 111 | C=1 | A: none; C: 15; P: none |
| atomic-multiple-mutable | 100, 101, 110, 111 | A=1 | A: 15; C: none; P: none |
| atomic-exclusive-mutable | 110, 111 | A=1, C=1 | A: 12,13,14,15; C: 12,13,14,15; P: none |
| open-multiple-erasable | 000, 001, 010, 011, 100, 101, 110, 111 | none | A: none; C: none; P: none |
| open-exclusive-erasable | 010, 011, 110, 111 | C=1 | A: none; C: 15; P: none |
| atomic-multiple-erasable | 100, 101, 110, 111 | A=1 | A: 15; C: none; P: none |
| atomic-exclusive-erasable | 110, 111 | A=1, C=1 | A: 12,13,14,15; C: 12,13,14,15; P: none |
| open-multiple-permanent | 001, 011, 101, 111 | P=1 | A: none; C: none; P: 15 |
| open-exclusive-permanent | 011, 111 | C=1, P=1 | A: none; C: 10,11,14,15; P: 10,11,14,15 |
| atomic-multiple-permanent | 101, 111 | A=1, P=1 | A: 10,11,14,15; C: none; P: 12,13,14,15 |
| atomic-exclusive-permanent | 111 | A=1, C=1, P=1 | A: 8,9,10,11,12,13,14,15; C: 8,9,10,11,12,13,14,15; P: 8,9,10,11,12,13,14,15 |
| open-multiple-expiring | 000, 001, 010, 011, 100, 101, 110, 111 | none | A: none; C: none; P: none |
| open-exclusive-expiring | 010, 011, 110, 111 | C=1 | A: none; C: 15; P: none |
| atomic-multiple-expiring | 100, 101, 110, 111 | A=1 | A: 15; C: none; P: none |
| atomic-exclusive-expiring | 110, 111 | A=1, C=1 | A: 12,13,14,15; C: 12,13,14,15; P: none |

Projection groups are built using only the retained coordinates. All pairs inside those groups are formed before testing the omitted coordinate. Equal retained projections with unequal omitted values reject all sixteen functions. Restricted profiles may constrain a coordinate; their surviving functions include every possible completion on unreachable inputs, rather than claiming unique global laws.

## What the event histories establish

The open mutable, erasable and expiring experiments allow historical authority and exact dispatch ancestry to vary independently of the selected current predicate. Atomic scoped authority checks remove invalid-authority commitment, exclusive trusted exact-tuple creation removes foreign origin, and permanent immutable retention with permanent-existence predicate removes predicate failure. The composed rows above give the resulting domain restrictions without changing the predicate within an experiment.

Restoration after commitment does not retroactively authorize an invalid commit. Revocation after a valid commitment does not falsify historical authority. Same attempt/different executor and same executor/different attempt both fail exact ancestry. A dedup reply returns an existing physical effect, with its existing origin; it does not grant the requesting attempt authorship. The two candidate commit orders yield different origins. Lost acknowledgement and retry retain cause under dedup; a non-dedup retry creates a second physical effect and fails the fixed cardinality contract. An old truthful snapshot may differ from present truth, and selecting a different observation changes the domain.

## EXACT_EFFECT disagreement search

The decision checker separately validates fixed contract obligations, one exact physical commitment, governing grant history at commit, the dispatch ancestry, and the selected live predicate. It never reads the computed A/C/P fields. Exhaustive checks found 0 equal-A/C/P decision conflicts under the same fixed contract. This agrees with the specification's meaning rather than establishing the conjunction through a preprogrammed cube oracle.

Seven diagnostic cases retain the focal physical semantics while violating fixed-domain selection, physical identity/cardinality, evidence trust, freshness/current-observer truthfulness, history continuity, or independent claim-policy selection. Their different eligibility decisions are surrounding-contract dependencies. They cannot be inserted as a new truth axis without changing the declared domain. A fabricated producer claim is explicitly separate from physical/event truth.

## Anti-smuggling classification

**authorized causal receipt: REPRESENTATION COLLAPSE.** A receipt that actually certifies exact commit authority and exact attempt/executor ancestry packages two separately grounded propositions. Adding a current-predicate attestation packages a third. DERIVATION: Trusted complete receipt, exact physical/scope binding, authoritative commit-point epoch and revocation history, and exact source tuple. The receipt can derive A and C. DERIVATION: The receipt establishes P at issue time, and the chosen predicate is preserved by all allowed transitions through the selected observation. Then P also follows; preservation is explicit and fails for open mutable, erasable or expiring profiles. SEMANTIC SMUGGLING: Calling an authorized-causal-current receipt merely C silently includes A and P in causal origin. Boundary: Signing or retaining a receipt alone does not preserve the live target predicate.

**state containing verified origin: DERIVATION.** Authenticated exact physical provenance linked to the started dispatch can derive C. Matching target bytes or a logical dedup key cannot. REPRESENTATION COLLAPSE: The state separately stores authenticated authority-at-commit, source tuple and live-predicate evidence. One record represents multiple semantic propositions. SUBSTRATE DISCHARGE: Complete mediation permits only this exact attempt/executor to create the exact initially absent effect. C is invariant true. SEMANTIC SMUGGLING: Redefining the independently selected state predicate to include verified origin imports C into P. Boundary: Provenance must remain attached to the exact historical physical effect through current-state changes.

**still-current receipt: DERIVATION.** A current receipt can establish P only under an explicit binding from its fresh authoritative observation to the independently fixed predicate. DERIVATION: Receipt initially proves P; every P-breaking transition invalidates its checked revision, and the checked revision/clock is read at the selected observation. Still-current receipt implies preserved P. REPRESENTATION COLLAPSE: The receipt also independently attests exact authority and source ancestry. Its single representation contains A, C and P evidence. SEMANTIC SMUGGLING: Defining causal validity to mean current receipt validity inserts P into C; selecting P to equal receipt validity changes the fixed predicate unless independently specified. Boundary: Unexpired receipt bytes do not show that a mutable target remains correct; a truthful earlier snapshot has its own observation time.

**unified business-effect record: REPRESENTATION COLLAPSE.** A common schema may store exact physical identity, scoped authority, source ancestry and current validity; one row does not reduce the number of propositions it represents. SUBSTRATE DISCHARGE: Enforced exact-authority admission, exclusive exact attempt/executor creation, or durable permanent retention is separately proved. Only the corresponding A, C or P obligation is discharged. SEMANTIC SMUGGLING: Replacing exact physical cause with logical business-key equality changes C, and aggregating duplicates hides physical identity/cardinality obligations. Boundary: Business key, exact physical effect, evaluated dispatch and current target are different bindings.

**atomic transaction: SUBSTRATE DISCHARGE.** Atomicity can discharge A when every creation atomically validates exact active scoped authority and current generation/epoch, revocation serializes with commit, and no bypass exists. DERIVATION: Transaction establishes P at commit and all permitted later transitions preserve the selected predicate through observation. P is derived conditionally; atomicity alone only establishes the commit-time state. SUBSTRATE DISCHARGE: The same trusted mediation additionally restricts the exact creator tuple, or enforces permanent immutable retention. C or P can separately become invariant. SEMANTIC SMUGGLING: Calling any atomic write authorized, or substituting its transaction snapshot for later selected current observation, imports obligations not supplied by atomicity. Boundary: Multiple authorized dispatches remain possible, and later mutable/expiry events remain possible.

**sole-writer store: SUBSTRATE DISCHARGE.** A sole writer discharges C only if trusted complete mediation proves that it serves solely the one evaluated exact attempt/executor for this initially absent effect. One service may serve many attempts. SUBSTRATE DISCHARGE: The sole writer also performs exact atomic authority checks and current epoch validation. A is invariant true. SUBSTRATE DISCHARGE: The selected predicate is permanent existence of a durably retained immutable event. P is invariant true. SEMANTIC SMUGGLING: Equating writer identity with evaluated attempt identity silently drops the attempt part of C; equating technical write access with governed authority drops A. Boundary: Same executor serving another attempt defeats causal inference even with a single writer.

DERIVATION means a separately proved fact implies another under stated assumptions, including explicit predicate preservation through observation. SUBSTRATE DISCHARGE means an enforcement restriction makes an obligation invariant. REPRESENTATION COLLAPSE combines distinct facts in one representation. SEMANTIC SMUGGLING changes the meanings by inserting authority, cause or present validity into another coordinate. Multiple labels can describe different uses of the same proposal.

## Limits

- Finite standard-library software experiment, not an external human laboratory or a proof about every implementation.
- Two executor agents of one fixed subject, two attempt IDs, one epoch advance, initial epoch-zero capability tokens, one identified physical effect and one finite target value abstraction.
- Core reachability explores all states of a behavioral quotient with at most one physical creation. Repeated authority/target cycles are quotiented by state plus retained raw commit-era facts. Dedicated scenarios cover two physical creations and cardinality failure.
- All physical operations are serialized events. Both orders of ready contenders and commit/revocation races are represented; weak-memory behavior, untrusted hardware and low-level partial commits are outside the trusted complete-event abstraction.
- Mutable restoration is restoration of the target value, not recreation of the same deleted physical event. An erased immutable record is not recreated under the old physical identity.
- Expiry uses two clock regions around a fixed deadline, sufficient for this selected expiring-validity predicate; clocks and evidence timestamps are trusted within the fixed contract.
- Producer claims, acknowledgements, dedup replies and old snapshots do not establish ground truth. Contract-invalid diagnostics hold physical semantics fixed and explicitly vary surrounding obligations.
- Trusted event records model factual evidence; this is not a cryptographic implementation or a defense against fabricated records.
- Predicate IDs, scope, evaluated tuple and selected observation are fixed per experiment; different lifecycle predicates are separate experiments.
