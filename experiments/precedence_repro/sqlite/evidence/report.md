# Independent SQLite reproduction

The only semantic input was the frozen specification. No repository, corpus, helper, fixture, report, production code or other agent source was read or imported.

The experiment uses real SQLite transactions and a separately written storage-free replay oracle. Historical physical-effect facts, current target/event state and producer claims occupy separate tables. A/C/P are computed from operational facts; no action assigns truth axes.

| Predicate | Atomic authority guard | Exact creator restriction | Discovered A/C/P | Invariants |
|---|---:|---:|---|---|
| mutable | 0 | 0 | 000, 001, 010, 011, 100, 101, 110, 111 | {} |
| mutable | 0 | 1 | 010, 011, 110, 111 | {"C": 1} |
| mutable | 1 | 0 | 100, 101, 110, 111 | {"A": 1} |
| mutable | 1 | 1 | 110, 111 | {"A": 1, "C": 1} |
| retained | 0 | 0 | 001, 011, 101, 111 | {"P": 1} |
| retained | 0 | 1 | 011, 111 | {"C": 1, "P": 1} |
| retained | 1 | 0 | 101, 111 | {"A": 1, "P": 1} |
| retained | 1 | 1 | 111 | {"A": 1, "C": 1, "P": 1} |
| erasable | 0 | 0 | 000, 001, 010, 011, 100, 101, 110, 111 | {} |
| erasable | 0 | 1 | 010, 011, 110, 111 | {"C": 1} |
| erasable | 1 | 0 | 100, 101, 110, 111 | {"A": 1} |
| erasable | 1 | 1 | 110, 111 | {"A": 1, "C": 1} |
| expiring | 0 | 0 | 000, 001, 010, 011, 100, 101, 110, 111 | {} |
| expiring | 0 | 1 | 010, 011, 110, 111 | {"C": 1} |
| expiring | 1 | 0 | 100, 101, 110, 111 | {"A": 1} |
| expiring | 1 | 1 | 110, 111 | {"A": 1, "C": 1} |

Depth bound: 5. Native transitions independently checked: 60,096. No native/oracle mismatch occurred. No fixed-contract decision disagreement was found among equal semantic A/C/P observations.

Projection groups were formed using only retained coordinates before examining the omitted coordinate. Every one of the sixteen total Boolean functions was enumerated for each omitted coordinate and each profile. The JSON includes all truth tables, fitting masks, concrete counterexamples, minimal corner traces and equal-projection witness pairs. Surviving functions are compatible with the discovered restricted domain; unobserved input rows are unconstrained.

Commit/revoke ordering, restoration, epoch mismatch, foreign origin, the same attempt with a different executor, deduplication, mutation/restoration, erasure, expiry and stale observation are represented by operations. File-backed tests kill a subprocess after COMMIT and before acknowledgement, reopen its WAL database, retry the same attempt and then try other attempts/executors. Exactly one physical effect persists; retry receipts do not determine its creator.

The focused comparison also probes surrounding-obligation changes. Identical physical A/C/P with a changed decision arises when an envelope violates fixed scope, cardinality/selection, trust, observer freshness/truthfulness, history continuity or independently selected claim policy. Those probes are labeled contract violations, rather than silently adding an axis. See the JSON for explicit classifications and underlying native facts.

## Anti-smuggling classification

* **Authorized causal receipt — DERIVATION** when independently trusted evidence proves exact commit-time scope authority and exact attempt/executor origin. Its expansion is A and C. Calling that combined receipt bare causality hides authority and is **SEMANTIC SMUGGLING**.
* **State containing verified origin — REPRESENTATION COLLAPSE**: one record can contain both live state evidence and creator evidence. An independently selected state-value predicate alone still does not establish C; comparing verified exact creator IDs does. Building origin into the meaning of generic P is **SEMANTIC SMUGGLING**.
* **Still-current receipt — DERIVATION only with explicit conditional predicate preservation** or a truthful current observation. A past receipt plus allowed mutation/erasure/expiry does not imply current P. Defining currentness into receipt validity bundles the observation coordinate and requires expansion.
* **Unified business-effect record — REPRESENTATION COLLAPSE**: a composite record can represent authority history, creator identity and current predicate evidence together. Verification must expand all three obligations; a logical operation key is not physical identity or causation.
* **Atomic transaction — SUBSTRATE DISCHARGE only under the authority profile's exact checks, current epoch, all-writer mediation, no bypass and serialized revocation**. Bare all-or-none commit implies none of the semantic coordinates by itself. Atomic creation does not preserve a mutable or expiring predicate.
* **Sole-writer store — no creator discharge from one SQLite writer**. The same writer serially serves different attempts and executors. **SUBSTRATE DISCHARGE** of C requires the explicit exact-creator restriction and trusted complete mediation. Deduplication selects an existing effect and never reassigns origin.
* **Permanent event existence — SUBSTRATE DISCHARGE** of P for the independently fixed existence predicate under permanent retention. Immutability of bytes alone does not preserve existence or expiring validity.

## Reproduction

```sh
cd cleanroom-sqlite
python -m unittest -v test_sqlite
python explore.py --output /path/to/output-directory --depth 5
```

The second command emits `results.json` and `report.md`. To emit JSON to standard output, use `python explore.py --depth 5` without `--output`. Both commands are independent of the original workspace path.

## Limits

* Deterministic depth bound; discovered reachability is evidence, not an exhaustive unbounded theorem.
* Two executors and two attempt IDs; one fixed subject, effect, target, epoch, boundary, evaluated attempt and observation predicate per experiment.
* State merging preserves continuation facts, including physical creator and raw commitment authority facts; ACK claims and absolute journal sequence do not govern modeled continuations.
* SQLite native transactions and file durability are exercised; this is not a hardware power-loss or distributed consensus test.
* The trusted test driver grounds request/executor identity; SQLite text columns and a producer receipt are not an external cryptographic identity proof.
* Profile restrictions assume trusted complete mediation; a privileged actor able to replace schema or corrupt the database violates that surrounding obligation.
* Software independence from the frozen specification; not an independent external human laboratory.
