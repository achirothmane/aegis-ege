# Cycle 4: eliminate separate custody in an atomic native destination

Baseline: merged #239, `2704032d9b6da0d23fa647886df8f2fdc900f240`.
This cycle tests a stronger alternative than deleting a custody check from the
old runtime: it removes the separate mutable effect-owner register entirely.
The candidate executes real PostgreSQL transactions and submits their real
observations to the unchanged production evidence consumer. It does not add a
model oracle or change the frozen generic runtime to fit the alternative.

## Candidate and retained relations

Every trial drops the native `custody` table. The alternate executor has no
reserve/load/phase/transfer operation and no mutable current effect-owner
generation. There is no durable per-attempt input file. A surviving independent
caller supplies the requested claim to fresh executor/observer processes.

The destination locks the target, checks the signed exact admission against the
current locked authority epoch/generation, and checks a stable logical effect
key. It appends a row to a non-idempotent ledger, updates the target state and
inserts an immutable completion receipt **in the same SQL transaction**. The
receipt is written after the effect statements and before commit, never as a
separate pre-dispatch reservation. Competing admitted attempts serialize using
native transaction locks. A completed effect is not reexecuted or relabeled as
the successor's cause.

| Relation | Candidate treatment |
| --- | --- |
| Current effect owner, mutable custody phase and transfer generation | Removed; the custody table is absent throughout each test |
| Exact trusted admission and authority at the effect boundary | Retained; signed exact request and current native authority generation checked under transaction lock |
| Stable effect identity and durable completion retention | Retained in the destination's atomic immutable receipt |
| Actual committer/attempt and transition | Retained as causal evidence in that receipt; not synthesized from the recovering actor |
| Truthful closure and independent claim strength | Retained in the unchanged standalone consumer and independently supplied `EXACT_EFFECT` policy |
| Pending execution serialization and abort cleanup | Supplied by PostgreSQL transaction locks and rollback; not a portable current-custodian interface |

The v1 evidence transport still has `CustodyGeneration=1`. Here it is a fixed
initial attempt tag for exact receipt joins; no operation increments, selects
or transfers it. Removing the mutable register does **not** remove this field,
the immutable attempt/cause relation, or retention. Calling the receipt
"closure evidence" instead of "custody" would not by itself erase a semantic
relation. The bounded reduction is specifically the separate mutable ownership
relation under a transactionally closed destination profile.

## Native separating cases

The actual effect is an append to a separate ledger without an effect/dedup key.
Its physical tally is independent of the receipt table. The admitted transition
has equal before/after state, so state CAS/equality cannot conceal a duplicate
non-idempotent append. This is permitted by K02's effect/state separation.

| Native case | Required result |
| --- | --- |
| Commit, suppress the callback ACK, executor exits 100, fresh observer and successor | One ledger append; original attempt can close exactly; successor receives existing completion and cannot claim the original cause |
| Same crash, exact observation withheld | `UNKNOWN`; read-only recovery changes no tally; stale admission cannot execute; even a newly admitted successor cannot replay the completed effect |
| Executor exits 99 after SQL effect/receipt writes but before commit | Both writes roll back; original is `UNKNOWN`; a separately authorized successor may commit exactly once |
| Two simultaneously authorized successor attempts | One append and one immutable actual committer; losing attempt's false exact closure is rejected |
| Valid historical completion followed by a later target-state change | Receipt is byte-identical and causality remains exact; current false `CLOSED` is rejected |
| Remove only the native completion retention write | The lost-ACK successor commits a second physical append; the precise retention assertion fails with `committed_effects=2` |

Process barriers establish transaction visibility before the abrupt exit;
exiting does not run the executor's rollback defer. The pre-commit PostgreSQL
connection dies and the destination rolls back. Recovery uses a separate
process with only a dedicated `SELECT` credential; an attempted native update
must be denied. The standalone consumer is another process, receives only the
bundle/public policy files, and has no destination credentials or signing keys.
The caller supplies new execution authority explicitly; `UNKNOWN` supplies none.

`scripts/run_custody_elimination.py` runs the complete positive corpus, removes
the single live `retainNativeCompletion` call, compiles the actual alternate
native executable with race detection, and runs the lost-ACK retention case.
Only a semantic assertion showing **two committed ledger effects** counts as
the erasure witness. Compile failures, skipped tests and unrelated failures
are rejected. The exact source is restored and every positive case rerun.
This witness falsifies erasing retention from this alternative, not every
possible custody-less architecture or every completion representation.

The composite gate still requires all six #235 and three #239 native cases,
plus these six candidate cases without skips. Fourteen old source blobs are
pinned in the new additive manifest, including the #236 consumer and #239
tests/manifest/harness. The earlier 142 standalone outcomes, 176 differential
traces, ten removal witnesses and immutable historical source pins remain
required. The old source and old evidence grades are not repinned.

## Scope, prior art and interpretation

This experiment can demote **a separate mutable custody register** in the
tested PostgreSQL profile. It cannot justify global elimination of durable
effect retention, a four-to-three carrier change, or three-to-two universally
necessary obligations. The generic production runtime remains unchanged.
All physical effects here are contained in one native transaction. External
HTTP effects, cross-destination atomicity, loss of all caller state, completion
garbage collection, unbounded retries and destination rollback/loss are outside
the demonstrated contract. Receipt retention must cover eligible retries; any
reclamation would need an independently enforced exclusion rule.

The alternative's core mechanism is prior art. [RIFL (SOSP 2015), sections 3.1
and 3.2](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf) describes durable
completion metadata atomic with mutations, retry rendezvous, and safe retention
or exclusion of stale clients. [DBOS's official transaction
documentation](https://docs.dbos.dev/python/tutorials/transaction-tutorial)
describes recording a transaction result in the same datasource transaction
and returning that retained result on workflow replay. The native destination
therefore carries real atomicity, serialization and retention responsibility;
deleting an application table does not delete that trusted machinery.

If the positive corpus passes, the verdict is **MERGE/DEMOTE the separate
mutable ownership register in this bounded profile; KEEP the durable
effect/completion/cause relation**. If completion erasure yields the specified
second append, it is a bounded necessity witness for retained retry distinction
in this alternative. Neither verdict makes custody universally irreducible or
introduces a novel Aegis primitive. Classification remains **useful composition
of known mechanisms**. Native execution results belong to the generated CI
artifact and exact tested head, not an assumed local PostgreSQL run.
