# Cycle 8: precedence challenge and specification-only reproduction

Starting live main: `271c40bbf46d75f8c3c09c04fe651195e572ab2b` (#243).
The complete Cycle 7 report and executable corpus were read before edits.
All changes in this cycle are additive research, evidence or assurance files.
No production policy, runtime, public API, claim type or fourth axis is added.

## Disposition

**Prior-art class: N1 — KNOWN CONSTITUENTS + KNOWN COMPOSITION.**
The three obligations and their ordinary conjunction are replaceable with known
authorization, transaction/origin, current-view and verification mechanisms.
No examined single primary source is credited with the identical open-mutable
three-projection theorem. That prevents an N0 attribution; it does not justify
an originality thesis. The executable corpus is useful engineering evidence,
but a new table of familiar predicates is insufficient intellectual novelty.

**Reproduction class: R4 — independently reproduces across multiple realizations
and survives deliberate disagreement search**, within the declared software
bounds and trusted surrounding contract. The exact measurements and limits
appear below. Successful reproduction does not upgrade the precedence class.

**Publication class: P1 — useful engineering note / technical report only.**
The present evidence supports an explicit reproducible caution about conflating
commit authority, exact origin and present state. It does not yet establish a
research contribution strong enough to prepare a formal paper submission.

## Exact definitions and domain

Fix the governing subject, exact logical effect, target, independently selected
claim predicate, generation/epoch, enforcing boundary and evaluated attempt q.
Let e be an actual committed physical effect, t_e its actual commitment point,
and t_o the current observation point.

- **A(e)**: relevant governed authority for the exact subject, action/effect,
  target, generation/epoch and boundary was valid at t_e. This concerns the actual
  effect; it does not assert that q caused it. Both competing origins can be
  authorized for the same scope.
- **C(e,q)**: that actual physical effect was caused by q's exact attempt AND
  executor identity. Equal state, logical operation key, response, or effect
  cardinality does not establish that origin.
- **P(e,q,t_o)**: the independently chosen fixed current predicate is true at
  t_o. It does not include A or C implicitly. Permanent event existence and
  unexpired validity are different independently selected profiles.

No-effect worlds have undefined A-at-commit and are excluded. The open mutable
class permits governed revocation/restoration, competing origins, technical
writers outside the governed boundary and later mutation. Unauthorized worlds
do not demonstrate failure of a completely mediated native fence.

The surrounding proof contract fixes exact scope/identity, one-effect
cardinality, independent claim selection, truthful current observation,
admissible evidence and trust roots. Historical continuity is separately required
when trusted history is claimed. No bit vector alone establishes these inputs.

## Strongest prior art and closest joined precedents

The full [responsibility matrix](prior-art-cycle-8.json) has 42 serious primary
source records with every requested field: date/reference, object, guarantee,
boundary, revocation, lost ACK, retries, operation identity, actual-attempt
attribution, current semantics/freshness, history, assumptions, proved/withheld
claims, relationships to A/C/P, explicit separation, derivation/discharge and
classification. [The search log](search-log-cycle-8.md) records semantic/theorem
queries, examined-source limits and the research stop decision.

| Primary source / date | Closest contribution | Missing relation or restriction | Classification |
|---|---|---|---|
| [Daml structured ledger, CSF 2019](https://www.canton.io/publications/csf2019-abstract.pdf) | Atomic updates carry requester/actor authorization; a created contract may later be consumed | On-ledger validity boundary; no exact external worker-attempt lower bound | CLOSE BUT MISSING RELATION |
| [Canton detailed ledger model, inspected 2026-10-04](https://docs.canton.network/overview/reference/ledger-model-detailed) | Authorization context, unique commit identity and current active-state projection are distinct | Exact update/requester identity differs from the physical executor; complete valid-ledger mediation restricts worlds | CLOSE BUT MISSING RELATION |
| [Stacks SIP-005, created 2019-07-23](https://github.com/stacksgov/sips/blob/main/sips/sip-005/sip-005-blocks-and-transactions.md) | Authorization, originating/sending account and transaction postconditions in one transaction | Transaction-time conditions do not establish later independent present truth | CLOSE BUT MISSING RELATION |
| [UCONABC, 2004](https://profsandhu.com/journals/tissec/p128-park.pdf) and [formal UCON, 2005](https://profsandhu.com/journals/tissec/p351-zhang.pdf) | Continuing authorization, mutable attributes and temporal conditions | Obligation fulfillment is not physical attempt identity; formal core excludes post-use obligations | PARTIAL PRECEDENT |
| [RIFL, SOSP 2015](https://sigops.org/s/conferences/sosp/2015/current/2015-Monterey/126-lee-online.pdf) | Atomic durable operation result, stable identity and retry rendezvous | Logical RPC identity is not exact worker identity or present target truth | KNOWN MECHANISM |
| [W3C PROV, 2013](https://www.w3.org/TR/prov-dm/) | Generation/activity/agent relations and invalidation | A provenance assertion needs authenticity and does not enforce authority | PARTIAL PRECEDENT |
| [Jensen/Snodgrass, 1996](https://www.cs.arizona.edu/sites/default/files/TR96-02.pdf) | Historical recording and fact-specific current validity | Temporal data does not supply physical origin or governing permission | PARTIAL PRECEDENT |
| [PCA, CCS 1999](https://www.cs.princeton.edu/~appel/papers/says.pdf), [TUF](https://theupdateframework.github.io/specification/latest/), [CT RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | Independent assumptions, expiry/revocation, root succession and authenticated history | Verified history is not authorized/current external effect | KNOWN MECHANISM |
| [BLF, CSFW 2004](https://people.eecs.berkeley.edu/~necula/Papers/sigpcc_csfw04.pdf) | Authorization logic joined to semantic proofs; signer origin distinguished from correctness | Program admission differs from exact external effect/current truth | KNOWN COMPOSITION |

The closest joint source is the structured Daml/Canton ledger. Its authorization
context cannot be obtained from the action alone; retained updates coexist with
a changing active-contract set. SIP-005 is the clearest existing transaction
composition of authorization, origin and postconditions. Neither is relabeled
as a proof of the fixed open-boundary A/C/P theorem.

BLF is an earlier joined proof/authorization precedent. Its conservativity and
decision-procedure theorems concern policy/proof logic, rather than the three
external-effect projections. Proof-carrying data supplies historical transcript
compliance, with current external facts requiring additional modeled inputs.

**Theorem search result:** no equivalent full three-projection theorem was
identified in the primary sources examined. No source supplied a valid general
derivation of A from C/P, C from A/P or P from A/C under the frozen open mutable
assumptions. This is not a universal literature absence statement. Relevant
formal results concern authorization temporal policies, provenance consistency,
linearizable histories, interference assumptions and authenticated data.

Conditional preservation under retained immutable existence and fully mediated
authority/origin constraints is already explained by those known mechanisms.
No discovered derivation falsified the bounded claim without adding a restriction
or expanding a retained predicate's meaning.

## Strongest prior-art substitute and executable replacement trial

The replacement is scoped ongoing authorization plus destination serialization,
stable operation identity, one atomic business-effect/origin record, provenance,
current observation, authenticated log/checkpoint and independently provisioned
verifier question and roots. These obligations need no new Aegis-specific concept.

`experiments/precedence_repro/substitute.py` is a standalone SQLite implementation
of that reconstruction, with standard Ed25519 via the experiment-only
`cryptography==46.0.0` dependency. The effect/origin record, target update and
hash-linked history append share one SQL transaction. Fixture observer/custodian
keys are public deterministic test seeds. Verifier roots, selected claim, expected
checkpoint and observation point are supplied separately from signed envelopes.
This is an executable mechanism reconstruction, not a claim to have installed
RIFL, DBOS, Daml or TUF or implemented their complete protocols.

| Trial | Native result | Truth | Independently selected EXACT_EFFECT |
|---|---|---|---|
| Revoke, exact claimant commits outside closed fence, restore | One committed effect | 011 | UNKNOWN |
| Different authorized attempt/executor wins same logical effect | One committed effect | 101 | UNKNOWN |
| Exact authorized commit followed by target mutation | Historical commit retained | 110 | UNKNOWN |
| Exact authorized commit and required current view | One committed effect | 111 | CLOSED |

Eight representative substitute tests passed: these separating cases;
commit-time rejection of revoked/stale generation; exact sole-attempt constraint;
permanent existence versus expiry/deletion; replay preserving the original
winner; independent question/roots; old authentic observation versus changed
world; and history/checkpoint authenticity separate from effect closure.
The independent reproductions below exercise the full profile space rather than
only the four representative controls.

Replacement scope is deliberately bounded: it reproduces the semantic cases,
profile restrictions and representative proof-contract limitations. It does not
replace Aegis's full PostgreSQL/Kubernetes/TPM/succession runtime, fault-tolerance
protocol or performance profile. The original constitutional corpus remains the
authority for those implementation guarantees.

## Clean-room input, architecture and exclusion

The [frozen specification](../../../experiments/precedence_repro/specification.md)
has SHA-256
`50e59249ff4fa50300ec9df39228b960acaf1a5e6a01513b1f3d8452f1ae12ac`.
It includes only definitions, domain and proof-contract assumptions, the decision
question, falsification questions, restricted profiles and interpretation rules.
No expected reachable corner set or restricted-profile answer was supplied.

Two fresh-context reproduction agents received that file and an isolated output
directory. Neither received the repository, Cycle 7 report, runtime packages,
`experiments/acpbasis`, test helpers, existing cube constructors, fixtures,
result oracles or the other reproducer's source/results. Their own data models,
transition implementations, observation oracles and test generation were written
from the specification. Execution-interface guidance supplied no result answers.
The parent copied their sources and original evidence byte-for-byte only after
both had declared their results frozen; none was corrected to match Cycle 7.

- **SQLite realization:** separate grants/epoch, physical commit archive,
  retained events, mutable targets, journal and producer-claim tables. Native
  `BEGIN IMMEDIATE` transactions and schema triggers implement restrictions.
  A separate storage-free Python replay oracle checks every explored transition.
  The depth-five BFS merges equal continuation facts, not equal A/C/P bits.
  A real child process exits after COMMIT without acknowledgement; reopening
  the WAL database and retrying preserves the original effect and origin. A
  before-COMMIT process-exit control leaves no committed effect.
- **Event/history realization:** standalone JavaScript dispatched-attempt ancestry,
  factual commit/revocation events, target lifecycle and clock regions. A finite
  behavioral graph closes under its enabled transitions; a separate history
  interpreter derives A/C/P. Its independently structured EXACT_EFFECT witness
  checker reads authority history, dispatch ancestry, current predicate and
  contract obligations without reading the computed A/C/P fields.

Both programs group samples by retained values before inspecting omitted truth,
then enumerate all sixteen total Boolean functions for each retained pair.
Producer claims, logical dedup keys, acknowledgements and snapshots are kept
separate from physical/oracle facts. Their original data are retained in the
[SQLite evidence](../../../experiments/precedence_repro/sqlite/evidence/results.json)
and [event-model evidence](../../../experiments/precedence_repro/event_model/results/analysis.json).

Frozen SQLite result SHA-256:
`ec428ba3887ea8944c4ce6c77a7f0ba3422db0e1529ece1012ca63905403494d`.
Frozen event-model result SHA-256:
`08855a12817f13c3c2199f69ffb9e18071cf9a410da6211ccef28ab77db09769`.
Parent reruns reproduced both complete JSON files byte-for-byte. Individual
source/input/output hashes and the post-freeze comparison interfaces are in
the [registration](../../../testdata/governed-action/kernel-shrink/independent-reproduction-v1.json)
and each producer's original freeze manifest.

## Independent results and comparison

| Realization | Tests/checks | Discovered states | Explored transitions | Bounds and extra checks |
|---|---:|---:|---:|---|
| Native SQLite plus replay oracle | 14 passed | 9,776 | 60,096 | Depth 5, 16 profiles, process-exit/recovery and native write-lock serialization |
| JavaScript event/history model | 16 passed | 12,288 | 60,736 | Closed finite quotient, 16 profiles, 23 deliberate ordered-event scenarios |
| Parent known-mechanism substitute | 8 passed | Representative trials | Four decisive controls | Independent question/roots, Ed25519/checkpoint, replay and old-observation controls |

Each independent producer checks 768 retained-pair functions across its sixteen
profiles. The parent runner separately enumerates functions over each emitted
truth set after execution. It then executes the original Cycle 7 model and
compares all seven shared profiles. All sixteen profiles also agree between
the two independent realizations. The
[post-freeze comparison](../../../testdata/governed-action/kernel-shrink/independent-reproduction-result-v1.json)
records **zero reachable-set or function-set disagreements**.

| Shared Cycle 7 profile | Independently discovered committed A/C/P set | Invariant / discharge |
|---|---|---|
| Open mutable | 000, 001, 010, 011, 100, 101, 110, 111 | None |
| Mutable, atomic exact-authority guard | 100, 101, 110, 111 | A=1 |
| Mutable, exact sole creator | 010, 011, 110, 111 | C=1 |
| Permanent immutable event, existence predicate | 001, 011, 101, 111 | P=1 |
| Permanent event with both restrictions | 111 | A=C=P=1 |
| Erasable immutable event | 000, 001, 010, 011, 100, 101, 110, 111 | None |
| Retained immutable bytes, expiring-validity predicate | 000, 001, 010, 011, 100, 101, 110, 111 | None |

All other combinations are included in the sixteen-profile evidence. In
particular, both authority and creator restrictions on a mutable/expiring
predicate yield 110/111; authority with permanent existence yields 101/111;
sole creator with permanent existence yields 011/111. Those are domain
restrictions, not general derivations in the original open mutable class.
Behavior on unreachable retained inputs is unconstrained: multiple total
functions may fit a restricted profile without becoming universal laws.

## Independent separating witnesses

These positive-retained witnesses were selected from independently discovered
projection groups and factual traces after freeze. No cube constructor assigned
their truth values.

| Omitted relation | Equal retained projection | SQLite physical traces | Event/history traces | Discovered differing truth |
|---|---|---|---|---|
| A | C=P=1 | q commits; versus revoke q's executor, then q commits outside guarded mediation | Start q and commit; versus start q, revoke, commit | 111 versus 011 |
| C | A=P=1 | q commits; versus another attempt using the same executor commits | q dispatch commits; versus same attempt with another executor commits | 111 versus 101 |
| P | A=C=1 | q commits; versus q commits then target mutates | q dispatch commits; versus commit followed by target change | 111 versus 110 |

Each retained projection is equal while its omitted value differs, so none of
the sixteen candidate functions fits that omitted relation. Both producers also
retain witnesses for every other discovered corner and pair-function failure.
Later authority restoration cannot change A-at-commit; target restoration can
change P without changing exact historical C.

## Deliberate disagreement search and fourth-coordinate question

The reproductions vary both contender orders, adjacent commit/revocation,
restoration before/after commit, epoch changes, same attempt/different executor,
same executor/different attempt, mutation/restoration, deletion, event erasure,
expiry, deduplication, retry, missing ACK and old truthful observations. SQLite
also exercises exact subject/action/target/boundary/generation mismatches and
native lock serialization. No equal truthful A/C/P vector produced a different
EXACT_EFFECT judgment with the **same fixed surrounding contract**.

The strongest challenge is a non-deduplicated retry: the focal first effect can
remain 111 while a second physical effect makes exactly-one closure fail. That
is a real cardinality dependency, already retained by #241 and the fixed proof
contract. It would refute sufficiency of A/C/P *alone*; that sufficiency is not
claimed. Similarly, unchanged physical truth with untrusted evidence, substituted
scope/policy, broken required history or a falsely current observer can change
the evidence judgment. Both analyses expose and classify those contract failures.
An authentic old 111 snapshot after mutation is not equal present semantic
truth: the present predicate has changed. Snapshot authenticity supplies no
autonomous wall-clock freshness theorem.

**No fourth semantic coordinate became necessary within the fixed domain.**
This conclusion remains conditional: the question itself specifies the three
obligations, SQLite's truth-level decision uses their conjunction, and the event
checker reconstructs the corresponding witnesses. The search does not prove
that every other action policy can be reduced to this question.

## Independent anti-smuggling review and disagreements

The two analyses independently give different leading labels to some proposals
because they analyze different uses of the same record. Their expanded semantic
conclusions agree. The original classifications are retained rather than edited.

| Proposal | SQLite leading classification | Event-model leading classification | Expanded conclusion / Cycle 7 comparison |
|---|---|---|---|
| Authorized causal receipt | DERIVATION from complete trusted evidence | REPRESENTATION COLLAPSE | Receipt to A/C is legitimate evidence projection; calling the bundle bare C and deriving A from C alone is SEMANTIC SMUGGLING |
| State containing verified origin | REPRESENTATION COLLAPSE | DERIVATION from separately authenticated provenance | One record may carry P and C; redefining independent P to include C is SEMANTIC SMUGGLING |
| Still-current receipt | DERIVATION with observation/preservation assumptions | DERIVATION with observation/preservation assumptions | Fresh bound observation or proved preservation can establish P; an old/unexpired receipt alone cannot |
| Unified business-effect record | REPRESENTATION COLLAPSE | REPRESENTATION COLLAPSE | One row packages obligations; business-key equality and cardinality do not establish exact origin |
| Atomic transaction | SUBSTRATE DISCHARGE only with complete exact checks | SUBSTRATE DISCHARGE under that restriction | Ordinary atomicity alone does not supply commit authority or later predicate preservation |
| Sole-writer store | No discharge from sole writer alone; SUBSTRATE DISCHARGE with exact creator restriction | SUBSTRATE DISCHARGE only with exact creator restriction | One service can serve many attempts; sole process identity is insufficient |

These label differences are not unresolved profile disagreements. Cycle 7's
smuggling rows expressly concern redefinitions of C or P, which both reproductions
reject. A composite certificate openly carrying separately proved facts is
legitimate. Permanent retention can also be described as conditional derivation
of present existence from historical creation; the resulting profile invariant
P=1 agrees with Cycle 7's explicit-assumption preservation argument.

Other differences are model representation and exploration bounds: SQLite has
9,776 depth-bounded states; the event quotient has 12,288 closed finite states;
Cycle 7 has 256 states across seven profiles. Those are not interchangeable
state counts. Scope/identity facts are fixed or abstracted differently, and the
independent producers cover nine additional restriction combinations. The truth
sets and fitting Boolean functions agree in every compared semantic profile.
No constitutional defect or production correction was exposed.

## Reproducible execution

From the repository root with Python 3.12, Node 24 and experiment-only
`cryptography==46.0.0`:

```sh
python3 -B scripts/run_independent_reproduction.py --out /tmp/independent-reproduction
```

The runner checks frozen hashes and all original blobs, executes both isolated
programs and their tests, and compares only afterward. It fails and preserves
evidence if a disagreement appears. The native and event programs can also run
separately using the commands in their unchanged READMEs. Neither imports the
parent registration, old expected results or frozen result JSON as an oracle.

The fixture scheduler/observer grounds physical attempt identities and truthful
commit facts. SQLite columns, signatures and event records are not themselves
proof against a lying trusted observer. Complete mediation excludes schema
replacement, privileged corruption and bypass writers in restricted profiles.
Tests cover process crashes and serialization, not hardware power loss,
weak-memory execution or Byzantine consensus. These limits remain explicit.

## What the bounded statement actually establishes

For a fixed committed-effect domain, equal retained coordinate projections with
different omitted truth values refute all total Boolean functions on that pair.
The result establishes **projection irredundancy of these three specified
predicates**. It does not establish three unavoidable implementation primitives.

An integer, record or verified aggregate claim can encode several relations.
Losslessly retaining all eight distinct truth vectors would require three bits
of information, while answering the single conjunction question can be encoded
in one decision bit under an adequate trusted contract. Neither observation
proves a universal minimum number of records, concepts, proof objects or services.
Calling an aggregate receipt a derivation from causality alone would obscure
extra semantics; openly certifying the complete aggregate obligation is legitimate.

The EXACT_EFFECT question itself names the three obligations. Reproducing its
abstract evaluator therefore validates the specified distinctions and reachable
traces; it cannot establish completeness for every other consequential-action
question. Additional policy, identity, trust, freshness and history obligations
must remain visible rather than disappearing behind the predicate notation.

## Claims withheld

No universal minimum/kernel theorem, global first/novelty assertion, statistical
independence, irreducibility on every substrate, portable sufficiency from A/C/P
alone, perpetual wall-clock freshness, hardware WORM result, or independent
external human peer review is claimed. The reproduction is independence of
implementation and context from supplied source code, within one orchestrated
software research run; it is not institutional or model-family independence.

No product feature, new public API or production policy was developed. Publishing
this report is a research record, not a product/distribution readiness decision.

## Constitutional preservation

The preservation check compares every preexisting Git blob against the starting
main, including all earlier models, tests, fixtures, policies and workflows.
Its scope is stronger than checking only the eight production Go files. New
research files do not become inputs to the existing Cycle 7 oracle.

| Anchor | Obligation retained |
|---|---|
| #235 | Effect finality, authority/history succession and independent verification |
| #236 | Claim strength is selected independently by the relying party |
| #239 | State/custody does not establish cause; historical cause does not establish current closure |
| #240 | Fewer representations do not eliminate semantic obligations |
| #241 | One physical effect row still requires replay exclusion and exact-origin evidence |
| #242 | A/C/P separation is bounded to the declared mutable class |
| #243 | Conditional discharge, eight-corner reachability and the bounded projection result |

Baseline production fingerprint: 8 Go files, 1,550 lines, 51,499 bytes;
canonical SHA-256
`521371fb3ec22c7ab3054ba664ec0e5e7f570e8847113b1ad867b46e85a67ea1`;
`governedaction` tree
`6c6b1e754a369cf8d30f627af1ead8b9b3835f14`.
The final independent runner records before/after fingerprints and preservation
of all 774 original repository files in its machine-readable artifact.
All 774 matched in both checks. Production files/lines/bytes, canonical SHA-256
and the complete `governedaction` tree are identical before and after execution.

The baseline Cycle 7 runner, all 23 existing Python kernel-verifier tests and
the kernel-shrink checker passed locally. Go, PostgreSQL, Kubernetes and the
native provider tooling are unavailable in this workspace; the unchanged
repository workflows provide those constitutional checks on the PR commit.
The new source-registration file triggers those existing native workflows as
well as the additional independent reproduction workflow.

## Final synthesis

After prior-art subtraction, the surviving evidence is an explicit engineering
separation of three familiar predicates: commit-point permission, exact physical
attempt/executor origin, and independently selected present truth. The two
specification-only realizations reproduce their projection irredundancy in the
declared open mutable class and reproduce the stated profile restrictions.
No examined prior theorem falsifies that bounded truth claim. The known-mechanism
replacement supplies the same semantic composition without an Aegis-specific
concept, so an originality thesis for the composition is not supported.

Representation reduction can package the propositions. Enforcement and predicate
preservation can make coordinates invariant in restricted domains. Expanded
certificates can legitimately prove several propositions; renaming a composite
as one of the original predicates does not eliminate its dependencies. Cardinality,
identity, trust, history, policy and current-observer assumptions remain explicit.

Final decisions: **N1 / R4 / P1**. Preserve this as a useful reproducible engineering
report. The evidence does not justify preparing a formal paper submission on
novelty or a universal minimum. Expert identification of a genuinely equivalent
earlier theorem, or a counterexample under the same fixed contract, would reopen
the relevant classification.
