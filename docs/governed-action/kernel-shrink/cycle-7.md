# Cycle 7: conditional collapse and bounded A/C/P falsification

Starting main: `413229f06e7843e1e465062a795035d2c8272595` (#242).
This cycle adds experiments and assurance gates. It changes no production code,
claim type, public API, kernel record, or independent trust policy.

**Disposition: B, within the declared bounded class.** Mutable effect profiles
retain three non-derivable truth coordinates. Specific closed destination
profiles discharge coordinates, sometimes all three, with native mechanisms.
This is not a universal minimum, a statistical independence result, or a novelty
claim. Whether the basis is universal remains unresolved.

## Stable definitions and domain of the predicates

Fix a governing subject, exact logical effect, target, independently selected
claim predicate, and enforcing boundary. Let `e` be the actual committed physical
effect, `q` the claimed execution attempt, `t_e` the commit linearization point,
and `t_o` the current observation point.

- **A(e)**: the relevant governed authority for that exact subject, action/effect,
  target, generation/epoch and boundary was valid at `t_e`. In the foreign-attempt
  case both candidate executors are authorized for the same exact scope. A is
  authority for the actual effect, not proof that the claimant caused it.
- **C(e,q)**: that exact physical effect was caused by the exact attempt and
  executor identity named by `q`. Equivalent state or the same logical effect key
  produced by another authorized attempt does not satisfy C.
- **P(e,q,t_o)**: the current truth predicate selected independently for the
  claim profile is satisfied at `t_o`. PostgreSQL/Kubernetes select exact current
  target state. The immutable-event profile selects permanent existence of the
  exact event. The expiring-event profile selects existence AND unexpired
  validity. Each predicate is fixed before its experiment, not changed mid-trace.

No-effect states are outside the committed-effect cube: A-at-commit is undefined,
not artificially false. C is not redefined to mean *authorized* causality, and P
is not redefined to mean *authorized and caused by this attempt* current state.

The PostgreSQL production report is not three independent truth bits. It checks
exact identity before reporting authority, and authority before reporting
`EXACT_COMMIT_RECORD`. Therefore an unauthorized actual cause can have semantic
`C=1` while the consumer declines to report supported causality. Native truth is
read from the actual row; the independent consumer is tested separately.

## Conditional-collapse matrix

Each row has exactly one of the requested seven classifications. A discharge is
useful, but is not derivation from the two coordinates alone.

| Proposed derivation | Exact additional assumptions | Classification | Assumption removal / witness |
|---|---|---|---|
| A from C+P, mutable destination | Exact cause and current state, but governed revocation is separate from technical SQL/API credentials | FALSIFIED BY COUNTEREXAMPLE | `011`: revoke, actual claimed commit by outside-boundary writer, restore current authority |
| A from C+P, atomic authority-bound destination | Every effect writer validates exact active epoch/generation inside the same commit; revocation participates in its serialization; no bypass writer | SUBSTRATE DISCHARGE | Native revoked/stale-epoch/stale-generation execution is rejected; open-boundary `011` restores the missing relation |
| A from C+P, ordinary CAS or lock ownership | Linearizable target update or one process owns a lock, without atomic governed-authority validation | FALSIFIED BY COUNTEREXAMPLE | Technical acceptance remains possible after governed revocation; separate Kubernetes Lease is not a target commit fence |
| A from an "authorized causal receipt" | C is renamed to include successful authority validation | SEMANTIC SMUGGLING | Expanded receipt contains A; removing its authority component restores `011` |
| A from hardware attestation alone | Trusted code/platform identity, without a specified current authority input and commit boundary | UNRESOLVED | Hardware is not exercised in this cycle; attestation alone supplies no derivation theorem. If hardware enforces the exact predicate, classify that stronger proposal as substrate discharge |
| C from A+P, atomic unique-effect destination | Exact active authority, destination key uniqueness, native transactions, one committed logical effect | FALSIFIED BY COUNTEREXAMPLE | `101`: another authorized attempt wins the same effect key |
| C from A+P, deterministic/idempotent/at-most-once operations | Equal payload/result, deterministic state machine, or no duplicate logical effect, with more than one possible attempt | FALSIFIED BY COUNTEREXAMPLE | The authorized other attempt produces the same result; cardinality is not origin |
| C from A+P, sole-attempt creation | Initially absent effect; only this exact attempt may create it; all other actors/pre-existing effects excluded; trusted destination enforcement and truthful metadata | SUBSTRATE DISCHARGE | SQL sole-attempt CHECK excludes the other authorized attempt; removing it restores `101`. A single writer that serves many attempts does not qualify |
| C from A+P plus a destination-native operation record | Durable exact operation/attempt identity, atomically bound to the actual effect | REPRESENTATION COLLAPSE ONLY | The record implements C. RIFL/DBOS coupling and #241 do not erase the causal relation |
| C from a "correct state" containing exact verified origin | P's definition includes exact-attempt origin | SEMANTIC SMUGGLING | Expanded P contains C |
| P from A+C, mutable target | Authentic authorized historical commit; later authorized or external target mutation remains possible | FALSIFIED BY COUNTEREXAMPLE | `110`: exact commit, later target drift; historical cause unchanged |
| P from A+C, immutable event existence | Effect IS a retained write-once event; exact event existence is the independently selected predicate; no deletion/expiry/compensation invalidates it; readable durable store | DERIVATION UNDER EXPLICIT PROFILE ASSUMPTIONS | C implies historical existence; retention implies current existence. Enabling deletion restores `110` |
| P from A+C, monotonic facts | Predicate is upward-closed under every allowed future transition, established by the effect, with no temporal expiry or external invalidation | DERIVATION UNDER EXPLICIT PROFILE ASSUMPTIONS | This is the same preservation argument as immutable existence; it does not cover arbitrary predicates on a monotonic store |
| P from A+C, immutable but expiring validity | Event bytes never change, but independently required validity expires | FALSIFIED BY COUNTEREXAMPLE | `110` after policy-time expiry, with unchanged event bytes |
| P from A+C, event-sourced current state | A complete, correctly ordered log through an independently current head, deterministic fold and fixed current predicate are supplied | SUBSTRATE DISCHARGE | The current suffix/head carries the missing current-state information; a historical commit prefix alone fails |
| P from a "still-current exact receipt" | C's meaning includes satisfaction of the current predicate | SEMANTIC SMUGGLING | Expanded C contains P |
| Any coordinate from fewer rows/tables/services | Relations retained in one native row/object | REPRESENTATION COLLAPSE ONLY | #240/#241 and the Kubernetes single-object profile preserve the semantic joins |

There is **no GENERAL DERIVATION** established by this cycle. The hardware row is
explicitly unresolved, rather than counted as an unrun successful or failed test.

## Assumption expansions and anti-smuggling

| Apparent collapse | Expanded dependency | Mechanism | Trust boundary |
|---|---|---|---|
| C ⇒ A in the closed SQL path | C ⇒ actual commit; every accepted commit satisfies exact continuing authority | `FOR SHARE` authority row held through effect transaction; epoch/generation checks; revocation serializes against it | PostgreSQL transactions and complete writer mediation, including administrators |
| A+P ⇒ C in sole-origin storage | Current effect ⇒ an initially absent effect was created; only exact q can create it | Native sole-attempt constraint and trustworthy provenance fields | Destination writer identity/permissions and initially empty state |
| C ⇒ P for immutable existence | Exact cause ⇒ event existed; retention ⇒ it still exists | Atomic no-replace publication; durable event retention; publish-only operations | Filesystem/store durability and a trusted interface excluding privileged deletion |
| A+C ⇒ P for event sourcing | Historical event + complete current suffix/head ⇒ current fold | Ordered retained log and current-head observation | Log completeness, current-head freshness and deterministic interpreter |
| A+C+P ⇒ supported certificate | Truth + exact identity/cardinality + independent question + admissible evidence | Existing portable evaluator, independently provisioned roots/claim type, truthful current observer | Relying party's provisioning and destination/history attestations |

Each assumption removal makes the missing obligation reappear. Atomic A
enforcement and sole-origin C enforcement are implementations of those relations.
Permanent-existence P is a legitimate profile projection: immutability is not
authority or causality disguised by vocabulary, but its current predicate is
narrower than mutable-state closure.

## Smallest separating witnesses and cube

PostgreSQL uses the #241 one-row path; there is no custody table and no separate
completion table. Native facts must show exactly one physical effect. The A=0
writer is explicitly privileged and outside the governed executor; it does not
show failure of the closed native fence. All candidate authorities at observation
are active again, so present authority cannot answer A-at-commit.

Minimal positive-retained pairs are `111 ↔ 011` for A, `111 ↔ 101` for C, and
`111 ↔ 110` for P. The new cube measures actual commit authority for both possible
attempts, tightening #242's admission-based retained projection without changing
or weakening its constitutional test.

| A C P | One native physical effect and current observation | Independently required PostgreSQL EXACT_EFFECT CLOSED claim | Retry | Historical trust |
|---|---|---|---|---|
| 000 | Unauthorized other attempt; later target drift | UNKNOWN; false CLOSED unsupported | No replay | UNTRUSTED_HISTORY without separate continuity proof |
| 001 | Unauthorized other attempt; required state currently holds | UNKNOWN; false CLOSED unsupported | No replay | Same independent history obligation |
| 010 | Unauthorized claimed attempt; later drift | UNKNOWN; false CLOSED unsupported | No replay | Same independent history obligation |
| 011 | Unauthorized claimed attempt; required state holds | UNKNOWN; false CLOSED unsupported | No replay | Same independent history obligation |
| 100 | Authorized other attempt; later drift | UNKNOWN; false CLOSED unsupported | No replay | Same independent history obligation |
| 101 | Authorized other attempt; required state holds | UNKNOWN; false CLOSED unsupported | No replay | Same independent history obligation |
| 110 | Authorized claimed attempt; later drift | UNKNOWN; exact historical cause can remain valid | No replay | Same independent history obligation |
| 111 | Authorized claimed attempt; required state holds | CLOSED supported under the fixed proof contract | No replay: already committed | CLOSED alone still does not establish TRUSTED_HISTORY |

All eight are possible in the declared **open-boundary mutable** class. Only
`100/101/110/111` occur among effects produced by the complete atomic authority
fence. Sole-attempt creation eliminates C=0 corners. Immutable permanent
existence eliminates P=0 corners. The composed fenced, sole-origin, immutable
profile has only `111` among committed effects. These are real constraints, not
missing cube witnesses to be fabricated.

## Claim requirements and closure

The unchanged portable policy accepts only EXACT_EFFECT and POSTCONDITION.
STATE_ONLY is a causality result, not a selectable claim type. HISTORICAL_COMMIT
is not a supported policy value; this cycle does not add it.

| Independent claim type | A required for CLOSED? | C required? | P required? | Other obligations |
|---|---|---|---|---|
| EXACT_EFFECT | Yes, for the exact admitted commit | Yes, actual claimed attempt/owner/transition | Yes, current required state supplied by a truthful current observer | Signed statements, independent roots/build/case/claim/policy bindings, exact effect/custody identity and one-effect cardinality; continuity/succession separately when claimed |
| POSTCONDITION | No positive commit-authority proof required | No; matching state may yield STATE_ONLY | Yes | Authentic independently selected state claim and no contradictory supplied evidence. A supplied invalid commit remains disqualifying; missing commit is allowed |
| STATE_ONLY | Not a claim type | Result label only | Not a selectable policy question | Do not infer an alternate claim contract from a producer label |
| HISTORICAL_COMMIT | Unsupported | Unsupported | Unsupported | A historical exact cause can remain supported while current closure is UNKNOWN; no new claim type is introduced |

`A AND C AND P` is necessary and sufficient for the cube's exact semantic
closure **only after fixing the surrounding proof contract**. It is not
sufficient for a portable certificate under arbitrary evidence/trust/policy.
The live evaluator rejects wrong independent claim strength, untrusted roots,
wrong build and duplicate-effect cardinality while the original event's A/C/P
truth is retained. These failures belong to existing policy, trust, identity
and replay obligations, not a new coordinate.

**Freshness limit:** the offline destination envelope is a signed snapshot,
not a live destination query. A retained authentic snapshot can still be
accepted after the real world drifts. The permanent regression pins this exact
limit and shows that a new truthful observation yields UNKNOWN while retaining
A/C. CLOSED means the required predicate in the attested current-view profile;
present truth requires a separately justified current observer. No signature,
build SHA, historical receipt or trusted history supplies perpetual freshness.
This cycle does not claim the offline verifier enforces wall-clock freshness.

## Cross-domain evidence and limits

| Domain | Experiment | Supported conclusion | Limit |
|---|---|---|---|
| PostgreSQL | Eight native one-row worlds, atomic revocation/epoch/generation rejection, lock serialization and sole-attempt CHECK control | Mutable open-boundary truth separates all coordinates; exact consumer rejects seven false CLOSED claims | Fixture trust roots and destination facts; A=0 worlds intentionally use the outside-boundary writer |
| Kubernetes | Eight native API-object worlds with retained actual commit version, current target observation, actual owner/attempt and co-located authority | Same truth separation; resourceVersion authority/CAS discharge is an existing closed-boundary mechanism | Truth oracle, not a newly supported portable verifier profile; privileged outside-boundary writes explicitly marked |
| GitHub/CI | Unchanged reconciler on common API snapshots; one actual native rerun reused for a never-dispatched observer's foreign local claim | Current run state is not exact origin. Legacy CLOSED cannot be upgraded to EXACT_EFFECT; new test sends no additional provider mutation | Revoked-authority pair and later-attempt drift use API-snapshot fixtures, not native provider executions. No native authority-at-provider-commit proof; no eight-corner native cube claimed |
| Publish-only object/event store | Native POSIX temporary-write + fsync + atomic no-replace link + directory fsync; re-open/dedup; explicit deletion negative; fixed expiry predicate | Exact cause discharges permanent existence under retention; key uniqueness does not transfer actual origin; expiry restores P independence | Trusted publish-only interface and filesystem, not hardware WORM. Publisher object disposal/lost caller result is not an OS-process crash experiment |

No domain semantics were added to the production kernel. Differences in
realization are allowed; every domain is not forced into PostgreSQL's certificate.
Kubernetes's C truth is known from the supervised actual invocation, cross-checked
against its native commit version. Retained custody by itself is not a causal
certificate, and the experiment does not reinterpret #239 to make it one.

## Prior-art challenge

The mappings below are architectural inferences from primary sources, not
claims that these authors use Aegis's labels or proved this cycle's lower bound.

| Primary source | Closest replacement / credit | What it does not derive |
|---|---|---|
| [Park/Sandhu, UCONABC (2004)](https://profsandhu.com/journals/tissec/p128-park.pdf), ongoing-authorizations section | Ongoing authorization, revocation, mutable attributes and independent obligations/conditions predate Aegis. UCON can express relevant predicates in a wider policy framework | UCON's ABC letters mean different things. No exact-attempt causality/current mutable-state equivalence theorem found in the examined source |
| [Lee et al., RIFL (SOSP 2015)](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf), completion durability and retry rendezvous | Durable unique operation identity, atomic completion/effect coupling, retention and reconfiguration provide #240/#241's closest known mechanism | A returned historical result does not certify current authority or later mutable state |
| [DBOS transactions/datasources](https://docs.dbos.dev/python/tutorials/transaction-tutorial), execution guarantees; [outbox](https://docs.dbos.dev/python/examples/outbox) | Atomic outcome checkpoint and business transaction discharge causal/replay obligations without a separate orchestrator transaction. Outbox coupling commits publication intent before delivery | External endpoint semantics and later target truth remain separate; outbox insertion is not proof of delivery |
| [Temporal activity definition](https://docs.temporal.io/activity-definition), idempotency/retry sections | Durable workflow history; destination idempotency keys address repeated external calls after lost completion | Activity completion history is not current external-state truth or actual-attempt origin for a deduplicated winner |
| [Burrows, Chubby (OSDI 2006)](https://www.usenix.org/legacy/event/osdi06/tech/full_papers/burrows/burrows_html/), locks/sequencers | Recipient-side generation/sequencer validation is the relevant stale-writer authority mechanism. Merely owning a lock is insufficient | The application must enforce the governing scope at the destination; accepted state says nothing about which attempt caused it |
| [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) and [PROV constraints](https://www.w3.org/TR/prov-constraints/), events/lifetimes | Generation, activity/agent association, attribution, delegation, revision and invalidation already separate causal responsibility from temporal existence/validity | Provenance consistency is not governed authorization enforcement or a live destination observation |
| [Ongaro/Ousterhout, Raft](https://raft.github.io/raft.pdf), client interaction | Deterministic replicated state plus unique client serial numbers and retained responses already distinguish application, deduplication and current reads | Consensus orders application events; it does not automatically supply the application's authorization predicate or freeze later state |
| [Fowler, Event Sourcing](https://martinfowler.com/eaaDev/EventSourcing.html), current state/replay/external updates | State derived from a complete event history is a legitimate representation reduction; external update replay requires separate control | A single old event is not the complete current fold or proof of an external effect |
| [RFC 9162, Certificate Transparency](https://www.rfc-editor.org/rfc/rfc9162.html), introduction and security considerations | Append-only inclusion/consistency and externally observed log heads are known history mechanisms; logging does not prevent misissuance | Historical inclusion does not prove authorization or an unexpired/current business predicate |

Prior art already contains the constituent obligations and their important
couplings. No novelty claim is justified by renaming them. No examined source
provides a broad theorem deriving one fixed A/C/P truth coordinate from the
other two without additional scope assumptions. This targeted search is not
proof that no equivalent basis exists elsewhere.

## Bounded formal result and executable mapping

`experiments/acpbasis/model.py` is an explicit finite transition system, not a
truth-table generator that assigns A/C/P independently. Its state contains
active authority, generation, actual historical committer/authority snapshot,
event presence, mutable target and expiry. Transitions revoke/restore, advance
generation, commit by one of two possible attempts, mutate/restore the target,
expire validity and, in the negative profile only, erase an event.

BFS explores to a fixed point. For each coordinate it enumerates all **16**
total Boolean functions of the other two bits and rejects every candidate
inconsistent with the reachable worlds. Seven explicit profiles contain 256
reachable states in total:

| Profile | States | Committed truth corners | Functional result |
|---|---:|---|---|
| Mutable open boundary | 56 | All eight | No A=f(C,P), C=f(A,P), or P=f(A,C) |
| Mutable atomic authority fence | 24 | 100,101,110,111 | A=1 invariant; C/P remain non-derivable |
| Mutable sole origin | 32 | 010,011,110,111 | C=1 invariant; A/P remain non-derivable |
| Immutable permanent existence | 28 | 001,011,101,111 | P=1 invariant on committed effects; A/C remain non-derivable |
| Immutable fenced sole origin | 8 | 111 | All obligations discharged in this restricted profile |
| Immutable event with erasure allowed | 52 | All eight | P non-derivability returns |
| Immutable event with expiring predicate | 56 | All eight | P non-derivability returns |

The separating traces map to PostgreSQL and Kubernetes's native commit/authority/
drift worlds; retention/erasure/expiry map to the native object-store controls.
The generation transition maps to the PostgreSQL stale-generation fence test.
The model does not prove fairness, unbounded concurrency, fault-tolerant storage,
cryptographic correctness, arbitrary domains or universal primitive minimality.

## Preservation, implementation and reproducibility

Production changes: **none**. The new Go predicates/helpers are test-only.
Python's formal checker and fourth-domain store are experiment-only. The
registration and workflows require native cases rather than treating skips or
compilation errors as evidence. Every pre-existing byte in governedaction,
evidenceverify, the PostgreSQL experiment and shrink registrations is preserved
by `scripts/run_acp_basis.py` (68 baseline files). Existing assurance runners
retain their compiled-source removal witnesses and restore source exactly.

| Kernel measure | Before | After |
|---|---|---|
| governedaction complete source tree | `6c6b1e754a369cf8d30f627af1ead8b9b3835f14` | Identical |
| Production Go files / lines / bytes | 8 / 1,550 / 51,499 | Identical |
| Three runtime production files: lines / bytes | 955 / 30,047 | Identical |
| Canonical production SHA-256 (runner's path/length/bytes encoding) | `521371fb3ec22c7ab3054ba664ec0e5e7f570e8847113b1ad867b46e85a67ea1` | Identical |
| Production verifier sources | Baseline exact bytes | Identical; additive tests only |
| New production primitive / fourth axis / claim type | 0 | 0 |

| Anchor | Preserved obligation |
|---|---|
| #235 | Native lost-ACK effect finality + authority succession + Genesis/history custodian succession + independent verification |
| #236 | Independently selected required claim strength; state cannot downgrade EXACT_EFFECT; trusted history cannot upgrade it |
| #239 | Matching custody/state does not establish exact cause; historical commit does not establish current closure |
| #240 | Custody-table-free path, retained atomic completion and composed native succession |
| #241 | One physical effect row as causal record; compiled replay-exclusion removal still yields two physical effects |
| #242 | Original three bounded separating pairs and immutable registration bytes |

Required evidence gates for the reviewed change are the existing complete
composite/native corpus and compiled-erasure trials, plus:

- `TestPostgresCompositeACPSeparatingCube`: eight actual native rows/current views,
  seven false CLOSED rejections, one positive independently verified CLOSED.
- `TestPostgresCompositeACPAtomicAuthorityDischarge`: three stale/revoked negative
  cases and a native lock-timeout SQLSTATE control during the actual commit.
- `TestPostgresCompositeACPOriginRestriction`: unique-key other-attempt witness
  and native sole-attempt constraint control.
- `TestKindACPConditionalCollapse`: eight native API-object worlds; no skipped
  corner; unchanged co-located/split-Lease baseline corpus.
- `TestACPGitHubNativeForeignClaim`: one native provider effect, read-only foreign
  observer claim, unchanged real reconciliation executable; no extra rerun.
- Portable evidence/claim/freshness tests with race detection; finite/native
  object-store tests; immutable-source and fingerprint checks.

Commands: `python3 -B scripts/run_acp_basis.py --out <evidence-dir>`;
`go test -race ./evidenceverify ./cmd/github-rerun-proof`; the named PostgreSQL
tests require the existing composite assurance environment. Kubernetes needs
the existing isolated KinD profile. The native GitHub test requires its exact
cross-domain workflow snapshots and fails when the required native profile is
enabled but missing. Raw native results are emitted as workflow artifacts.

## Strongest claim and claims withheld

**Supported:** within the declared mutable committed-effect class and tested
effect profiles, A, C and P are a bounded functionally non-derivable semantic
basis for the independently required EXACT_EFFECT judgment, with trust,
identity/cardinality, current-view and claim-policy obligations fixed. Native
closed boundaries and independently narrowed predicates may legitimately
discharge coordinates with fewer physical representations.

**Withheld:** the universal minimum for all governed systems; a universal
three-primitive kernel; irreducibility under every realistic substrate; novelty
of the triad or its constituent mechanisms; full native eight-corner GitHub
separation; hardware-enforced fourth-domain immutability; wall-clock freshness
enforced by the offline verifier; A/C/P alone being sufficient for historical
trust, safe retry, custody succession or portable proof under arbitrary policy.

No fourth axis passed the requested admission test. Counterexamples involving
untrusted/mismatched evidence, duplicate identity, stale observation and history
were expressible with existing trust, claim-policy, replay, freshness and
continuity distinctions. The intellectual reduction is profile-specific
discharge, not deletion of one generally needed coordinate.
