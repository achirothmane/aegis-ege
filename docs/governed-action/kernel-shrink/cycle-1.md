# Kernel shrink cycle 1: delete duplicate checks, retain necessary joins

Baseline: `4cb43bb779bf902734f7c675545a2b5a4807a184`, including constitutional
anchors [#235](https://github.com/achirothmane/aegis-ege/pull/235) and
[#236](https://github.com/achirothmane/aegis-ege/pull/236).

**Result:** the executable reference runtime is 32 source lines and 610 bytes
smaller. It has the same public declarations, imports, primitive data types,
custody transitions, binding bytes and observation checks. No essential check
moved into an adapter, policy producer or external helper.

Nine candidate concept families were examined. In the bounded native profile,
three can be derived, one can share a record, and two belong outside the core.
Three obligations must remain: exact trusted admission, retained effect custody,
and evidence sufficient for the independently required closure. Most of these
placements already existed; they are not six newly deleted primitives.
The concrete new deletion is duplicated executable logic. Ten unsafe binding or
retention removals produce permanent regression witnesses.

This does **not** establish a global nine-to-three primitive theorem. The frozen
v1 contract and its broader action/plan semantics remain unchanged.

## A. Before

There are three different inventories; combining their counts would be misleading:

| Inventory | Before | After |
|---|---:|---:|
| Requested semantic candidate families reviewed | 9 | 9 classified |
| Reference-runtime primitive data types | 4 | 4 |
| Frozen v1 semantic concepts / record families | 6 / 5 | 6 / 5 |
| Three runtime production files: source lines | 987 | 955 |
| Three runtime production files: source bytes | 30,657 | 30,047 |
| Whole `governedaction` module: production Go files | 9 | 9 |
| Whole module: production source lines | 1,752 | 1,720 |
| Whole module: production source bytes | 56,334 | 55,724 |
| Runtime functions / private functions | 26 / 7 | 28 / 9 |
| Copies of request-projection validation/encoding | 2 | 1 |
| Copies of observation verification | 3 | 1 |

Source-line counts include comments and blanks. Two small private functions
increase function count while deleting duplicate predicates. Public APIs,
production imports and the six execution/recovery entry points are unchanged.

The four data types are Identity, State, Attestation and Transition. The six
frozen concepts are ActionIdentity, ActionRevision, DecisionBasis, EffectIdentity,
ExecutionAttempt and ClosureObligation; ActionRef combines the first two.
Neither count proves semantic irreducibility.

The trusted implementation includes the `governedaction` boundary/runtime code,
the independent `evidenceverify` evaluator, domain destination enforcement,
and the declared continuity/Genesis trust profile. Signers, quorum storage,
destination transactions and checkpoint provisioning do not disappear from the
TCB merely because they are outside the core module. Their production code and
dependencies did not change in this cycle.

Mandatory guarantees remain:

- #235: one external effect after lost acknowledgement, controller crashes and
  fresh-process reconstruction; no stale authority resurrection; identical
  governing history; an authorized successor custodian; CLOSED with exact
  evidence and UNKNOWN without it.
- #236: independently provisioned claim strength; state evidence cannot satisfy
  EXACT_EFFECT; valid signatures and trusted history cannot upgrade effect truth.

## B. After: elimination decisions

The strongest implemented alternative is exercised by
`experiments/kernelshrink/runtime_test.go`. Its input has subject, transition and
admission, with owner/attempt retained in one custody tuple. Current state input
is derived from Transition.From; fresh state still comes from the adapter.
It invokes the actual runtime, not a replacement acceptance oracle.

| Candidate family | Classification in the bounded profile | Alternative and retained distinction |
|---|---|---|
| Authority | DERIVE | A trusted admission dependency plus destination authority-at-commit enforcement. No separate authority object. Never infer current authority from historical custody. |
| EffectIdentity | DERIVE | Exact admitted subject/state/transition projection, independent of issuer, executor and attempt. Stable operation identity/cardinality still has to exist. The function remains for compatibility. |
| ExecutionAttempt | MERGE | One retained effect/attempt/owner/generation custody relation. Eliminate a separate attempt object, retain the attempt distinction. |
| Custody | KEEP AS CORE obligation | Preserve possible-effect ownership before escape and through uncertainty. Native storage owns atomicity, durability, fencing and deduplication. |
| ClosureObligation | KEEP AS CORE obligation | A claim must have sufficient exact evidence. Claim profiles and their required standard belong to trusted verification policy, not a new kernel type. |
| ActionRef | DERIVE, bounded scope | The complete admitted transition is sufficient for the single-effect profile. This does not delete ActionRef from the general frozen contract: intentional same-payload actions and multiple effect slots still need their declared identity/cardinality semantics. |
| DecisionBasis | KEEP AS CORE relation | Independently trusted expectations and an exact admission binding. A compact attestation can carry its result; an untrusted producer cannot adjudicate its own standard. |
| Historical continuity bindings | DEMOTE TO SUBSTRATE + VERIFIER | Authenticated continuity and independently retained checkpoints; preserve exact outcome/history and successor-custodian joins. No history primitive in the runtime. |
| Claim strength / required_claim_type | DEMOTE TO VERIFIER/POLICY | A verification-contract property of ClosureObligation. Keep it mandatory in independent policy; keep it absent from core types. |

KEEP denotes a necessary obligation or relation, not a proved irreducible Go
object. The three retained obligations can be implemented using known
mechanisms. The experiment does not prove they each require a distinct primitive.

Other concepts in the current inventory:

| Concept | Disposition |
|---|---|
| Identity, State, Attestation, Transition | KEEP opaque information and binding roles. Four carrier types remain; this cycle does not reassert their global irreducibility. |
| ActionIdentity / ActionRevision | DERIVE the composite ActionRef where the trusted profile supplies exact identity/revision; preserve generic v1 distinctions. |
| StateBinding / AuthorityContext | MERGE as DecisionBasis dependencies, with destination-native revalidation. |
| Acceptance / Observation / effect receipt | DERIVE typed artifacts. Provider return, matching state and exact causal commit remain distinct. |
| UNKNOWN / REJECTED / CLOSED | DERIVE epistemic dispositions. UNKNOWN carries no retry authorization. |
| Fencing generation / custody phase / checkpoint CAS | DEMOTE mechanism to native substrate. Retain monotonicity and exact joins; four custody phases are not four primitives. |
| Root keys / quorum / Genesis / TPM | DEMOTE to declared trust/continuity substrate. They remain explicit TCB assumptions, not newly eliminated code. |
| Capability / Constraint / undifferentiated Evidence from older candidate bases | DELETE / SUPERSEDED as current primitive candidates; historical elimination experiments remain proof harness. They were already absent from the executable four-type runtime. |
| Origin, approval use, credential use, taint / propagation | KEEP existing implementation pending separate elimination trials. They are trusted profile relations; their location in the library alone proves neither core necessity nor safe demotion. No deletion is claimed here. |
| Effect Finality / Authority Succession / Historical Succession / Independent Verification | DERIVE composition guarantees. Do not introduce primitive objects for guarantee names. |

## C. Necessity: preserve joins without inflating object counts

`scripts/run_kernel_shrink.py` temporarily removes one relation's enforcement from real source,
retains every other current mechanism, runs the named regression and restores
exact bytes. Ten removals are falsified. These are local necessity witnesses;
they are not an exhaustive search over all implementations without a concept.
The derived/merged alternatives above must be considered alongside them.

| Required relation | Smallest retained witness | What survives without a separate object? |
|---|---|---|
| Exact independently trusted admission | A validly signed admission selects another policy; every other request and commit field remains exact. Acceptance becomes falsely supported when the independent policy join is removed. | DecisionBasis can be attested and policy-owned. Its independent binding cannot disappear. |
| Authority at actual commitment | One signed commit has `AuthorityActive=false`. Without that check it closes. Native #235 additionally switches authority generations and rejects stale admission. | Authority remains a dependency, not a new core object. |
| Effect-bound evidence | One signed commit names another effect. Trusted history still verifies; exact closure does not. | Effect identity can be derived. Equivalent exact admission/transition joins may supply identity, so the witness does not prove a distinct EffectIdentity primitive. |
| Attempt-bound custody | One signed commit names another attempt. Removing the attempt join falsely closes it. Foreign-attempt recovery is also denied. | Attempt and custody share a tuple; their distinctions cannot be erased. |
| Owner / monotonic custody generation | Change one owner or generation in a signed commit. Other fields and signatures remain valid; closure must remain UNKNOWN. | Native fencing supplies the mechanism. History-custodian authority cannot substitute for effect-owner authority. |
| Retention through uncertain commitment | An effect occurs, acknowledgement and exact observation are lost, then an adapter is reconstructed. Removing retention permits a second effect. | A native atomic operation record can supply custody; the surviving relation need not be a separate object. |
| Independently required closure | Signed POSTCONDITION evidence plus matching state and trusted history under EXACT_EFFECT. Producer-selected standard incorrectly produces CLOSED. | `required_claim_type` is an independently provisioned verification-contract field. No core promotion is needed. |
| Exact historical outcome binding | Re-sign the producer bundle for another intent while retaining its predecessor history. Effect truth stays CLOSED; historical trust must fail. | Substrate/verifier continuity is sufficient. Historical trust and closure cannot be one truth bit. |

A tenth trial collapses effect/admission digest domains. Sharing their projection
is safe; using effect identity as an admission statement is not. Domain separation
is an existing binding requirement, not a newly discovered primitive.

## Prior-art subtraction

The following classification is an inference from primary-source mechanisms and
the executable corpus, not a theorem that no other literature contains this
composition.

| Primary source | What it already explains | Remaining boundary |
|---|---|---|
| [Park/Sandhu, UCON, 2004](https://profsandhu.com/journals/tissec/p128-park.pdf) | Mutable attributes, ongoing authorization and obligations. Subtract continuing authorization as a novel primitive. | Monitoring semantics do not supply every destination's atomic commit guard. |
| [Lee et al., RIFL, SOSP 2015](https://web.stanford.edu/~ouster/cgi-bin/papers/rifl.pdf) | Stable RPC identity, retries, durable completion records atomically coupled to effects, migration and retention. Subtract operation identity and recovery mechanisms. | Scope and retention assumptions matter; an unobserved outcome cannot be relabelled known failure. |
| [DBOS steps](https://docs.dbos.dev/golang/tutorials/step-tutorial) and [datasources](https://docs.dbos.dev/golang/reference/datasources) | Durable workflow recovery and replay; atomic application/durability transactions for database effects. | External steps can execute again after a crash before checkpointing. General external exactly-once behavior is not implied. |
| [TUF specification 1.0.36](https://theupdateframework.github.io/specification/v1.0.36/) | Independently trusted initial roots, sequential root versions and old/new threshold authorization of succession. | Signed-metadata succession alone does not fence effect execution or retire every history writer. |
| [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162.html) | Authenticated log heads, inclusion and append-only consistency proofs. Subtract authenticated continuity mechanisms. | Logs can retain false claims and inconsistent views; they do not manufacture effect causality. |
| [Burrows, Chubby, OSDI 2006](https://research.google/pubs/the-chubby-lock-service-for-loosely-coupled-distributed-systems/) | Recipient-checked sequencers/generations and stale-holder exclusion. Subtract fencing as a novel mechanism. | A separate lease check does not atomically constrain an unrelated destination object. |
| [Appel/Felten, Proof-Carrying Authentication, 1999](https://www.cs.princeton.edu/~appel/papers/says.pdf) | A client supplies proof against the relying party's policy assumptions. Subtract producer-independent acceptance standards as a novel primitive. | An authorization proof is not automatically an effect receipt. |
| [W3C PROV-DM](https://www.w3.org/TR/prov-dm/) | Entities, activities, revisions and explicit generation/usage/derivation relationships. Subtract causal-provenance vocabulary. | A provenance assertion needs trustworthy evidence; observed equality alone does not establish this attempt's cause. |

Transactional uncertainty, deduplication and at-most-once behavior are already
explained by the atomic-operation/completion and fencing mechanisms above.
Another broad search round is unlikely to change this cycle's kernel decision
or novelty category, so research stops here.

## D. Preservation and migration

Local executable evidence is retained in
`testdata/governed-action/kernel-shrink/unit-result-v1.json`:

- 176 identical old/new traces: 140 exact-byte/malformed-binding cases and 36
  Run/RunFenced/Recover observation cases, including adapter call order and errors.
- Both pinned and reduced runtime suites pass with the race detector.
- The independent verifier passes; all ten altered implementations fail their
  intended regression assertions.
- Primitive-reduction, frozen normative, temporal-standing and new shrink suites
  pass locally with the race detector.

The in-memory experiment does not claim native crashes, independent deployment
or physical failure-domain separation. Native preservation is a separate,
mandatory exact-head CI gate. Its artifacts, not the unit JSON, establish:

| Gate | Required permanent cases |
|---|---|
| #235 composite PostgreSQL | `TestPostgresCompositeGenesisHistoryCustodianLostAcknowledgement/CLOSED` and `/UNKNOWN`: lost acknowledgement, controller crashes, fresh process, one effect, exact history and successor custody. |
| Authority / exact causality | `TestPostgresCompositeAuthorityGenerationSwitchDoesNotReviveOldAdmission`, matching-state/foreign-effect causality regression, and lost-acknowledgement authority-change recovery. |
| #236 verifier | `TestIndependentPolicyRejectsBundleClaimDowngrade`, explicit claim profiles, missing/unknown requirement rejection, truthful UNKNOWN, history/effect separation. |
| Destination interval | PostgreSQL post-revalidation state/authority changes, stale owner and replay; Kubernetes post-read races, stale owner/replay and separate-Lease counterexample. |
| Broader frozen assurance | Unchanged normative/K07 corpus, three-domain gate, Terraform process-loss/recovery and KinD integration. |

CI explicitly requires the native #235 CLOSED and UNKNOWN cases without skips
and evaluates fresh bundles with the expected source build from independent
policy. Merge requires these exact-head checks to pass.

All current policy fixture constructors explicitly provide `required_claim_type`
through the independent policy channel. No compatibility fallback was added.
`TestKernelShrinkPolicyMigrationCannotChooseClaimFromBundle` also removes the
field from otherwise valid legacy JSON for **both** producer claim types; both
remain INVALID/UNKNOWN. No weaker or stronger silent default exists.

Hidden self-selection audit: roots/roles, build/case, admission policy hash,
destination profile, history ID/checkpoint and succession expectations already
come from independent policy and have negative regressions. Component grades
are checked against the declared succession profile; maximum grade is a ceiling,
not an undisclosed minimum. Producer closure/causality/history labels are checked
against derived judgments. UNKNOWN grants no retry semantics. No new unprotected
relying-party expectation was demonstrated, so no additional policy fields were
invented.

### Destination and assurance honesty

PostgreSQL's positive profile couples authority generation, custody/fence,
effect record and state advance in its native transaction. Kubernetes's positive
profile co-locates guard and effect state under resourceVersion CAS. The separate
Lease/target-object profile remains insufficient. Runtime prechecks alone do
not claim Continuing Authority through destination commitment.

The original v1 freeze, historical cross-domain/Terraform/fence registrations,
normative vectors and oracle are byte-identical. A **new** shrink registration
pins the three changed implementation blobs. The new source gate first runs the
original checker against its exact historical baseline, then accepts only the
registered smaller implementation. It rejects unrelated deltas, imports/public
surface changes, repins of historical profiles and growth disguised as shrinkage.
Current native tests reprove the changed implementation; old native results
retain their original source scope. Proof results expose physical source changes
rather than claiming zero frozen-source byte delta.

Runtime TCB source shrinks; no runtime/verifier/adapter dependency or privilege
is added. Assurance implementation grows: 121 source-gate lines, 114 replay/
mutation-harness lines, 83 checker-test lines and 400 Go experiment/regression
lines, plus CI wiring. These are visible proof costs, not relocated admission,
effect or closure logic. This cycle does not claim that the entire assurance
pipeline or every possible definition of TCB became smaller.

Open #143 and #181 remain separate work. R01's split-brain fulfillment and R02's
independent provider failure domains are not superseded by this same-owner,
bounded native profile. Neither is merged or closed as a side effect.

## E. Novelty status and stopping decision

**2. Useful composition of known mechanisms.**

The current evidence supports carefully joined independent admission,
destination enforcement, durable custody, sufficient effect evidence and
authenticated succession. It does not establish a distinct irreducible Aegis
primitive beyond prior art. A failed unsafe deletion proves that a guarantee
needs a binding somewhere; it does not prove a new core object is necessary.

The "governed effect through time" candidate can therefore use a derived exact
action/effect projection, trusted admission, one effect-custody relation and
independent closure verification. It must retain authorization/effect,
effect/observation, observation/causality, closure/history,
history custody/current effect authority, UNKNOWN/failure and uncertain
commit/safe retry distinctions. The paired regressions preserve these boundaries.

No formal model or primitive expansion is introduced. The frozen general
contract is not rewritten around a single-effect experiment. Further deletion
must eliminate a real relation or redundant trusted implementation without
merely renaming it, hiding it in a helper, or enlarging hidden trust. Until that
evidence exists, kernel expansion and claims of new irreducible semantics pause.
