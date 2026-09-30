# K01 + K02 + K03 domain-profile mapping — candidate Kernel v1

Status: **DRAFT / UNFROZEN**  
Normative owner: Aegis integration-contract steward  
Companion contract: [kernel-v1.md](kernel-v1.md)

This mapping applies the K01 ActionRef / DecisionBasis rules, K02 EffectIdentity / ExecutionAttempt / recoverable-custody rules, and K03 temporal / next-effect resumption rules to the three design-visible seeds already selected by the queue:

- CI rerun / Workflow Failure Lab;
- Kubernetes node mutation / Aegis;
- the existing EEP synthetic CRM fixture.

It does not add a new runtime profile service. Existing domain contracts remain authoritative for their payload semantics.

## 1. Reviewed source set

| Owner | Reviewed revision / identity | K01 use |
|---|---|---|
| Aegis-EGE | `8ba7ff710c3f75fe662ffd90f3569ecc81e98227` | K03 base after merged K02 |
| EASL | `7c4e1e28218853919d00362dc071e1eb6f61cc56` | current subject-state semantics |
| EASL StateBinding vectors | blob `82d151531da6f98262de1e247658d89a8299c53c` | earned conformance identity |
| Workflow Failure Lab | `d44bd4c47f8748bfca706a4c4833adf8ce940cf6` | C05-repaired CI/EBA consumer |
| WFL vendored StateBinding vectors | blob `82d151531da6f98262de1e247658d89a8299c53c` | byte-identical EASL mirror |
| Agent Action Guard | `5276336cec396a0ac0b77d45eb5b981b01d7d7ea` | AuthorityGrant semantics |
| assumption-gate | `435bc970c10dda83b786677ce9cc98ab9eac3799` | AssumptionState semantics |

Important versioned contracts already owned by those repositories include:

- `eba.integration/v0.1`
- `eba.temporal/v1`
- `eba.context/v1`
- `eba.canonical-json/v1`
- EASL `subject_state_binding` conformance v1
- `aegis.ege/evidence-composition/v1`
- `aegis.ege/permit/v0alpha1`
- `aegis.eep/crm-http-json/v1`
- `aegis.eep/crm-postcondition/v1`
- `aegis.eep/crm-outcome/v0alpha2`

## 2. CI rerun seed

### Trusted profile selection

The trusted selector is the **owner-controlled CI verifier/execution package**, not the remote analyzer or the ActionRequest.

The selected profile is the current CI use of:

- `eba.integration/v0.1`;
- `eba.temporal/v1`;
- `eba.context/v1`;
- `eba.canonical-json/v1`;
- EASL subject-state binding conformance v1;
- the domain evidence policy `ci-retry-gate.evidence-decision.v1`;
- Agent Action Guard AuthorityGrant semantics.

The caller cannot remove those mandatory dependencies by supplying a smaller basis.

### ActionRef

**ActionIdentity**

The logical rerun proposal lineage for one owner-controlled CI action request.

**ActionRevision material semantics**

The revision must bind at least the current CI context already declared by the profile:

- principal;
- operation;
- repository namespace;
- workflow run id;
- run attempt;
- head SHA;
- workflow id;
- exact resource scope / failed-job execution where the selected operation is job-scoped;
- side-effect meaning;
- current owner-controlled verifier/profile versions.

A changed run attempt, head SHA, repository/account scope, operation, or exact job execution is not the same admitted revision.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Evidence decision | domain policy says the rerun candidate is eligible | WFL CI evidence gate |
| StateBinding | current run/head/attempt state still matches evaluated state | WFL EASL compatibility layer using the pinned EASL vectors |
| AssumptionState | required rerun-safety assumption is VALID and correctly bound | WFL EBA verifier; assumption shape owned by assumption-gate |
| AuthorityGrant | principal/action/resource/side-effect scope is allowed | WFL EBA verifier; grant semantics owned by Agent Action Guard |
| Context profile | exact trace, audience and GitHub repository namespace match | `eba.context/v1` validator |
| Temporal profile | required artifacts are valid at the explicit evaluation instant | `eba.temporal/v1` validator |
| Canonical profile | authorizing artifact bytes are in the supported deterministic domain | `eba.canonical-json/v1` validator |
| Action digest / request_ref | Decision applies to this exact ActionRequest revision | WFL execution-boundary verifier |

### AuthorityContext

The CI seed binds:

- principal `ci-retry-gate` or the currently configured exact principal;
- GitHub Actions rerun operation;
- exact repository namespace;
- exact workflow-run/job resource scope;
- side effect = true;
- owner-controlled execution environment.

The namespace is not authenticated by a client string; it is constructed in the trusted local profile.

### Hard preconditions versus observations

Current run/head/attempt reads are **state observations and StateBindings**.

They are not renamed as a universal atomic destination guard.

Any provider-enforced current-state requirement for the actual rerun operation remains a domain/native enforcement question and is tested in D01. K01 does not claim exactly-once rerun or a new GitHub fencing primitive.

### Adapter/effect/outcome semantics

- effect implementation: owner-controlled native GitHub rerun operation;
- current dispatch receipt semantics come from `eba.integration/v0.1`;
- `SUCCEEDED` means the rerun API dispatch was accepted, not that the new workflow later passed;
- later workflow outcome remains separate observation evidence.

K04 will define the candidate-kernel closure relation. K01 does not upgrade a dispatch receipt into closure.

### Admission invalidation

Admission must fail or be re-established when, where material:

- head SHA changes;
- run attempt changes;
- repository/account namespace changes;
- operation/resource scope changes;
- AuthorityGrant is revoked/expired/out-of-scope;
- AssumptionState is stale/contradicted/unknown;
- mandatory profile or validator version becomes unknown;
- the owner-controlled verifier semantics change materially.

## 3. Kubernetes node-mutation seed

### Trusted profile selection

The trusted selector is **Aegis server/deployment configuration at the governed EGE boundary**.

For the current node-drain seed, configured stronger obligations force mutation through:

```text
POST /v1/ege/execute
```

The legacy execute route cannot be selected to bypass configured EBA/capability obligations.

Relevant current contracts include:

- `eba.integration/v0.1`;
- `eba.context/v1`;
- `eba.temporal/v1`;
- `eba.canonical-json/v1`;
- `aegis.ege/evidence-composition/v1`;
- `aegis.ege/permit/v0alpha1`;
- the installed consequence/capability policy versions;
- EASL subject-state semantics where consumed.

### ActionRef

**ActionIdentity**

The logical governed node-mutation intent.

**ActionRevision material semantics**

The revision must bind, where applicable:

- intent/action identity;
- action kind;
- Kubernetes node target;
- cluster/account/deployment namespace identity;
- resourceVersion;
- deterministic execution-plan digest;
- evidence-manifest digest;
- relevant EBA artifact references;
- principal/audience/namespace context;
- installed mutation adapter semantics;
- configured consequence policy/version/hash;
- capability-fence semantics when required;
- required evidence-composition profile/version.

Changing the node, cluster/account context, resourceVersion, plan digest, adapter meaning, policy meaning, or mandatory evidence profile yields a different material revision/basis.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Signed EGE Permit | exact action/evidence/plan/context bindings were signed by the configured permit authority | Aegis EGE execution boundary |
| EBA conformance bundle when configured | evidence, assumptions, authority and approvals satisfy the selected profile | Aegis EBA validator |
| StateBinding / live state | current node/plan-relevant state still matches admission | Aegis/EASL + Kubernetes adapter |
| Evidence composition | required named-source / independence predicate is satisfied at its declared assurance | Aegis evidence composer |
| Consequence admission | consequence class/policy permits this exact action scope | Aegis consequence validator |
| Capability fence when configured | the mutation remains within current capability scope | Aegis capability-fence owner |
| Adapter/profile version | the installed mutation meaning matches the admitted meaning | Aegis server/adapter owner |
| Approval references when required | approval applies to the exact revision/context | Aegis EBA validator |

### AuthorityContext

Where the profile requires them, the basis binds:

- execution principal;
- exact action;
- target/resource;
- authenticated deployment namespace or explicit singleton context;
- approval authority;
- credential/audience semantics;
- capability scope.

A self-hashed EBA artifact is not external issuer authentication. The Kubernetes/Aegis profile uses authenticated parent binding through the signed Permit for the covered external artifacts.

### Hard destination preconditions

The current Kubernetes execution path may use destination-enforced or API-server-enforced predicates such as:

- Node resourceVersion;
- Pod UID / identity preconditions;
- other server-side mutation preconditions declared by the adapter.

The Kubernetes Lease coordinates cooperating Aegis executors; it is **not** represented as fencing a non-cooperating destination writer.

### Bounded-age observations

Examples include:

- node health observation;
- PDB/preflight state;
- evidence observations with freshness bounds;
- previously read resource state before the final mutation-time check.

A prior read cannot replace a required server-enforced precondition.

### Adapter/effect/outcome semantics

The bound adapter meaning is the installed Aegis Kubernetes mutation implementation and deterministic plan semantics.

Current postflight/domain observations remain owned by the Kubernetes adapter and existing decision contract. K04 will define the candidate-kernel ClosureObligation relation; K01 makes no universal closure claim.

### Admission invalidation

Admission must fail or be re-established when, where material:

- action or target changes;
- resourceVersion changes;
- plan digest changes;
- evidence/assumption/authority/approval binding changes;
- required evidence independence becomes unknown/dependent;
- principal/audience/namespace changes;
- configured consequence/capability policy changes materially;
- adapter semantics change;
- a mandatory use-time validator becomes unavailable.

## 4. EEP synthetic CRM seed

### Trusted profile selection

The trusted selector is **the configured Aegis EEP executor profile**, not the incoming plan.

Current versioned profiles:

- execution: `aegis.eep/crm-http-json/v1`;
- intended postcondition: `aegis.eep/crm-postcondition/v1`;
- outcome artifact: `aegis.eep/crm-outcome/v0alpha2`;
- execution Permit: `aegis.ege/permit/v0alpha1`.

### ActionRef

**ActionIdentity**

The logical customer-update intent.

**ActionRevision material semantics**

The revision must bind:

- intent id;
- operation `update_customer` / current exact domain operation;
- exact customer target;
- destination id;
- account id;
- base endpoint;
- adapter profile;
- expected resource version;
- signed plan/patch digest;
- postcondition profile version;
- evidence/permit bindings used to authorize the attempt.

A different destination, account, customer, endpoint, expected resource version, adapter profile, patch meaning, or postcondition profile is a materially different revision.

### DecisionBasis

| Required dependency | Typed meaning | Validator / use-time owner |
|---|---|---|
| Signed Permit | exact intent/target/evidence/plan/execution binding is authorized | Aegis EEP executor |
| ExecutionBinding | destination/account/endpoint/adapter/expected version match configured executor | Aegis EEP executor |
| Durable attempt claim | one attributable possible effect is owned before dispatch can escape | Aegis attempt store |
| Journal evidence | authorization/dispatch/outcome evidence is retained | Aegis journal owner |
| Destination identity read | customer endpoint identifies the configured destination/account | CRM adapter |
| Expected resource version | the exact conditional-write version is established | CRM adapter |
| Postcondition profile | intended-field meaning is versioned | EEP postcondition evaluator |

### AuthorityContext

The CRM seed binds:

- configured destination;
- account;
- endpoint;
- exact customer;
- permitted operation;
- adapter profile;
- the authority represented by the signed Permit.

A request cannot switch account or endpoint by changing only the plan payload.

### Hard destination precondition

The current automatic profile requires destination-enforced:

```text
If-Match: <expected ETag/resource version>
```

HTTP 412 is a definite precondition rejection for this profile.

A local lock is not represented as remote fencing.

If the destination cannot supply/enforce the identity + conditional-write contract, this automatic profile is unsupported.

### Bounded-age observations

The pre-mutation GET and post-mutation observations are observations.

The pre-mutation read supplies the ETag used by the later destination precondition, but the read by itself is not atomicity.

### Adapter/effect/postcondition versions

Admission binds:

- `aegis.eep/crm-http-json/v1`;
- `aegis.eep/crm-postcondition/v1`;
- the current signed plan semantics;
- exact configured destination/account/endpoint.

The postcondition profile distinguishes:

- `ALREADY_SATISFIED`;
- `VERIFIED`;
- `PARTIAL`;
- `UNSATISFIED`;
- `UNKNOWN`.

K01 preserves those typed facts. K04 later defines the common closure/disposition relation and must not erase them.

### Admission invalidation

Admission must fail or be re-established when:

- destination/account/endpoint changes;
- customer/operation changes;
- expected resource version changes;
- plan/patch digest changes;
- adapter profile changes;
- postcondition profile changes;
- mandatory durable claim/journal is unavailable;
- required destination identity or conditional-write support is missing.

## 5. K02 effect/attempt/custody mappings

### 5.1 CI rerun / Workflow Failure Lab

#### EffectIdentity

For the selective-rerun seed, the logical effect is:

> request one provider rerun of the exact failed job execution bound by repository, workflow run, source run attempt, head SHA, workflow id and exact job execution identity.

The trusted profile must treat aliases or display names as insufficient. The exact repository/run/job execution binding is what distinguishes the target.

Two separately authorized ActionIdentity lineages may intentionally request equivalent reruns, but byte-identical payloads do not automatically merge their EffectIdentity.

#### ExecutionAttempt

One call to GitHub's job-rerun boundary is one ExecutionAttempt for that EffectIdentity.

The current implementation proves a narrower property:

- one evaluated state epoch triggers at most one selective rerun mutation;
- binding drift before the call prevents mutation;
- the configured attempt cap can block a further rerun.

Current executable evidence:

- `test_selective_epoch_performs_only_one_state_bound_mutation`
- `test_selective_epoch_does_not_mutate_after_binding_drift`
- `test_attempt_cap_blocks_all_candidates`
- `test_selective_subject_binding_blocks_run_attempt_drift`
- `test_selective_subject_binding_blocks_when_target_job_execution_changes`

#### Provider fanout/cardinality

GitHub may rerun dependent jobs when a job rerun is requested.

The existing profile therefore blocks selective automatic rerun when that provider fanout would cross the workflow-wide side-effect guard.

Evidence:

- `test_workflow_wide_side_effect_guard_blocks_safe_job`

K02 does not reinterpret a single POST as necessarily one downstream job execution when the provider contract says the operation can fan out.

#### Custody and process loss

The current WFL implementation does **not** contain a dedicated durable pre-dispatch attempt store equivalent to EEP's `FileAttemptStore`.

Therefore K02 does not credit the CI seed with provider-independent exactly-once dispatch or with automatic replay after an ambiguous process loss.

The conformant recovery rule is narrower:

1. retain the invoking workflow-run identity, ActionRequest/Decision/receipt artifacts that exist, exact source run/attempt/head/workflow/job target, and provider history needed to reconstruct the effect;
2. if the API call completed and the receipt was emitted, acceptance is recorded only as dispatch acceptance;
3. if the process disappears after the effect may have escaped but before confirmation is durable, **do not automatically dispatch again**;
4. custody moves to provider-history/operator reconciliation for the same EffectIdentity;
5. a new automatic attempt is allowed only after the profile can establish that no prior effect exists or a provider guarantee makes the retry idempotent.

If the retained GitHub history/artifacts are insufficient to reconstruct the exact target/effect, the automatic path stops. Missing retention cannot be repaired by generating a new request id.

This is a deliberate limitation, not a hidden workflow-service requirement.

#### Stale-worker/takeover boundary

The CI profile has no K02 claim of general multi-writer fencing.

A new executor must not take over an ambiguous prior dispatch merely because the prior runner is presumed dead.

The current safety claim is limited to state revalidation immediately before one mutation in the active invocation. D02 must later test the real provider embedding; K02 does not promote that into destination fencing.

---

### 5.2 Kubernetes node mutation / Aegis

#### EffectIdentity and declared effect set

One node-drain ActionRef can contain several consequential effects declared by its deterministic plan, including:

- the node cordon effect;
- one eviction effect per exact Pod UID in the admitted plan.

Each effect remains attached to the same ActionRef revision and plan digest but has a distinct domain effect slot.

A Pod name alone is not sufficient identity when the API gives an exact UID. Recreated Pods with reused names are not silently treated as the original effect target.

#### ExecutionAttempt and checkpoint custody

A concrete cordon/eviction operation is an ExecutionAttempt.

The existing checkpoint/recovery path retains:

- ActionID;
- plan/recovery context;
- whether cordon completed;
- exact completed Pod UIDs;
- remaining work;
- recovery state.

Executable evidence:

- `TestFileDrainCheckpointStoreRoundTrip`
- `TestCheckpointedExecutionRequiresFreshAuthorizationThenResumesRemainingPod`
- `TestInspectDrainRecoveryReconcilesEvictionThatSucceededBeforeCheckpointWrite`

The last case is the critical crash window:

```text
provider/API mutation succeeded
→ process failed before local checkpoint completion
→ recovery re-reads live state
→ recognizes the completed exact Pod effect
→ does not create a second eviction merely to repair the checkpoint
```

#### Recovery and several attempts

A resumed drain is not a new ActionIdentity merely because a new process executes it.

Recovery must preserve the original admitted action/effect identities, reconcile completed effects, and obtain fresh authorization for remaining mutation work where the current profile requires it.

A failed/pre-dispatch attempt and a later authorized retry may refer to the same EffectIdentity. Attempts remain distinct in history.

#### Lease/fencing scope

The Kubernetes Lease coordinates cooperating Aegis executors.

It is **not** claimed as a destination fencing token against arbitrary writers.

For stale Aegis workers, the adapter verifies current ownership before each mutation. Destination/API safeguards such as resourceVersion, Pod UID identity, live PDB checks and other server-enforced preconditions remain separately necessary.

If an operation lacks a sufficient server-side precondition and a stale worker could create an implicit second forbidden effect, automated takeover for that operation must stop.

#### Retention/custody

Checkpoint and journal evidence for unresolved or partially executed drains must be retained through recovery/transfer. Resetting a checkpoint merely to restore availability is not permitted.

A custody transfer to a recovery executor does not imply that already-running external work has been cancelled.

---

### 5.3 EEP synthetic CRM

#### EffectIdentity

The current CRM ActionRef permits at most one customer-update mutation effect for the exact:

- intent/revision;
- destination id;
- account id;
- endpoint;
- exact customer id;
- operation;
- plan digest;
- adapter/postcondition semantics.

The K02 EffectIdentity is the logical customer-update effect under that bound scope.

The existing deterministic:

```text
MutationAttemptID = SHA256(permit_digest || 0x00 || plan_digest)
```

is a **local attempt/custody key**. It is not represented as provider-side deduplication.

#### ExecutionAttempt

The current profile permits one dispatch attempt for that deterministic local attempt key.

Before dispatch can escape, it requires:

1. durable attempt claim;
2. authorization journal evidence;
3. destination/account/precondition validation;
4. dispatch-intent journal event;
5. durable transition to `POSSIBLE_EFFECT`;
6. only then the PATCH.

This ordering directly covers CE4.

Executable evidence:

- `TestExecutorBoundConditionalMutationAndDurableCompletion`
- `TestExecutorReplayAfterRestartDoesNotDispatchAgain`
- `TestExecutorConcurrentDuplicateAllowsOnePossibleEffect`
- `TestExecutorAttemptStoreAndJournalOutagePreventDispatch`

#### Already-satisfied no-op

When the exact requested fields already hold, the profile records no external mutation:

```text
CLAIMED
→ COMPLETED
request_acceptance = NOT_DISPATCHED
postcondition = ALREADY_SATISFIED
```

The profile does not fabricate provider acceptance.

Evidence:

- `TestExecutorAlreadySatisfiedAvoidsMutation`

#### Destination CAS and idempotency scope

The current CRM profile does not rely on a provider idempotency key.

Its hard destination guard is the exact ETag/resource version enforced through:

```text
If-Match: <expected resource version>
```

A stale value receives the profile's definite precondition rejection.

Evidence:

- `TestExecutorStalePreconditionBlocksAtDestination`
- `TestExecutorMissingDestinationPreconditionBlocksAutomaticPath`

The local attempt key prevents this executor from blindly replaying the same bound attempt across restart/concurrency. It does not fence another client that ignores the local store.

#### Ambiguous dispatch and recovery

If the request may have committed but response acceptance is unavailable, the attempt remains `POSSIBLE_EFFECT`.

No automatic second PATCH is permitted for that attempt.

The existing observation path may later establish the intended postcondition without rewriting request acceptance:

```text
request_acceptance = UNKNOWN
postcondition       = VERIFIED
```

This says the desired state is observed, not that the uncertain request is proven causal.

Evidence:

- `TestExecutorLostResponseAfterCommitCanVerifyPostconditionWithoutClaimingAcceptance`
- `TestExecutorAcceptedRequestWithUnavailableObservationRemainsUnknown`

This is recoverable custody: the same deterministic attempt record retains destination/account/customer, observation handle and possible-effect state across process loss.

#### Retention

An unresolved `POSSIBLE_EFFECT` record and its journal/observation handle must not be deleted or reset merely to permit another write.

Retention continues until later K04 closure/disposition semantics authorize retirement or custody is explicitly transferred.

---

### 5.4 Cross-domain K02 required-test review

| Queue test / adversary | Current K02 evidence / disposition |
|---|---|
| one intended effect with several attempts | normative relation is defined in `kernel-v1.md`; Kubernetes recovery preserves one effect identity across recovery attempts; K05 will later freeze executable cross-domain vectors rather than invent a shared runtime here |
| two deliberately distinct identical requests | defined as distinct only through trusted ActionIdentity/domain cardinality, never by payload bytes alone |
| already-satisfied no-op | EEP `TestExecutorAlreadySatisfiedAvoidsMutation` |
| domain-supported idempotent retry | permitted only with declared provider/CAS scope; current EEP deliberately does **not** retry POSSIBLE_EFFECT; Kubernetes retries/resumes only after reconciliation/fresh authorization |
| recovery after process loss | EEP restart replay test + possible-effect record; Kubernetes checkpoint/reconciliation tests |
| CE3 cross-provider duplication | denied while prior provider acceptance is possible; none of the current seeds claims automatic cross-provider failover |
| CE4 effect before journal | EEP requires durable claim/journal/possible-effect state before PATCH; outage test proves no dispatch |
| CE6 stale worker after takeover | Kubernetes ownership is checked for cooperating executors and server preconditions remain required; CI/EEP do not claim unsafe automatic takeover |
| provider-local key outside retention/account | no current seed is credited with a universal provider key; any future key must bind provider/account/operation/retention |
| aliases to one target | Kube uses exact Pod UID; EEP binds destination/account/customer; CI binds repository/run/job execution rather than display label |

The first row is intentionally a **semantic relation review**, not a frozen general conformance vector. K05 owns immutable accepted/rejected vector publication. K02 must not pre-empt K05 by creating a hidden reference runtime.

### 5.5 Declared crash-window matrix

| Domain | Before durable custody | After possible dispatch / before acceptance | After acceptance / before local finalization |
|---|---|---|---|
| CI rerun | current implementation has no dedicated attempt store; one active invocation only | no blind automatic retry; retain/reconstruct exact target and reconcile provider history/operator custody | receipt, when emitted, records dispatch acceptance only; downstream workflow outcome remains separate |
| Kubernetes drain | checkpoint/journal mechanisms retain bounded execution context | recovery inspects live target state and reconciles completed exact effects before resume | checkpoint recovery + fresh authorization for remaining mutations; accepted external work is not cancelled by ownership change |
| EEP CRM | durable attempt claim + journal required before PATCH | `POSSIBLE_EFFECT`; no replay; use observation handle | `ACCEPTED` or later postcondition evidence retained; K04 later owns administrative closure |

## 6. K03 temporal / resumption mappings

### 6.1 CI rerun / Workflow Failure Lab

#### Clock and validity domains

The CI seed already uses `eba.temporal/v1` with an explicit evaluation instant.

Current wall-clock semantics:

```text
not_before <= now < expires_at
```

and exact-expiry reuse fails closed.

Relevant executable evidence includes:

- `test_authority_uses_half_open_expiry_boundary`
- `test_assumption_uses_half_open_expiry_boundary`
- `test_future_checked_assumption_is_rejected`
- `test_equivalent_timezone_offsets_share_the_same_boundary`
- `test_authority_expiry_is_finite_by_default`

The CI profile also preserves non-time epochs:

- repository identity;
- workflow run id;
- run attempt;
- head SHA;
- workflow id;
- exact failed job execution identity.

Those state/revision epochs are not replaced by wall-clock freshness.

#### Next-effect boundary

The next consequential effect is the actual GitHub rerun request.

Immediately before that boundary, the current implementation revalidates the selective-rerun subject.

A wakeup, delayed runner step or callback cannot reuse an old decision without current checks.

Current evidence:

- `test_selective_subject_binding_allows_unchanged_job_execution`
- `test_selective_subject_binding_blocks_run_attempt_drift`
- `test_selective_subject_binding_blocks_when_target_job_execution_changes`
- `test_selective_epoch_does_not_mutate_after_binding_drift`

#### Expired authority

An expired AuthorityGrant or Decision does not authorize another rerun.

A future valid rerun requires a new current basis whose action revision still matches the provider state.

A fresh timestamp alone cannot rescue a changed run/head/job revision.

#### Observation after start authority expiry

A rerun accepted by GitHub becomes a provider-side workflow operation.

Later observation of that workflow attempt may remain useful after the original start authority expires, because observation does not itself create another rerun effect.

This does not authorize:

- a second rerun;
- a different job;
- another repository;
- a new run attempt mutation.

The current WFL receipt still means dispatch acceptance only; downstream pass/fail remains separate evidence.

#### Revocation and partition limit

The current CI profile does not claim an instant global revocation channel into GitHub.

If a required authority/revocation view cannot be established before a new rerun effect, the automated rerun stops.

Already accepted provider work is not claimed to be cancelled by later local revocation.

---

### 6.2 Kubernetes node mutation / Aegis

#### Time and epoch domains

The Kubernetes/Aegis seed uses several independent domains:

1. EBA wall-clock validity for AssumptionState / AuthorityGrant / Permit inputs;
2. Kubernetes state epochs such as node resourceVersion and exact Pod UID;
3. deterministic plan digest / policy / adapter versions;
4. Aegis lifecycle generation/epoch where runtime trust applies;
5. boot-bound monotonic deadline for active Runtime Trust Lease enforcement.

These are not collapsed into one timestamp.

#### EBA commit-boundary temporal semantics

Aegis C03 consumes the WFL `eba.temporal/v1` semantics at the actual mutation boundary.

Current behavior includes:

- explicit non-zero evaluation instant;
- finite mutation-bound assumption validity;
- finite AuthorityGrant `not_before` / `expires_at`;
- exact-expiry rejection;
- malformed time rejection;
- future assumption-check rejection.

Dependency evidence:
- Aegis C03 PR #69 head `31461753efd789744e81bdef64c7db85fc7d0163`, CI success.
- WFL C03 PR #110 head `9209acbf93bf0bdb82dad4e180feacfa2b211c1a`.

#### Recovery / next effect

A paused/restarted node drain does not resume mutation merely because a checkpoint exists.

The recovery path:

1. loads the original checkpoint;
2. re-reads current Kubernetes state;
3. reconciles already-completed exact effects;
4. computes remaining authorized work;
5. returns `RECOVERY_REAUTHORIZATION_REQUIRED` when more mutation remains;
6. requires a fresh authorization before resuming remaining Pod effects.

Evidence:

- `TestCheckpointedExecutionRequiresFreshAuthorizationThenResumesRemainingPod`
- `TestInspectDrainRecoveryReconcilesEvictionThatSucceededBeforeCheckpointWrite`

Thus:

```text
checkpoint exists
!=
permission to mutate
```

#### Runtime Trust Lease clock separation

Runtime Trust Lease is an Aegis runtime mechanism, not a universal kernel-v1 clock.

Its signed lease expiry is wall-clock bounded by attestation freshness:

```text
lease_expires_at =
min(now + lease_ttl,
    remote_verified_at + max_attestation_age)
```

When applied on Linux, the active lease is also bound to the current boot through a monotonic deadline.

Evidence includes:

- `TestRuntimeTrustLeaseExpiryCappedByRemoteAttestation`
- `TestRuntimeTrustRenewalRequiresNewerRemoteEvidence`
- `TestRuntimeTrustEvaluationRevokesExpiredLease`
- `TestRuntimeTrustEvaluationRevokesPolicySupersession`
- `TestRuntimeTrustWatchdogRemainingUsesBootClock`
- `TestRuntimeTrustWatchdogDoesNotRevokeBeforeDeadline`
- `TestRuntimeTrustWatchdogRevokesAtDeadlineAndSignsEvidence`
- `TestApplyRuntimeTrustRenewalFailsAfterCurrentMonotonicDeadline`
- `TestRuntimeTrustWatchdogRejectsBootChange`

Wall-clock rollback therefore cannot extend the active lease within the same boot.

A changed boot does not reuse the old boot-bound deadline.

#### Revocation-view guarantee

The current runtime trust watchdog can revoke the local/kernel-mediated network scope it actually controls.

At monotonic expiry it advances the current kernel revocation epoch before signing expiry evidence.

That claim is local to the enforced action class.

It does **not** mean:

- a previously accepted cloud/provider job is cancelled;
- all cluster writers instantly observe the same revocation;
- a network partition is globally resolved.

Before another governed Kubernetes mutation, the profile still requires its current authority/state/precondition witnesses.

#### Policy/adapter rollout

A node-drain basis is not reusable under materially changed:

- consequence policy/version/hash;
- capability policy;
- evidence-composition requirement;
- mutation adapter semantics;
- postcondition semantics;
- plan digest.

Absent an explicit trusted compatibility rule, the old basis cannot authorize a new effect after such a rollout.

#### Current-subject / C08 relation

C08 strengthens the current-subject/freshness boundary used by the relying path:

- current boot identity;
- attestation challenge;
- bounded remote verification freshness;
- bounded bootstrap receipt freshness;
- current executable/provenance subject;
- revocation-list validity.

C08 does not create global temporal authority.

Its K03 role is narrower: an old relying artifact from another boot/current subject cannot become current authority merely because its signature/hash remains valid.

Aegis C08 PR #74 head:
`c483f2ba56db473e41117ffe3aa591ce01f206e2` — CI success.

---

### 6.3 EEP synthetic CRM

#### Clock and state domains

The current EEP executor evaluates the signed Permit against its current clock:

```text
now < permit.valid_until
```

before the CRM mutation path proceeds.

The same ActionRevision also binds non-time state:

- destination;
- account;
- endpoint;
- customer;
- operation;
- expected resource version / ETag;
- plan digest;
- adapter profile;
- postcondition profile.

Permit freshness cannot replace an ETag/resource-version mismatch.

#### Next-effect boundary

The consequential effect boundary is the PATCH.

Immediately before external dispatch, the existing profile has already established:

- exact permit/plan binding;
- configured destination/account/endpoint match;
- durable attempt claim;
- authorization journal;
- destination identity;
- current expected ETag/resource version;
- dispatch-intent journal;
- durable `POSSIBLE_EFFECT` state.

A delayed worker cannot skip those checks because it still possesses the old Permit.

If the Permit is expired before this path reaches the effect boundary, no new PATCH is authorized.

#### Provider acceptance versus local dispatch

The current CRM profile distinguishes:

- local dispatch boundary;
- destination HTTP acceptance;
- post-mutation observation.

A local send time is not represented as destination acceptance time.

For the current synthetic HTTP profile there is no separate provider-enforced wall-clock deadline claim beyond the destination's conditional mutation semantics.

Therefore K03 does not invent one.

If a future CRM/provider profile has a server-enforced request deadline, acceptance-time claims must come from that provider protocol/evidence rather than local send time.

#### Ambiguous request after authority expiry

If a PATCH may already have escaped while authority was valid but acceptance becomes ambiguous:

- K02 keeps the same `POSSIBLE_EFFECT` custody;
- authority expiry does not prove the request failed;
- postcondition observation may continue if authorized;
- no second PATCH is emitted merely to regain certainty.

This preserves:

```text
request_acceptance = UNKNOWN
postcondition       = VERIFIED | PARTIAL | UNSATISFIED | UNKNOWN
```

without turning observation into new mutation authority.

#### Adapter/postcondition rollout

An old Permit/DecisionBasis cannot silently authorize a new effect under a materially changed:

- `aegis.eep/crm-http-json/v1` successor;
- postcondition profile;
- destination/account/endpoint interpretation;
- conditional-write semantics.

A new profile version requires explicit compatibility or a new current basis.

---

### 6.4 Cross-domain K03 revalidation matrix

| Dependency | CI rerun | Kubernetes/Aegis | EEP CRM |
|---|---|---|---|
| wall-clock authority | revalidate at rerun boundary | revalidate at governed mutation boundary | revalidate Permit before PATCH |
| state revision | run attempt/head/workflow/job | resourceVersion, Pod UID, plan/state | ETag/resource version + exact target |
| policy/adapter version | owner-controlled verifier semantics | consequence/capability/adapter/evidence profile | executor + postcondition profile |
| hard destination precondition | provider-native semantics only; no invented fencing | API-server preconditions where required | `If-Match` |
| revocation view | local/current authority view; no instant provider cancellation | configured authority + local runtime fence where applicable | signed Permit/current local authorization view |
| accepted external work | later workflow observation may continue | already-running provider work is not cancelled by local ownership change | postcondition observation may continue |
| next new effect | requires fresh/current basis | requires fresh/current basis | requires fresh/current basis |

### 6.5 K03 required/adversarial test review

| Queue case | Evidence / disposition |
|---|---|
| reuse still-valid bound evidence | WFL temporal validators accept before expiry; immutable artifact reuse remains allowed when profile requirements stay current |
| refresh expired dependencies | Kubernetes recovery explicitly requires fresh authorization; runtime trust renewal requires newer remote evidence |
| reject wrong revision | CI state-binding drift tests; Kubernetes resource/plan revalidation; EEP exact binding/ETag checks |
| continuing observation after start-grant expiry | permitted only as observation/reconciliation of an already accepted fixed effect; no seed treats it as permission for a new mutation |
| approval then revocation during partition | new effect stops when the profile-required current revocation view cannot be established; no instant global revocation claim |
| stale policy after wakeup | runtime trust policy supersession revokes old lease semantics; domain maps reject silent adapter/policy reinterpretation |
| process-local clock reset | active runtime lease uses boot-bound monotonic deadline; no cross-boot reuse |
| provider-enforced deadline | no current seed claims remote acceptance-time guarantee without provider evidence |
| duplicate callback | classified as observation vs new effect; new effect must revalidate current basis/cardinality |
| next mutation after authority expiry | forbidden without fresh authority |
| old policy under new adapter semantics | forbidden absent explicit compatibility |

### 6.6 K03 outage / rollout treatment

| Situation | CI | Kubernetes/Aegis | EEP CRM |
|---|---|---|---|
| authority/revocation source unavailable | no new rerun | no new governed mutation that requires that witness | no new PATCH |
| observer unavailable after accepted effect | preserve uncertainty/provider history | preserve checkpoint/custody | preserve `POSSIBLE_EFFECT` / outcome uncertainty |
| process restart | wakeup is not permission | recovery + current-state reconciliation + reauthorization | load durable attempt; no blind replay |
| policy/adapter rollout | old basis not silently reused | version/hash compatibility required | old Permit not reinterpreted under new semantics |
| boot change | n/a | old boot-bound runtime deadline not reused | n/a |

## 7. Obligation-to-owner table

| K01 obligation | Owning implementation / contract |
|---|---|
| exact ActionRequest / action digest in CI | WFL `eba.integration/v0.1` |
| CI temporal admissibility | WFL `eba.temporal/v1` |
| CI/Aegis contextual bindings | WFL/Aegis `eba.context/v1` consumers |
| deterministic EBA bytes | WFL/Aegis `eba.canonical-json/v1` consumers |
| relevant-state invalidation | EASL StateBinding + domain consumers |
| assumption projection semantics | assumption-gate + consuming profile |
| authority scope semantics | Agent Action Guard + consuming profile |
| EGE permit signature/binding | Aegis `aegis.ege/permit/v0alpha1` |
| evidence independence | Aegis `aegis.ege/evidence-composition/v1` |
| Kubernetes mutation-time state/preconditions | Aegis Kubernetes adapter |
| CRM destination/account/precondition binding | Aegis `aegis.eep/crm-http-json/v1` |
| CRM intended-postcondition meaning | Aegis `aegis.eep/crm-postcondition/v1` |
| effect/attempt common relations | **K02 — defined in `kernel-v1.md`; mapped here to existing domain mechanisms** |
| resumption/time common relations | **K03 — defined in `kernel-v1.md`; mapped here to explicit temporal/revalidation owners** |
| closure/UNKNOWN common relations | **K04 — not defined here** |

## 8. CE1 and CE2 seed review

### CE1 — vacuous profile

All three seeds must reject a caller attempt to:

- select an empty mandatory-requirement set;
- remove an owner-required validator;
- select an unknown profile/version;
- substitute a self-declared validator as trusted;
- use route choice to obtain weaker governance for the same governed operation.

### CE2 — revision / approval substitution

All three seeds must reject reuse of an earlier basis when a material binding changes.

At minimum the review covers:

- CI: repository/run/attempt/head SHA/workflow/job scope/principal;
- Kubernetes: action/target/cluster context/resourceVersion/plan/evidence/policy/adapter;
- EEP: destination/account/endpoint/customer/expected version/plan/postcondition profile.

## 9. Positive-seed review

A positive seed is useful only when the required operation can still proceed under its legitimate profile:

- a legitimate eligible CI rerun can reach the owner-controlled native execution boundary;
- a legitimate governed Kubernetes drain can pass the configured EGE boundary;
- a legitimate CRM update can pass exact destination/account/If-Match checks and preserve its typed postcondition result.

Reject-all behavior does not satisfy K01.

## 10. K01/K02/K03 limits

This map does not claim:

- a universal action schema;
- a universal evidence ontology;
- a shared identity provider;
- a general policy engine;
- a universal closure enum;
- exactly-once external effects;
- automatic provider substitution;
- a new shared runtime or repository.

The next semantic item after K03 is K04, not platform extraction.
