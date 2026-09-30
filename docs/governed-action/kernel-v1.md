# Candidate Governed-Action Kernel v1 — K01 + K02 + K03 + K04 + K05 contract

Status: **FROZEN — candidate kernel contract v1 (K06 baseline)**  
Queue items: **K01 — Define revision, basis and trusted profile bindings**; **K02 — Define effect/attempt and recoverable custody relations**; **K03 — Define temporal and next-effect resumption semantics**; **K04 — Define truthful closure and UNKNOWN disposition**; **K05 — Publish normative examples and change control**  
Normative scope: **K01 + K02 + K03 + K04 + K05**. K06 freezes this exact semantic baseline; K07 may execute it but may not change its accepted/rejected meaning under v1.

This document defines the smallest shared relations needed to bind an exact consequential action proposal to the typed basis used to admit it, identify and retain accountable custody of possible effects/attempts, determine what must be re-established before any later effect boundary, and truthfully dispose of the resulting closure obligation without manufacturing certainty. It does **not** create a kernel service, identity service, policy engine, action catalog, universal evidence schema, universal outcome service, scheduler, workflow runtime, durable workflow service, global clock, revocation bus, global lock, or generic authorization token.

## 1. Candidate boundary

The candidate kernel preserves six concepts in five record families:

1. **ActionIdentity**
2. **ActionRevision**
3. **DecisionBasis**
4. **EffectIdentity**
5. **ExecutionAttempt**
6. **ClosureObligation**

The five record families are:

- **ActionRef** = ActionIdentity + ActionRevision
- **DecisionBasis**
- **EffectIdentity**
- **ExecutionAttempt**
- **ClosureObligation**

K01 defines the normative relations for **ActionRef** and **DecisionBasis**, plus trusted profile selection and their boundary bindings.

K02 defines the normative relations for **EffectIdentity** and **ExecutionAttempt**, including effect cardinality, attempt custody, crash ambiguity, idempotency/fencing scope, and recovery ownership.

K03 defines validity intervals, clock domains, dependency-specific revalidation and the rule that continuation/wakeup carries no automatic authorization for a new effect.

K04 defines **ClosureObligation** as the accountable relation between effect/attempt history, typed observations/postconditions, evidence horizon, residual uncertainty, custody and administrative disposition.

K05 publishes versioned accepted/rejected examples for CE1–CE12, paired positive counterparts, positive seed traces and the change-control rule that separates implementation fixes from normative changes.

Still unresolved:

- **K06** must verify prerequisite evidence and record immutable hashes/source commits before this draft becomes the frozen candidate kernel contract v1.

No implementation may claim frozen-v1 conformance merely because it conforms to the unfrozen K01–K05 draft.

## 2. Governing invariant slice

K01 directly supports:

- **I1 — Binding integrity:** admission cannot silently change action revision, subject, destination, account, or material semantics.
- **I2 — Valid admission at the actual effect boundary:** mandatory typed predicates and scoped authority must hold at the declared enforcing boundary.
- **I3 — No implicit authority or effect amplification:** the admitted basis cannot silently enlarge principal, scope, destination, account, tenant, credential audience, adapter semantics, or effect cardinality.

K02 makes the effect-cardinality part of I3 explicit and establishes the custody part of:

- **I5 — No unowned possible effect:** a consequential effect that may survive its executing process has reconstructable identity and accountable custody before it can escape.

K03 establishes:

- **I4 — Continuation carries no automatic authorization:** at the next effect boundary, every profile-required current witness is still valid or explicitly re-established. Wakeup, callback, retry, recovery ownership or a still-running process is not permission.

K04 establishes:

- **I6 — Truthful disposition:** provider acceptance, observation, verified postcondition, residual uncertainty and administrative retirement remain distinct. UNKNOWN is never converted into success or proof that replay is safe.

K01–K05 now define the candidate relations and the published draft oracle. K06 still owns the immutable freeze record.

## 3. ActionRef

An **ActionRef** identifies one immutable interpretation of a proposed consequential action.

It consists semantically of:

```text
ActionIdentity
+
ActionRevision
```

The serialization remains domain-owned.

### 3.1 ActionIdentity

ActionIdentity answers:

> Which logical proposal lineage is this?

It must remain stable across revisions of the same proposal and must not be reused for an unrelated proposal.

### 3.2 ActionRevision

ActionRevision answers:

> Which exact material interpretation of that proposal is being admitted?

The revision must bind every material field whose change could alter authorization, target, consequence, or execution semantics. Where applicable this includes:

- action kind / operation;
- exact subject and target;
- destination/provider identity;
- account and authenticated namespace / tenant;
- actor and on-behalf-of identity;
- credential issuer/audience or equivalent credential scope;
- installed adapter/effect semantics version;
- domain postcondition profile version;
- required relevant-state bindings;
- hard destination precondition identity;
- other domain-owned fields explicitly declared material by the selected profile.

A prior admission for revision A cannot authorize revision B merely because the ActionIdentity is unchanged.

The revision may be represented by a version, digest, immutable record reference, or another domain-native token, but the selected Admission Profile must state what fields it covers and how equality is checked.

## 4. DecisionBasis

A **DecisionBasis** is the complete typed dependency set used to admit one exact ActionRef.

A DecisionBasis is valid for admission only when all of the following are true:

1. it references the exact ActionRef being admitted;
2. the Admission Profile is trusted and known;
3. every mandatory predicate required by that profile is present;
4. every predicate has a typed meaning, validator identity/version, input reference, and use-time validation owner;
5. required AuthorityContext bindings match the actual effect boundary;
6. required StateBinding predicates match the relevant current state or an explicitly allowed bounded-age observation;
7. hard destination preconditions are not replaced by prior reads;
8. adapter/effect/postcondition versions are the versions actually installed or otherwise bound at the effect boundary;
9. no caller-controlled optional field can select a weaker interpretation of the same profile.

A generic boolean such as `approved=true`, `safe=true`, or `valid=true` is not a DecisionBasis.


### 4.1 Profile-relative admissibility and decision-basis distinguishability

Admission is always relative to a declared claim scope and trusted profile. Profile trust alone is not evidence that the profile contains every distinction relevant to the claim.

For each automatic-ALLOW claim scope, every **known decision-relevant distinction** must be handled in exactly one of these ways:

1. bound in the DecisionBasis / StateBinding and revalidated when K03 requires it;
2. discharged by a typed validator or a hard destination guard whose semantics are bound at the effect boundary; or
3. retained as an explicit unresolved assumption / critical defeater that prevents automatic ALLOW until it is resolved.

A useful bounded adequacy test is:

> under the declared claim scope and assumptions, two modeled states that are observationally identical to DecisionBasis must not require opposite admissibility decisions for a known decision-relevant distinction.

If such a pair exists, the automatic result is DEFER / DENY until additional distinguishing state/evidence is bound or a destination guard discharges the distinction.

This is a relation over the existing DecisionBasis, StateBinding and profile contracts. It is **not** a seventh core primitive, a scalar confidence score, or a generic `profile_adequate=true` flag.

Evidence-independence requirements are likewise scoped to the profile's declared failure/dependency model. `UNKNOWN` or `DEPENDENT` / otherwise violated required independence cannot satisfy the obligation. A hidden common cause outside the declared model is an assumption breach; it is not retroactive proof that absolute independence was ever knowable.

I2 also depends on explicit enforcement assumptions. The profile must identify the actual enforcing boundary and the complete-mediation / enforcement-integrity assumptions required for the claim. If those assumptions are missing, automatic ALLOW is unsupported. If the TCB/enforcer is actually compromised despite a declared assumption, the logical guarantee no longer applies; another record family would not solve recursive trust.

## 5. Mandatory predicate coverage

Each trusted Admission Profile defines its mandatory predicate set.

The semantic shape of one predicate requirement is:

```text
predicate_id
predicate_type
required = true
validator_id
validator_version
input/reference meaning
use-time validation owner
failure meaning
```

This is a semantic contract, not a new universal wire schema.

If a mandatory predicate is missing, unknown, evaluated by an unknown validator version, or cannot be checked at the declared boundary, admission fails closed for that profile.

A requester cannot:

- omit a mandatory predicate;
- provide its own validator and mark it trusted;
- downgrade the profile version;
- replace a typed predicate with a boolean;
- reinterpret an unknown predicate as optional.

## 6. Trusted Admission Profile selection

An **Admission Profile** defines the exact required predicates, bindings, validators, boundary, and domain versions for one action class.

Profile selection must be controlled by a trusted owner of the enforcing boundary, such as:

- server configuration;
- compiled owner-controlled verifier configuration;
- authenticated deployment policy;
- another mechanism whose authority is independent of the requesting actor.

The requesting actor may identify the action class, but it cannot unilaterally choose a weaker trusted profile.

### 6.1 Version rules

Admission requires an exact known profile version.

```text
unknown profile       -> reject/escalate, no effect
unknown version       -> reject/escalate, no effect
profile downgrade     -> reject unless explicitly authorized by the trusted owner
missing validator     -> reject/escalate, no effect
unknown validator ver -> reject/escalate, no effect
```

A profile update that changes which valid trace is accepted or rejected is a normative change and cannot retain the same frozen identity after K06.

### 6.2 Explicit singleton deployment

A deployment may legitimately have one tenant/account namespace.

That case must be explicit:

```text
namespace_mode = singleton
namespace_id   = <trusted deployment identity>
```

The singleton identity comes from trusted deployment configuration, not from a client-provided tenant string.

An equal local resource ID under another authenticated account/namespace is a different target binding.

## 7. AuthorityContext binding

Where applicable, DecisionBasis must bind the authority context that matters at the effect boundary:

- actor / principal;
- on-behalf-of subject;
- action/operation;
- resource scope;
- account;
- tenant or explicit singleton namespace;
- credential issuer;
- credential audience;
- allowed side effect / capability scope;
- approval or delegated-authority references.

Integrity is not authority.

A self-hash proves only that bytes were not changed relative to the recomputed digest. External authority requires authenticated issuance or an authenticated parent binding, while trusted in-process construction must be declared as such by the profile.

## 8. StateBinding

StateBinding remains the earned EASL primitive and is referenced rather than redefined here.

K01 uses it for the relation:

> this DecisionBasis is valid only for the declared relevant state of this ActionRef.

Current preserved conformance identity:

- EASL main reviewed head: `7c4e1e28218853919d00362dc071e1eb6f61cc56`
- WFL main reviewed head after C05: `d44bd4c47f8748bfca706a4c4833adf8ce940cf6`
- canonical vector blob in both repositories: `82d151531da6f98262de1e247658d89a8299c53c`
- Aegis current K01 base: `0d94613e1a05ae467170e615633d79c31a309d36`
- Aegis EASL module pin at this base: `github.com/achirothmane/easl v0.0.0-20260928052341-f7e3b79c6892`

The opaque state token remains domain-owned. K01 does not turn StateBinding into a universal state object or an atomic destination guard.

## 9. Hard destination preconditions versus observations

A **hard destination precondition** is a condition the destination must enforce atomically with, or as part of, accepting the mutation when the domain claim requires it.

Examples include:

- HTTP `If-Match` / ETag;
- Kubernetes resourceVersion or UID precondition;
- database compare-and-swap / transaction predicate.

A **bounded-age observation** is evidence about state observed before the effect boundary.

A prior read cannot be renamed a hard precondition.

If a profile requires a hard destination predicate and the destination cannot enforce it, that automatic path is unsupported and must remain blocked or be placed under a separately authorized weaker profile with a different claim.

## 10. Adapter, effect and postcondition version binding

Admission must bind the versions that determine the meaning of the action:

- adapter/transport semantics;
- operation/effect semantics;
- postcondition/outcome profile where one exists.

A hidden change to an adapter default cannot inherit admission issued for materially different semantics.

The mechanism may be a digest, immutable release identity, compiled version, or profile-specific identifier. The selected Admission Profile must state the actual mechanism and the use-time owner that verifies it.

## 11. Boundary contracts

K01 preserves these boundary contracts without turning them into mandatory services:

| Boundary | K01 requirement |
|---|---|
| **StateBinding** | exact relevant-state relation, version/reference pinned where used |
| **AuthorityContext** | principal/scope/account/tenant/audience semantics bound where applicable |
| **PolicyDecision** | typed decision dependency; a generic boolean is insufficient |
| **ExecutionPermit** | if used, must bind the exact ActionRef and DecisionBasis dependencies it represents |
| **OutcomeObservation** | may be referenced for profile completeness, but closure semantics remain K04 |
| **Admission/Closure Profile** | selection is trusted and versioned; K01 defines admission binding rules, while K04 defines closure meaning |

An ExecutionPermit is not itself independent proof that every dependency remains valid. K03 owns next-effect revalidation semantics.

## 12. K02 effect/attempt and recoverable-custody contract

### 12.1 EffectIdentity

An **EffectIdentity** answers:

> Which one consequential effect, within the admitted ActionRef and its domain-declared cardinality, are these attempts trying to realize?

EffectIdentity is not interchangeable with:

- ActionIdentity or ActionRevision;
- request id;
- permit id or permit digest;
- HTTP request id;
- provider operation id;
- local replay-guard key;
- ExecutionAttempt id.

One ActionRef may legitimately contain multiple effects when the domain profile declares that cardinality explicitly. For example, a bounded node-drain plan may contain a node-cordon effect plus one eviction effect per exact Pod UID.

Conversely, several ExecutionAttempts may belong to one EffectIdentity when the domain supports a safe retry relation.

The domain profile must make EffectIdentity reconstructable from retained facts sufficient to distinguish:

- one intended effect retried several times;
- two deliberately distinct effects whose payloads happen to be byte-identical;
- two aliases that resolve to the same protected target;
- one request that expands into several explicitly declared effects.

A caller-provided id cannot create a distinct effect merely by changing the label while the trusted profile says the target/cardinality slot is the same.

### 12.2 Effect cardinality

The selected profile must declare the permitted relationship between the ActionRef and its effects.

Examples of legitimate domain meanings include:

- one ActionRef permits at most one external mutation effect;
- one ActionRef permits one effect per exact item in a signed deterministic plan;
- one ActionRef permits zero external effects when the intended postcondition is already satisfied.

K02 does not introduce a universal cardinality enum. The domain meaning remains typed and owner-controlled.

The cardinality rule must prevent an implicit second effect. If the system cannot tell whether the first effect may already exist, it cannot manufacture availability by assigning a new EffectIdentity and dispatching again.

### 12.3 ExecutionAttempt

An **ExecutionAttempt** answers:

> Which concrete effort crossed, or may have crossed, the effect boundary for this EffectIdentity?

Each attempt must be related to:

- one EffectIdentity;
- the exact ActionRef revision;
- the DecisionBasis used at the relevant boundary;
- the domain execution boundary;
- the executing owner/generation;
- the destination/provider/account scope;
- the domain attempt identity and retained evidence.

Attempt identity is domain-owned. It must be unique for the declared retention scope, but uniqueness alone is not destination enforcement.

A deterministic local attempt id can support recovery and replay detection while still providing **zero** provider-side deduplication.

### 12.4 Facts, not a false universal state machine

K02 standardizes relations and knowledge boundaries, not one global lifecycle enum.

A domain may expose local states, but the common facts are:

**PREPARED / CUSTODIED**

Enough durable information exists to reconstruct the EffectIdentity, ActionRef, basis reference, owner and destination scope before a consequential effect may escape.

**POSSIBLY_DISPATCHED**

The effect may have crossed the boundary. Acceptance is not established. A blind retry is forbidden unless the same effect can be retried under an explicitly proven domain idempotency/fencing rule.

**ACCEPTED**

The destination/provider has supplied evidence sufficient for the profile to claim request acceptance.

ACCEPTED does not mean the intended postcondition is verified. K04 owns closure/disposition semantics.

A domain may also record definite no-dispatch/rejection facts. Those do not imply that every other failure proves non-acceptance.

### 12.5 Pre-dispatch custody ordering

For an effect that may survive the executing process:

```text
reconstructable EffectIdentity
+ accountable owner
+ durable attempt/custody record
before
external effect may escape
```

If the implementation can perform the effect before establishing recoverable custody, the automatic path is not K02-conformant.

A journal append that happens only after provider success is insufficient for I5.

The record need not be a new shared service. Existing domain journals, provider-hosted durable operation records, atomic destination markers, or bounded durable local stores may satisfy the requirement when their failure model is explicit.

### 12.6 Crash windows

Every domain profile must state what is known in at least these windows:

| Crash window | Required K02 treatment |
|---|---|
| before durable PREPARED custody | dispatch must not have occurred |
| after PREPARED, before boundary entry | recover the same EffectIdentity; do not invent a new effect |
| after boundary entry, before acceptance evidence | retain POSSIBLY_DISPATCHED and forbid blind replay |
| after provider acceptance, before local acceptance record | reconstruct from provider/destination evidence or retain ambiguity |
| after intended postcondition evidence, before local finalization | retain effect/attempt history; K04 later owns closure |

If a domain cannot distinguish a window safely, it must keep the stronger uncertainty rather than infer non-execution.

### 12.7 Idempotency, retention and provider scope

An idempotency or deduplication claim is valid only within its declared scope.

The profile must bind, where applicable:

- provider/destination;
- account/tenant;
- operation;
- target/effect scope;
- idempotency key or conditional-write token;
- provider retention window;
- any generation/fencing epoch.

A provider-local key reused with another provider, account, operation, or after the provider's documented retention horizon is not credited as the same enforcement domain.

A local request id, permit digest or attempt id is never described as provider enforcement unless the destination actually evaluates it.

### 12.8 CAS, generation and fencing

When two executors could race and a duplicate would violate the declared effect cardinality, the profile must identify the mechanism that makes stale execution harmless or impossible.

Acceptable mechanisms are domain-specific and can include:

- destination-enforced compare-and-swap / conditional mutation;
- provider-enforced idempotency within a bound retention scope;
- provider generation/fencing token;
- a proven single-writer boundary whose exclusivity actually covers the effect.

A process mutex or local lease coordinates only the executors that honor it.

If a stale worker can still reach the destination after takeover and the destination has no adequate CAS/idempotency/fencing rule, automatic takeover must stop.

Unsupported exclusivity cannot be repaired by relabeling a POSSIBLY_DISPATCHED attempt as failed.

### 12.9 Custody and transfer

Every unresolved possible effect has exactly one accountable **custody owner** at a time.

Custody means responsibility to retain the reconstructable EffectIdentity, attempts, provider/destination references and evidence needed for later reconciliation.

Transfer requires:

1. explicit identification of the effect and unresolved attempts;
2. a durable transfer record or equivalent retained evidence;
3. the receiving owner to accept responsibility;
4. the prior owner to retain history sufficient to prove the transfer.

Custody transfer does not cancel an already accepted or still-running external operation.

A new owner cannot dispatch a replacement merely because ownership moved.

### 12.10 Provider substitution and CE3

A provider switch does not create permission for a second equivalent effect.

If provider A may already have accepted the effect, provider B must not be dispatched for the same EffectIdentity unless the selected profile can establish one of:

- provider A definitely did not accept;
- provider A's effect is fenced/cancelled under a supported destination guarantee;
- the domain explicitly permits more than one effect and the ActionRef cardinality says so.

Otherwise the effect remains under reconciliation custody.

### 12.11 CE4 — effect before journal

The following ordering is forbidden:

```text
external effect
→ later create first recoverable attempt/custody record
```

The permitted ordering is:

```text
durable recoverable custody
→ boundary-entry / possible-effect record
→ external dispatch
→ acceptance/observation evidence
```

A domain may combine durable operations atomically when its substrate supports that stronger primitive.

### 12.12 CE6 — stale worker after takeover

Takeover is safe only when the old worker cannot create an additional forbidden effect.

The new owner must not infer this from local ownership alone.

The domain mapping must state whether safety comes from:

- destination fencing/generation;
- CAS/conditional mutation;
- provider idempotency;
- completed-state reconciliation that makes another dispatch unnecessary;
- or a rule that forbids automated takeover while old execution remains possibly active.

### 12.13 Required relation examples

**One intended effect, several attempts**

```text
EffectIdentity = E
Attempt A1 -> definite pre-dispatch rejection
Attempt A2 -> dispatch under the same E
```

A1 and A2 remain distinct attempts. The second attempt is allowed only if the domain can establish that A1 produced no effect or if a proven idempotency/fencing rule keeps both attempts within one effect.

**Two deliberately distinct identical requests**

Two separately authorized ActionIdentity lineages may legitimately request the same bytes against the same target. They remain distinct effects only if the trusted domain policy permits both; payload equality alone neither merges nor duplicates their identity.

**Already-satisfied no-op**

The EffectIdentity may be reconstructable while the executor records that no external dispatch was required. A local prepared/custody record may close its attempt as no-dispatch; it must not invent provider acceptance.

**Domain-supported idempotent retry**

A retry remains attached to the same EffectIdentity, receives a distinct ExecutionAttempt identity, and reuses only the provider idempotency/CAS scope the profile actually guarantees.

**Recovery after process loss**

Recovery loads or reconstructs the same EffectIdentity and unresolved attempt(s), keeps the existing custody owner or records a transfer, and decides from retained/provider evidence whether observation, safe retry, or stop is permitted. It does not mint a replacement effect to recover availability.

### 12.14 K02 completion rule

K02 is complete only when each design-visible possible effect has:

- reconstructable EffectIdentity under process loss;
- explicit domain effect cardinality;
- ExecutionAttempt identity and retained relation to ActionRef/basis/boundary;
- a named custody owner;
- declared retention/idempotency scope;
- explicit crash-window treatment;
- a stop rule for unsupported stale-worker exclusivity;
- no local id misrepresented as destination enforcement.

K02 fails if the specification permits:

- an unowned possible effect;
- an implicit second effect;
- blind replay after ambiguous dispatch;
- cross-provider duplication presented as recovery;
- effect-before-custody ordering;
- takeover whose safety depends only on a local ownership label.

Rollback/containment is to stop further conflicting dispatch, preserve all attempt/effect evidence, and observe/reconcile under the existing bounded authority.

## 13. K03 temporal and next-effect resumption contract

### 13.1 Time is typed, not one universal timestamp

K03 does not define one global time source.

A profile may depend on several distinct clock/epoch domains:

| Domain | Meaning | K03 rule |
|---|---|---|
| **wall-clock validity** | signed/declared `not_before`, `expires_at`, `valid_until`, evidence freshness | evaluate against an explicit trusted/current instant at the enforcing boundary |
| **boot-bound monotonic time** | local runtime lease deadline that must not be extended by wall-clock rollback | compare only within the same boot identity and the declared monotonic clock domain |
| **state / revision epoch** | run attempt, resourceVersion, generation, lifecycle epoch, policy hash/version | exact equality/current-state validation; wall-clock freshness cannot substitute for revision identity |
| **provider deadline / acceptance window** | a remote service's own deadline or acceptance rule | the provider-enforced rule remains authoritative; a local pre-dispatch check does not prove remote acceptance before that deadline |
| **observation horizon** | how long outcome/continuation observation remains meaningful | profile-specific; observation permission is distinct from authority to create a new effect |

These domains must not be silently converted into one timestamp or one integer epoch.

### 13.2 Half-open wall-clock validity

Where a dependency uses finite wall-clock validity, the default K03 interval is:

```text
not_before <= now < expires_at
```

or, for a single upper bound:

```text
now < valid_until
```

Exact-expiry reuse fails closed.

Equivalent timezone offsets that denote the same instant may normalize to the same time when the owning temporal profile explicitly supports that normalization.

Malformed, naive, wrong-type or otherwise unsupported timestamps cannot degrade into structural success.

K03 preserves the existing `eba.temporal/v1` rule that an absent/null expiry is profile-specific, not a universal permanent lease. A finite supporting dependency cannot be erased by projecting it into a non-expiring child.

### 13.3 Dependency-specific revalidation

At a next effect boundary, the profile determines which dependencies must be current and how.

| Dependency class | Revalidation rule before a new effect |
|---|---|
| immutable content digest / immutable signed artifact | may be reused when identity/signature remains valid and no profile rule requires reacquisition |
| finite evidence / assumption | re-check current time and any required current subject/state binding |
| AuthorityGrant / approval / permit | re-check expiry, revision/scope binding and the revocation view promised by the profile |
| StateBinding / target revision | re-read or otherwise establish the exact current state required by the domain |
| destination hard precondition | establish at the actual destination acceptance/mutation boundary; a stale observation cannot replace it |
| evidence-composition predicate | re-evaluate when any declared material source/dependency or required assurance has changed/expired |
| policy / consequence / capability semantics | verify the exact bound version/hash still governs the effect |
| adapter/effect semantics | verify the executing adapter/profile version is the one admitted; a hidden default change invalidates reuse |
| runtime trust lease | validate current generation/lease epoch/deadline and its enforcing boundary; an old process lifetime is not authority |
| provider operation already accepted | observation/reconciliation may continue if the profile permits, but acceptance does not mint authority for another effect |

Revalidation is scoped. K03 does **not** require reacquiring unchanged immutable evidence merely because a worker woke up.

### 13.4 Wakeup and continuation

The governing rule is:

> continuation is a control-flow fact, not an authorization fact.

The following events confer no new authority by themselves:

- process wakeup;
- retry timer firing;
- callback arrival;
- worker restart;
- recovery ownership transfer;
- lease/watchdog thread continuing to run;
- receipt of a duplicate webhook/callback;
- presence of an old ALLOW/permit in durable storage.

Before the next consequential effect, the executor must identify:

1. the exact next EffectIdentity / effect slot;
2. the current ActionRef revision;
3. the profile-required current witnesses;
4. the effect boundary where each witness is actually enforced;
5. whether the current operation is a **new effect** or only **observation/reconciliation** of an already-started bounded external operation.

If any mandatory current predicate cannot be established at the claimed boundary, the automatic mutation path stops.

### 13.5 Start authority versus continuation of an already accepted bounded job

A finite authority may authorize **starting one bounded external job**.

If the provider accepts that job while start authority is valid, expiry of the start grant does not necessarily prove that the already accepted external operation stopped.

A profile may permit continued **observation/reconciliation** after start-grant expiry when all of these hold:

- the external job/effect identity was fixed before expiry;
- no new effect is created;
- observation itself remains authorized;
- the profile explicitly declares that the provider operation may continue independently once accepted;
- custody remains accountable under K02.

This does **not** allow:

- starting another job;
- retrying the mutation;
- broadening resource scope;
- issuing a second callback-driven effect;
- renewing authority merely because the old job still exists.

A new consequential effect requires current authorization at that new boundary.

### 13.6 Dispatch time is not destination acceptance time

K03 distinguishes:

```text
local dispatch decision time
local request-send time
provider/destination acceptance time
provider operation execution time
observation time
```

A local check made before a provider-enforced deadline does not prove the provider accepted the request before that deadline.

If a profile claims acceptance-time enforcement, the destination/provider must expose evidence or a protocol guarantee sufficient for that claim.

If the provider only exposes a send-time API call and acceptance timing can cross the deadline, the stronger acceptance-time guarantee is unsupported and must not be advertised.

### 13.7 Revocation-view semantics

Revocation is only as strong as the view and enforcement boundary the profile actually has.

Each profile must state:

- what revocation source/view is checked;
- at what boundary it is checked;
- whether the check can be stale under partition;
- whether local enforcement can revoke future effects;
- whether already accepted remote work can continue.

K03 does not claim instant global revocation.

When the required revocation view is unavailable or too stale for the profile's claim, a new effect must stop.

A local revocation/fence can block later local/kernel-mediated effects without implying that a remote provider job already accepted is cancelled.

### 13.8 Runtime trust: wall-clock lease plus boot-bound monotonic enforcement

Aegis Runtime Trust Lease semantics remain owned by the existing runtime implementation.

K03 recognizes two distinct time relations:

1. the signed lease carries a wall-clock `expires_at`, bounded by attestation freshness;
2. when applied on Linux, the lease is installed as a boot-bound monotonic deadline using the current boot identity.

The monotonic deadline protects the active local lease from wall-clock rollback.

Required rules include:

- lease expiry cannot exceed the remote-attestation freshness boundary;
- renewal requires strictly newer remote evidence;
- lease epoch must advance monotonically;
- lease/generation/lifecycle lineage must match current state;
- policy supersession revokes the old lease semantics;
- the watchdog does not revoke before the monotonic deadline;
- at the deadline it advances the current kernel fence before producing expiry evidence;
- a boot change invalidates reuse of the old boot-bound deadline;
- renewal after the current monotonic deadline has already elapsed is rejected.

This runtime lease is not a universal clock service and does not automatically cancel remote external operations outside its enforced action class.

### 13.9 Policy and adapter version changes

An old decision cannot be silently reinterpreted under new semantics.

If any of these materially change:

- admission profile;
- policy/consequence/capability version or hash;
- adapter/effect semantics;
- postcondition profile;
- validator version whose meaning affects valid traces;

then reuse of an old DecisionBasis requires an explicit compatibility rule owned by the trusted profile.

Absent such a rule, the old basis cannot authorize a new effect under the new semantics.

A code rollout is therefore not merely a process restart when it changes action meaning.

### 13.10 Duplicate callbacks

A callback may trigger:

- observation of an existing EffectIdentity;
- reconciliation;
- a new effect.

The profile must classify which one it is.

A duplicate callback that only repeats an idempotent observation may be harmless.

A duplicate callback that could create a new consequential effect requires the same current-witness checks as any other new effect and must also respect K02 effect cardinality/idempotency rules.

"Callback received" is never sufficient authorization.

### 13.11 Wrong revision and stale state

A continuation for ActionRevision A cannot mutate ActionRevision B.

Before the next effect, material changes such as:

- run attempt/head SHA/workflow/job identity;
- Kubernetes resourceVersion/Pod UID/plan digest;
- CRM destination/account/customer/ETag/plan;
- policy/adapter/postcondition version;
- runtime generation/lifecycle/lease epoch;

must be re-established under the current profile.

If the correct current revision cannot be established, the new effect is blocked/escalated rather than performed under stale authority.

### 13.12 Temporal failure examples

**Approval then revocation during partition**

If the profile requires a current revocation view and the executor cannot establish it because of partition, it cannot create a new effect. K03 does not pretend the old cached ALLOW remains current.

**Stale policy after wakeup**

A wakeup under a superseded policy hash cannot reuse the old basis to create a new effect unless the trusted profile explicitly declares compatibility.

**Process-local clock reset**

A process-local monotonic counter that resets on restart cannot be compared to a pre-restart value unless the profile binds it to a persistent/boot identity that makes the comparison meaningful.

**Provider-enforced deadline**

A request locally emitted before the deadline but accepted after it satisfies the deadline only if the provider contract says so. Local send time alone is insufficient.

**Next mutation after authority expiry**

Observation/reconciliation may remain permitted under its own authority, but a new mutation requires current authority.

**Old adapter semantics after rollout**

An old permit/basis cannot be applied to a materially changed adapter default/version without an explicit compatibility decision.

### 13.13 Required positive examples

**Reuse still-valid bound evidence**

An immutable signed artifact may be reused without reacquisition when its identity/signature remains valid and all current-state/temporal dependencies required by the profile still pass.

**Refresh expired dependency**

If an assumption/evidence/authority dependency has expired, the system may obtain a fresh replacement and construct a new current DecisionBasis for the same ActionIdentity only if the current ActionRevision and all required bindings are re-established.

**Reject wrong revision**

A fresh authority artifact does not rescue a stale ActionRevision. Revision and authority are separate predicates.

**Continue observation after start-grant expiry**

When one bounded external job was accepted while start authority was valid, its provider status may still be observed after that authority expires if the profile permits observation and no new effect is created.

### 13.14 K03 completion rule

K03 is complete only when every continuation path identifies:

- the next effect boundary, if any;
- the relevant clock/epoch domains;
- each dependency that must still be current;
- the exact revalidation owner/mechanism;
- the revocation view and its partition/staleness limits;
- the policy/adapter version interpretation;
- whether an accepted external operation may continue independently;
- the distinction between observation and a new effect.

K03 fails if the specification permits:

- wakeup/callback/restart to imply permission;
- exact-expiry reuse;
- stale authority to create a new effect;
- a hard destination precondition to be replaced by an old observation;
- acceptance-time guarantees inferred only from local send time;
- a superseded policy/adapter to reinterpret an old decision silently;
- process-local clock reset to extend prior authority.

Rollback/containment is to retain read/observation/reconciliation behavior where authorized while suspending new effects until required current witnesses can be established.

## 14. K04 truthful closure and UNKNOWN disposition contract

### 14.1 ClosureObligation

A **ClosureObligation** answers:

> What outcome knowledge must still be acquired, retained or explicitly dispositioned for this ActionRef / EffectIdentity before the responsible owner may stop active investigation?

A ClosureObligation references, where applicable:

- exact ActionRef revision;
- one or more EffectIdentity values and their ExecutionAttempts;
- DecisionBasis / permit / policy references needed to interpret the effect;
- destination/provider/account/tenant scope;
- trusted versioned Closure Profile;
- typed OutcomeObservation / postcondition records;
- evidence-acquisition horizon and stop conditions;
- current custody owner;
- disposition authority;
- minimum retained evidence needed to support the final claim;
- any continuing external work or residual exposure.

The serialization remains domain-owned.

ClosureObligation is a relation over existing domain facts. It is **not** a universal outcome object or shared closure service.

### 14.2 Knowledge and administrative disposition are different axes

K04 preserves at least these distinctions:

```text
request/provider acceptance
!=
observation obtained
!=
intended postcondition verified
!=
causal attribution
!=
administrative retirement
```

A domain may represent them with its own types and richer facts.

Examples:

- a provider may have accepted a request while the intended postcondition remains UNKNOWN;
- the intended postcondition may be VERIFIED while the uncertain request's causal contribution remains unknown;
- a case may be administratively retired as terminal UNKNOWN without becoming success;
- a compensation may complete while the original effect remains historically real;
- an ordinary verified success may discharge automatically without a manual case.

A receipt is a **derived view** of underlying admission/attempt/observation records. Its existence cannot strengthen the knowledge those records support.

### 14.3 Closure Profiles

A **Closure Profile** is trusted, versioned domain policy that defines:

- what observations/postconditions are sufficient for routine discharge;
- which evidence sources/observers may be used;
- the bounded acquisition horizon;
- what counts as partial, contradictory or unavailable evidence;
- whether continuing external work is allowed at retirement;
- who may authorize terminal UNKNOWN;
- retention/access requirements after disposition;
- late-evidence handling;
- consequence-specific escalation requirements.

The requester cannot choose a weaker Closure Profile merely to retire its own uncertainty.

For higher-consequence actions, the same actor that requested or executed the effect cannot be treated as sufficient residual-risk authority unless the trusted profile explicitly assigns that authority.

### 14.4 Typed outcome knowledge remains domain-owned

K04 does not define one common enum.

It requires domain facts sufficient to distinguish the knowledge needed by the selected Closure Profile.

Possible dimensions include:

- dispatch / acceptance knowledge;
- observer availability and identity;
- exact target identity;
- postcondition facts;
- stable versus contradictory observation;
- partial application;
- continuing provider job state;
- compensation facts;
- causal-attribution limits;
- evidence timestamp/horizon;
- provenance/integrity of the observation.

A domain result such as EEP `PARTIAL`, Kubernetes `DIVERGED`, or WFL `UNVERIFIED_RECOVERY` must not be flattened into a generic success/failure bit.

### 14.5 Routine automatic discharge

A ClosureObligation may discharge automatically when the trusted Closure Profile has sufficient evidence.

No manual ticket is required merely because the kernel contract contains ClosureObligation.

A routine discharge requires:

1. the observation applies to the exact ActionRef / EffectIdentity scope;
2. the observer/postcondition profile is the expected trusted version;
3. the claimed result does not exceed the evidence;
4. required evidence is still accessible/retained;
5. no continuing external effect requires separate custody;
6. any residual facts required by the profile are explicitly retained.

Examples include:

- verified already-satisfied no-op;
- stable intended-postcondition verification;
- a completed bounded operation whose declared postflight facts all match.

Routine discharge does not imply that every real-world consequence is known.

### 14.6 Accepted is not verified

Provider/API acceptance proves only the profile-specific acceptance claim.

It does not independently prove:

- the intended postcondition;
- downstream completion;
- lack of partial side effects;
- absence of later divergence;
- causal attribution to this executor.

Therefore:

```text
HTTP 2xx / provider accepted / dispatch receipt
!=
verified intended outcome
```

A Closure Profile that requires intended-postcondition verification cannot discharge on acceptance alone.

### 14.7 Observation and verification

An **OutcomeObservation** supports only the claims its observer/profile can establish.

Verification requires exact scope and the domain's typed postcondition semantics.

An unrelated state change cannot satisfy a requested effect.

For example:

- a changed whole-object digest is not evidence that the requested CRM fields match;
- a successful rerun at the workflow level is insufficient when the profile requires the same failed step to have been genuinely re-executed;
- a Kubernetes node report is insufficient if exact expected Pod UID effects are not observed.

If the observation applies to the wrong target, wrong account, wrong revision or wrong profile version, it cannot discharge the obligation.

### 14.8 Partial outcomes and residual effects

Partial facts remain first-class domain facts.

A partial outcome may mean:

- some intended fields are satisfied and others are not;
- some planned effects completed and others remain;
- a recovery succeeded for some targets but not all;
- compensation covered part of the residual exposure.

K04 forbids collapsing these facts into a universal terminal state.

The Closure Profile must specify:

- which residual effects remain owned;
- whether further observation is required;
- whether new mutation authority is needed;
- whether compensation is permitted;
- whether terminal UNKNOWN retirement is allowed.

A disposition that retires one administrative case does not erase the remaining effect history.

### 14.9 Evidence horizon

Every non-trivial Closure Profile defines a bounded **evidence horizon** or another explicit stop condition.

The horizon answers:

> How long / how many attempts / under what provider-history window is active observation required before policy may decide that stronger knowledge is no longer reasonably obtainable?

The horizon is domain-specific.

Examples can include:

- bounded repeated reads;
- provider operation terminality;
- a provider-history retention window;
- a checkpoint/recovery reconciliation cycle;
- an explicitly authorized manual review deadline.

K04 does not require infinite investigation.

It also does not allow the owner to stop merely because observation became inconvenient.

### 14.10 Terminal UNKNOWN

**Terminal UNKNOWN** is an administrative disposition, not an epistemic upgrade.

It is permitted only when the trusted Closure Profile and its authorized residual-risk owner allow it.

At minimum, terminal UNKNOWN requires:

1. the exact ActionRef / EffectIdentity / attempt lineage is retained;
2. the evidence horizon or authorized stop condition has been reached;
3. all obtainable observations and contradictions are retained without manufacturing a stronger claim;
4. remaining external work is either:
   - known not to be continuing, or
   - explicitly bounded and still under named custody;
5. no unsafe replay/right-to-repeat is inferred from the UNKNOWN disposition;
6. required evidence/payload references remain retained for the declared policy period, or their unavailability is itself recorded;
7. the disposition authority is identified and independent enough for the selected consequence profile;
8. downstream consumers are told that knowledge remains UNKNOWN.

Terminal UNKNOWN may end **active investigation**.

It does not mean:

- success;
- failure;
- safe retry;
- safe budget/resource release;
- absence of external work;
- permission to delete effect history.

### 14.11 Continuing external work at retirement

A closure case may be administratively retired while a provider job continues only if the Closure Profile explicitly permits that arrangement.

Required conditions include:

- continuing job/effect identity is fixed;
- its expected bounds are known;
- custody owner is named;
- future observation/access expectations are stated;
- no second equivalent effect is automatically created;
- the disposition does not claim the external work stopped.

If these conditions cannot be met, retirement cannot orphan the continuing effect.

### 14.12 Custody transfer

Closure custody may transfer from one owner to another.

Transfer must preserve:

- ClosureObligation identity;
- effect/attempt lineage;
- current knowledge facts;
- unresolved contradictions;
- retained evidence references;
- evidence horizon status;
- continuing external work;
- prior disposition history.

The receiver accepts responsibility before the prior owner may relinquish it.

Transfer cannot manufacture success or reset UNKNOWN to a blank state.

### 14.13 Evidence retention and access

A claim is only as durable as the evidence needed to support it.

The selected Closure Profile must state the minimum retained evidence/access needed for its claims.

Depending on the domain this may include:

- exact action/effect/attempt identifiers;
- provider operation/run/job identifiers;
- checkpoint and journal records;
- observation/postcondition payload digests;
- enough payload or provider-access capability to re-evaluate the claimed postcondition;
- profile/version identity;
- timestamps/horizon metadata;
- custody/disposition authority records.

K04 does not require retaining secrets in plaintext.

Redaction is allowed when the retained representation still supports the promised verification.

If a required payload is deleted or provider history expires, the system must narrow future claims accordingly.

Expired/missing evidence cannot be replaced by a stronger summary label.

### 14.14 Provider-history expiry

If the only remaining observer/provider history disappears before closure is supported:

- record that the evidence source is no longer available;
- preserve the last justified knowledge state;
- do not convert UNKNOWN to NOT_APPLIED or success;
- apply the Closure Profile's escalation/terminal-UNKNOWN policy;
- retain enough identity/custody metadata to prevent blind replay.

Provider-history expiry is itself a closure fact.

### 14.15 Late evidence and correction

Late evidence never rewrites history.

The append-only semantic model is:

```text
observation/disposition at time T1
+
late observation at T2
+
new derived current view
```

The earlier event remains part of history.

Examples:

- terminal UNKNOWN at T1, then verified outcome at T2;
- VERIFIED at T1, then later domain divergence at T2;
- PARTIAL at T1, then compensation evidence at T2.

The new evidence may update the **current knowledge projection** according to the Closure Profile.

It does not erase the fact that the system previously operated under uncertainty.

### 14.16 Contradictory observations

Contradiction is not resolved by choosing the convenient observer.

When trusted observations conflict:

- retain both observations and their provenance;
- mark the stronger claim unsupported until the domain profile resolves the contradiction;
- continue or escalate the ClosureObligation according to policy;
- prohibit success if success requires facts that are currently contradicted.

If the evidence horizon ends while the contradiction remains unresolved, terminal UNKNOWN may be authorized under the normal K04 conditions.

### 14.17 Compensation

Compensation is a new domain fact/effect, not retroactive erasure.

K04 requires the history to retain:

- the original effect;
- the original known/unknown outcome;
- the compensating action/effect identity;
- compensation observation/postcondition;
- any residual exposure that remains.

A successful compensation may satisfy a domain Closure Profile without changing history to "the original effect never happened."

K04 does not require automatic compensation.

### 14.18 Retired UNKNOWN downstream semantics

A retired UNKNOWN remains UNKNOWN to later decision logic.

In particular, retirement cannot be interpreted as:

- successful completion;
- proof that repeating the effect is safe;
- proof that no resource/financial commitment remains;
- proof that a provider operation stopped;
- permission to discard idempotency/custody records.

A downstream budget/resource owner must use its own policy for UNKNOWN exposure; K04 does not create a universal resource-settlement algebra.

### 14.19 CE5 — permanent observation gap

When observation cannot be recovered within the authorized horizon:

```text
do not manufacture success
do not manufacture safe retry
retain effect identity + custody + last evidence
apply trusted UNKNOWN disposition policy
```

If residual external work cannot be bounded or owned, terminal retirement is not allowed.

### 14.20 CE7 — unrelated change as success

A domain oracle must evaluate the intended scoped postcondition, not merely "something changed."

Examples:

- unrelated CRM timestamp change cannot establish the requested patch;
- an unrelated successful CI job cannot prove the failed operation recovered;
- an unrelated Kubernetes object change cannot prove the planned effect.

A Closure Profile that permits unrelated change to satisfy the intended effect fails K04.

### 14.21 Requester self-retirement

The requester/executor cannot unilaterally retire high-consequence uncertainty merely because it prefers progress.

The trusted Closure Profile identifies the disposition authority.

For profiles where self-disposition is acceptable, that fact must be explicit and consequence-bounded.

Absent such an assignment, requester self-retirement of unresolved high-consequence effects fails closed.

### 14.22 Required examples

**Routine automatic discharge**

Exact target + trusted profile + sufficient stable intended-postcondition evidence -> obligation discharged without manual review.

**Verified scoped postcondition**

Provider acceptance may be UNKNOWN while the exact intended postcondition is VERIFIED. The closure claim is the verified state claim, not causal certainty.

**Partial result**

Some domain postconditions hold, others do not. The obligation retains residual effects and does not emit success.

**Authorized terminal UNKNOWN**

Evidence horizon exhausted + no stronger knowledge + residual work bounded/custodied + authorized disposition -> active investigation may retire as UNKNOWN.

**Late evidence**

A later observation is appended and may change the current knowledge projection. The earlier UNKNOWN retirement remains historical fact.

### 14.23 K04 completion rule

K04 is complete only when each domain seed identifies:

- its Closure Profile / policy owner;
- what exact evidence supports routine discharge;
- typed acceptance/observation/postcondition facts;
- evidence horizon or explicit stop condition;
- closure custody owner and transfer rule;
- minimum evidence retention/access;
- terminal UNKNOWN authority and conditions;
- continuing external-work treatment;
- late evidence/correction behavior;
- partial/compensation semantics where applicable.

K04 fails if the specification permits:

- false success;
- UNKNOWN -> safe retry;
- orphaned continuing work;
- unbounded and unowned investigation;
- deletion of required evidence while preserving a stronger claim;
- contradiction to be silently ignored;
- a domain to erase partial facts merely to fit a shared enum.

Rollback/containment is to leave the obligation active or explicitly transfer it, pause affected new effects when residual exposure exceeds policy, and preserve observation/effect history.

## 15. K05 normative oracle and change control

The draft normative oracle is published in:

- [normative-vectors-and-change-control-v1.md](normative-vectors-and-change-control-v1.md)
- `testdata/governed-action/v1/schema.json`
- `testdata/governed-action/v1/normative-cases.json`
- `testdata/governed-action/v1/change-control-cases.json`
- `testdata/governed-action/v1/change-log-template.json`

The normative case set is:

```text
governed-action.normative-cases/v1
status = DRAFT_UNFROZEN
```

It contains:

- rejected CE1–CE12 traces;
- one useful positive counterpart for each CE case;
- positive CI, Kubernetes and EEP seed traces;
- explicit source assumptions;
- expected observations/dispositions;
- invariant or domain-rule rationale for every rejected trace.

The meta-level `valid_trace` value answers only whether a trace is permitted by this candidate contract under the stated typed assumptions/profile. It does not replace domain-owned outcome semantics.

K05 also records these change-control rules:

1. unknown normative/profile versions are not silently accepted;
2. a caller cannot downgrade the same enforced action class to weaker obligations;
3. one case ID cannot have contradictory expected validity in the same normative version;
4. changing a core relation or accepted/rejected trace meaning is a **normative core change**;
5. a purported clarification that changes `valid_trace` is normative;
6. an implementation fix that moves code toward an unchanged oracle is not a normative change;
7. a new typed domain policy/profile can remain policy-only only when the existing extension relation already permits it and the same old profile/version answer is unchanged.

K07, not K05, owns full executable cross-adapter conformance. The K05 validator checks fixture/version/change-control consistency without pretending that a parsed JSON vector proves real destination enforcement.

## 16. Six-concept / five-family review

| Concept / family | K01 status | Seed review obligation |
|---|---|---|
| ActionIdentity | defined | seed has stable logical proposal identity |
| ActionRevision | defined | material target/account/semantic changes create or select a distinct revision |
| DecisionBasis | defined | all mandatory dependencies are typed and owned |
| EffectIdentity | defined by K02 | seed declares domain effect cardinality and reconstructable effect identity |
| ExecutionAttempt | defined by K02 | seed declares attempt identity, custody, crash windows, retention and destination enforcement scope |
| ClosureObligation | defined by K04 | seed declares closure profile, typed observations, evidence horizon, custody, retention and truthful disposition |

The domain mapping is recorded in [domain-profiles-v1.md](domain-profiles-v1.md).

## 17. CE1 / CE2 / CE9–CE12 adversarial obligations owned by K01

### CE1 — Vacuous profile

Reject a trace where the requester can choose:

- an empty mandatory-predicate set;
- an unknown profile version;
- a caller-owned validator as trusted;
- a weaker profile for the same enforced action class.

A legitimate trusted profile with no unnecessary external-evidence requirement remains valid when its trusted owner explicitly defines that smaller requirement set.

### CE2 — revision / approval substitution

Approval or basis for revision A must not admit materially changed revision B.

Material drift includes, where applicable:

- principal;
- target;
- account / tenant;
- action;
- resource revision;
- evidence reference;
- adapter/effect/postcondition semantics;
- required profile or validator version.


### CE9 — Trusted but inadequate profile

A profile can be trusted, correctly selected and internally satisfied yet still omit a known decision-relevant distinction. Such a trace is not automatically admissible merely because every listed predicate passed. If the omission leaves two modeled states indistinguishable to DecisionBasis while they require opposite admissibility decisions, automatic ALLOW is invalid until the distinction is bound, discharged by a typed guard/validator, or retained as an unresolved critical defeater.

### CE10 — Model-relative evidence independence

Evidence independence is evaluated only relative to the declared failure/dependency model and material dependency coverage of the selected profile. A label count is never independence. Required independence that is UNKNOWN or violated cannot satisfy admission. A genuinely hidden common cause outside the declared model is an assumption breach outside the logical guarantee, not evidence that the kernel had access to absent information.

### CE11 — Consequence-relevant state omitted or stale

When a known state distinction can change admissibility, omitting it from DecisionBasis/StateBinding reduces to CE9. When it is bound but stale, K03 requires it to be re-established at the next effect boundary. I3 is not expanded merely to restate those K01/K03 duties.

### CE12 — Enforcement assumptions and TCB boundary

A correct DecisionBasis is insufficient if the claimed enforcing boundary is not actually mediated under the declared enforcement-integrity assumptions. Missing complete-mediation or enforcement-integrity assumptions make automatic ALLOW unsupported. An actual compromise of the TCB/enforcer after those assumptions were declared is outside the logical guarantee rather than evidence for a seventh recursive-trust primitive.

## 18. Seed references

K01 composes existing versioned contracts rather than replacing them:

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

Their domain meaning and current owners remain intact.

## 19. K01 completion rule

K01 is complete only when every design seed has:

- one unambiguous trusted Admission Profile selection path;
- one bound ActionRef interpretation;
- a complete typed DecisionBasis;
- identified use-time validator owners;
- explicit account/tenant/singleton handling;
- explicit adapter/effect/postcondition version handling;
- hard preconditions distinguished from observations;
- a documented invalidation story for revision/profile/dependency changes.

K01 fails if completion requires:

- arbitrary authorization booleans;
- erasing domain-specific meaning;
- a caller-selectable weak profile;
- a new core discriminator beyond the fixed candidate concepts.

This document is frozen by the K06 manifest and freeze record. Any trace-affecting semantic change requires a new normative version and a new freeze.
