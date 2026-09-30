# Candidate Governed-Action Kernel v1 — K01 contract

Status: **DRAFT / UNFROZEN**  
Queue item: **K01 — Define revision, basis and trusted profile bindings**  
Normative scope: **K01 only**. K02–K05 remain unresolved and must not be inferred from this document.

This document defines the smallest shared relations needed to bind an exact consequential action proposal to the typed basis used to admit it. It does **not** create a kernel service, identity service, policy engine, action catalog, universal evidence schema, scheduler, workflow runtime, or generic authorization token.

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

K01 does not define effect/attempt custody or closure semantics:

- EffectIdentity and ExecutionAttempt relations are reserved for **K02**.
- temporal continuation semantics are reserved for **K03**.
- ClosureObligation knowledge/disposition semantics are reserved for **K04**.
- accepted/rejected normative vectors and frozen change control are reserved for **K05/K06**.

No implementation may claim K02–K05 semantics merely because it conforms to this K01 document.

## 2. Governing invariant slice

K01 directly supports these candidate-kernel invariants:

- **I1 — Binding integrity:** admission cannot silently change action revision, subject, destination, account, or material semantics.
- **I2 — Valid admission at the actual effect boundary:** mandatory typed predicates and scoped authority must hold at the declared enforcing boundary.
- **I3 — No implicit authority amplification:** the admitted basis cannot silently enlarge principal, scope, destination, account, tenant, credential audience, adapter semantics, or effect cardinality.

K01 also establishes the exact dependency references that K03 must later revalidate for I4. It does not by itself establish I4–I6.

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

## 12. Six-concept / five-family review

| Concept / family | K01 status | Seed review obligation |
|---|---|---|
| ActionIdentity | defined | seed has stable logical proposal identity |
| ActionRevision | defined | material target/account/semantic changes create or select a distinct revision |
| DecisionBasis | defined | all mandatory dependencies are typed and owned |
| EffectIdentity | reserved for K02 | seed identifies the domain mechanism that will later supply effect identity |
| ExecutionAttempt | reserved for K02 | seed identifies current attempt/journal mechanism without standardizing it here |
| ClosureObligation | reserved for K04 | seed identifies current outcome/observation owner without claiming K04 closure |

The domain mapping is recorded in [domain-profiles-v1.md](domain-profiles-v1.md).

## 13. CE1 / CE2 adversarial obligations owned by K01

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

## 14. Seed references

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

## 15. K01 completion rule

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

This document remains **unfrozen** until K02–K05 complete and K06 records the freeze.
