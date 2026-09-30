# Governed Action Kernel v1 — normative vectors and change control

Status: **DRAFT / UNFROZEN**  
Queue item: **K05 — Publish normative examples and change control**  
Normative case-set version: `governed-action.normative-cases/v1`

This document turns the K01–K04 prose contract into reviewable normative examples without creating an executable challenge platform. K07 owns full cross-adapter execution after K06 freezes the baseline.

## 1. Normative artifacts

The K05 oracle consists of:

- `docs/governed-action/kernel-v1.md` — concepts, invariants and relations;
- `docs/governed-action/domain-profiles-v1.md` — design-visible CI, Kubernetes and EEP mappings;
- `testdata/governed-action/v1/schema.json` — fixture-shape identifier;
- `testdata/governed-action/v1/normative-cases.json` — CE1–CE8 rejected traces, paired positive counterparts and positive seed traces;
- `testdata/governed-action/v1/change-log-template.json` — mandatory record shape for trace-affecting changes;
- `testdata/governed-action/v1/change-control-cases.json` — normative examples for change classification.

K05 does **not** freeze these files. K06 records their immutable hashes and reviewed source heads.

## 2. Meta-oracle meaning

Each normative case has one meta-level field:

```text
valid_trace = true | false
```

This field answers only:

> Is this trace permitted by the candidate Kernel v1 contract under the stated source assumptions and typed domain profile?

It is **not** a universal outcome enum.

Domain facts remain domain-owned, for example:

- CI dispatch acceptance versus validated recovery;
- Kubernetes `MATCH / DIVERGED / UNKNOWN`;
- EEP request acceptance, observation quality and `VERIFIED / PARTIAL / UNSATISFIED / UNKNOWN / ALREADY_SATISFIED`.

The case's `expected.disposition` is a review label describing the contract treatment of that trace. It is not a runtime wire protocol.

## 3. Case ID rules

Case IDs are normative identifiers within `governed-action.normative-cases/v1`.

- `CE<n>-R...` — rejected counterexample trace.
- `CE<n>-A...` — accepted positive counterpart.
- `SEED-...` — design-visible useful positive seed.

An ID must have exactly one expected `valid_trace` value within the same case-set version.

Publishing the same case ID with contradictory expected validity is an invalid oracle.

Changing a case's expected validity after K06 is a normative core change and requires a new normative version/freeze. It cannot be called an editorial clarification.

## 4. CE1–CE8 oracle rationale

| Case | Rejected trace | Positive counterpart | Primary invariant / domain rule |
|---|---|---|---|
| CE1 — Vacuous profile | requester chooses empty/weaker obligations or its own trusted validator | owner-selected legitimate trusted profile passes with all required predicates | I2 / trusted-profile semantics |
| CE2 — Approval/revision drift | approval for revision/account/target A admits material B | still-valid exact-scope basis may be reused for unchanged revision | I1 / I4 |
| CE3 — Timeout then provider substitution | provider A may have committed, then equivalent B effect is dispatched without safe substitution proof | preserve A as possible effect and reconcile without a second mutation | I3 / I5 |
| CE4 — Effect before journal | effect escapes before recoverable custody | durable effect/attempt custody exists before dispatch | I5 |
| CE5 — Permanent observation gap | UNKNOWN becomes success/safe retry or custody is dropped | bounded authorized terminal UNKNOWN retains truthful uncertainty and custody | I5 / I6 |
| CE6 — Takeover race / stale worker | local ownership transfer is treated as downstream fencing | effective destination fencing/CAS exists, or conflicting takeover remains blocked | I3 / I5 |
| CE7 — False outcome | unrelated state change becomes VERIFIED/APPLIED | exact scoped intended postcondition is observed | I6 / domain postcondition |
| CE8 — Current read / stale write | stale read is treated as atomic authorization without required CAS | destination atomically enforces the bound version and useful mutation proceeds | I1 / I2 |

Every rejected case names at least one violated invariant or typed domain requirement.

Every CE also has a positive permitted counterpart so deny-all behavior cannot satisfy the oracle.

## 5. Positive seed applicability

### CI / Workflow Failure Lab

The seed demonstrates:

- trusted profile selection;
- exact repository/run-attempt/head/workflow/job binding;
- current temporal/authority basis;
- one bounded rerun dispatch;
- dispatch receipt kept distinct from downstream result;
- later same-failed-step recovery evidence when closure requires it.

The seed does not claim GitHub provides provider-independent exactly-once execution.

### Kubernetes / Aegis

The seed demonstrates:

- exact drain plan/effect identity;
- current authority and target revision;
- bounded cordon/eviction effects;
- checkpointed custody;
- exact Pod UID reconciliation;
- postflight `MATCH` under the current domain oracle.

The seed does not claim the Kubernetes Lease fences arbitrary writers.

### EEP synthetic CRM

The seed demonstrates both:

1. a destination-guarded `If-Match` PATCH followed by stable exact-field verification;
2. an already-satisfied no-op that dispatches no PATCH.

The seed does not claim a local attempt ID is provider deduplication.

## 6. Immutable source references used by K05

K05 records these reviewed source identities in the case-set data:

- Aegis integrated K01–K04 base: `6130e941437bc005ccc94006f9ff277edbcebd2f`;
- WFL main: `d44bd4c47f8748bfca706a4c4833adf8ce940cf6`;
- EASL main: `7c4e1e28218853919d00362dc071e1eb6f61cc56`;
- WFL temporal vector blob: `0a161956b19e16d6adaaf3fa2cbeb453a7ddbcc3`;
- WFL canonical JSON vector blob: `99b13dbb634e3894aa6610c70e1f9820fc1c73d8`;
- StateBinding corpus blob in EASL and vendored WFL copy: `82d151531da6f98262de1e247658d89a8299c53c`;
- Aegis C06 reviewed head: `292a2faadb8e12d6f24b8b1064e62ba90fe33110`;
- Aegis C07 reviewed head: `3f1342749d0b83b3ef505f41e7f7d01b7070b548`.

K06 must verify that the final integrated freeze still corresponds to the cited prerequisite evidence. K05 does not treat a moving branch name as immutable evidence.

## 7. Contract and profile version handling

### Known exact version

A consumer may interpret a normative artifact only under an exact version whose semantics it knows.

```text
known exact version  -> evaluate under that version
unknown version      -> reject / unsupported
silent fallback      -> forbidden
```

### Profile downgrade

A requester cannot ask the same enforced action class to reinterpret an old decision under a weaker profile version.

A trusted owner may introduce a separately authorized typed profile when the frozen extension rules permit it, but that new profile is a different input. It cannot change the answer for the same old profile/version input.

### Read compatibility versus authorizing compatibility

Historical artifacts may remain readable without remaining authorizing.

Readability is not permission to use an obsolete profile for a new effect.

A migration that accepts old bytes for inspection but refuses them at an authorizing boundary is compatible when the old contract already permits that treatment.

## 8. Change classification

### Implementation-only fix

An implementation-only change:

- changes code or adapter behavior to match the existing frozen oracle;
- does not change a core relation;
- does not change `valid_trace` for the same case/profile/source assumptions;
- does not add a hidden mandatory shared obligation.

Example: adding the missing `If-Match` header because the frozen profile already required destination CAS.

### Policy / profile specialization

A policy/profile-only change is permitted when:

- the frozen contract already defines the extension point;
- the new typed profile is selected by its proper trusted owner;
- its authority, inputs and consequences are explicit;
- it does not reinterpret the same old profile/version input;
- it does not weaken I1–I6.

### Normative core change

A change is normative when it changes any of:

- a core concept/relation meaning;
- which trace is accepted or rejected for the same interpretation/profile;
- a mandatory boundary relation;
- a previously unstated rule added to make a failing case pass;
- the meaning of an existing predicate/profile field;
- an accepted/rejected case expectation.

**Normative core change dominates all other labels.**

A change can be schema-compatible and still be normative.

A change presented as a "clarification" is normative if it changes valid-trace acceptance.

## 9. Required change record

Every trace-affecting proposal uses the change-log template and records:

- prior normative version;
- proposed version;
- affected case/profile IDs;
- failing or motivating trace;
- old rule / new rule;
- whether valid-trace acceptance changes;
- whether a core relation changes;
- implementation/policy/adapter/Domain Pack flags;
- adjudicated classification;
- design-visible cohort consequences;
- reviewer attribution.

No invented approval is allowed.

## 10. Adversarial K05 rules

The K05 fixture validator and semantic review must reject:

- unknown case-set/schema version;
- contradictory expected verdicts for one case ID;
- a rejected case with no violated invariant/domain rule;
- a caller-selected empty mandatory requirement set presented as valid CE1 behavior;
- a profile downgrade presented as silent compatibility;
- a "clarification" that changes accepted/rejected meaning while retaining the same normative identity.

## 11. Oracle versus implementation defect

Use this decision rule:

```text
implementation violates unchanged published oracle
=> implementation/profile defect

published oracle lacks a rule needed to reject/accept the trace
or expected valid_trace must change
=> normative change
```

Do not edit the expected result merely to make a later implementation pass.

After a normative redefinition, a case/cohort that caused the redefinition is design-visible and cannot later count as held-out evidence for that revised core.

## 12. Freeze boundary

Until K06 records exact hashes and prerequisite evidence:

- this contract remains **DRAFT / UNFROZEN**;
- no held-out score may be claimed against it;
- no conformance result may rely on a moving branch identity;
- K07 executable cross-adapter coverage has not yet been performed.

K05 publishes the oracle. K06 freezes it. K07 executes it.
