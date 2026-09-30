# K07 — Executable frozen conformance and counterexample vectors

Status: **COMPLETE — frozen design-visible conformance**  
Frozen contract: `candidate-kernel-contract-v1`  
Frozen normative oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

K07 executes the K06-frozen oracle. It does not redefine it.

## Scope

The local Go harness executes every frozen case ID from
`testdata/governed-action/v1/normative-cases.json` through structured,
deterministic test inputs in:

`testdata/governed-action/k07/executable-cases.json`

The harness:

- requires exact case-ID equality with the 28 frozen traces;
- pins the frozen oracle by Git blob identity;
- derives validity/disposition from structured boundary conditions rather than
  copying `valid_trace` into the evaluator;
- asserts every rejected trace emits zero new effects;
- exercises useful positive behavior so deny-all cannot pass;
- retains ActionRef and, where an effect exists, EffectIdentity /
  ExecutionAttempt evidence;
- retains typed domain observations for CI, Kubernetes and EEP seeds;
- executes deterministic finite fault schedules for the principal crash,
  ambiguity, takeover, stale-write, outcome and independence cases.

## Frozen case coverage

| Frozen case family | Executable condition |
|---|---|
| CE1 | trusted profile selection |
| CE2 | exact revision/current basis |
| CE3 | possible effect + unsafe substitution |
| CE4 | custody before dispatch |
| CE5 | truthful UNKNOWN disposition/custody |
| CE6 | takeover with real fencing or blocking |
| CE7 | exact intended postcondition |
| CE8 | destination-enforced hard precondition |
| CE9 | trusted profile adequacy for the claim |
| CE10 | required model-relative evidence independence |
| CE11 | consequence-relevant state binding/currentness |
| CE12 | declared effect boundary + complete mediation |

Positive CI/Kubernetes/EEP seeds remain domain-typed. No universal outcome enum
or shared runtime is introduced.

## Deterministic fault schedules

The K07 fixture includes named schedules for:

- lost response after possible provider acceptance;
- crash before durable custody;
- permanent observation gap;
- stale worker after takeover;
- unrelated state change presented as success;
- stale-read/stale-write interleaving;
- unknown required evidence independence;
- undeclared enforcement boundary.

These are isolated/local conformance schedules. They are not real-substrate
evidence. D01 and D02 retain ownership of native GitHub/Kubernetes/EEP execution.

## Change-control boundary

A K07 failure may be fixed only by correcting an implementation/profile to the
unchanged frozen oracle.

If a failing trace requires changing:

- a frozen core relation;
- the same case ID's `valid_trace`;
- a frozen disposition meaning;
- a previously unstated rule needed to make the trace pass;

then K07 records a normative failure. The v1 oracle is not edited in place and a
new freeze is required before later held-out testing.

## Cross-language obligation

Workflow Failure Lab retains the Python compatibility owner for the semantics it
shares with the frozen generic/CI slice. Its Python runner now executes the
shared frozen case IDs from a byte-identical pinned copy of the K07 execution
fixture and agrees with the frozen oracle for that shared scope.

The Python runner does not claim ownership of Kubernetes/EEP domain semantics.

## Completion evidence

### Aegis / Go

- PR: `achirothmane/aegis-ege#84`
- exact reviewed head: `677699446ac641b3550926394ee1916d31e1b180`
- squash merge: `2b08f173d7e0dc7390b7ba9fec57ab10e28c48ba`
- CI run: `36667206044` — success
- unit job: success, including `go test ./...`
- integration/KinD job: success
- frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`
- K07 execution fixture blob:
  `89b971ab136d7b2c889c586429a803fec9587c0d`
- executed frozen cases: all 28, covering CE1–CE12 plus the four positive
  CI/Kubernetes/EEP seeds

### Workflow Failure Lab / Python

- PR: `achirothmane/workflow-failure-lab#113`
- exact reviewed head: `de9a28412750c57030b46b265e685df6fd757a8c`
- squash merge: `aabe4a04c4ea8857f448e148cb59e36efff6af8c`
- vendored oracle blob:
  `37e2e0a0867fa78df37f9d4243a1c4107d62094b`
- vendored execution fixture blob:
  `89b971ab136d7b2c889c586429a803fec9587c0d`
- shared generic/CI executable cases: 23
- CI run `36667574371`: success
- Compatibility Matrix run `36667574361`: success
- Remote v1 Consumer E2E run `36667574498`: success

### K07 completion decision

The mandatory design-visible frozen cases pass without changing the frozen
oracle or K01–K05 relations. Rejected traces produce zero new effects; positive
paths demonstrate useful permitted behavior or accountable safe containment;
domain observations remain typed.

Therefore K07 is complete for the scope required before D01/D02.

This is still not real-substrate D01/D02 evidence, independent D03 validation,
operator-value evidence, or a demonstrated platform kernel.

## What K07 does not prove

K07 does not establish:

- real GitHub rerun embedding;
- real Kubernetes crash/takeover guarantees;
- an external CRM provider's CAS behavior;
- independent implementation;
- held-out generalization;
- operator value;
- a demonstrated platform kernel.

Those remain D01–D06 work under the existing queue.
