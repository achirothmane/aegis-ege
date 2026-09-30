# K07 — Executable frozen conformance and counterexample vectors

Status: **DESIGN-VISIBLE CONFORMANCE HARNESS**  
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
shares with the frozen generic/CI slice. K07 is complete only after its Python
runner executes the shared frozen case IDs from a pinned copy of the K07
execution fixture and agrees with the Go result for that shared scope.

The Python runner does not claim ownership of Kubernetes/EEP domain semantics.

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
