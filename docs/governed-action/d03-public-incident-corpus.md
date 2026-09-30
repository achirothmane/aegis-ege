# D03 support track — public incident corpus

Status: **ACTIVE CORPUS — EVIDENCE ONLY**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

This corpus is a parallel falsification track for real incidents that happened in
independently owned public repositories and were later resolved with enough
evidence to reconstruct:

```text
observed signal
→ original ambiguity
→ corrected ground truth
→ repair
→ gate lesson
```

It is useful because CI Retry Gate and the governed-action kernel can be checked
against real failure/recovery histories without waiting for a maintainer reply.

It does **not** satisfy D03's independent-participant requirement. Public incident
replay is external evidence, but it is not the same thing as an independent
maintainer implementing and owning a held-out cohort after the contract freeze.

## Corpus rule

A case is admissible only when the source repository provides enough public
evidence to distinguish observation from the later established cause. A simple
"failed, reran, passed" event is insufficient.

The corpus must preserve counterexamples. In particular:

```text
rerun_passed != flaky_test
rerun_passed != application_failure
```

The gate must decide from retained execution evidence, not from the fact that a
rerun later became green.

## Case PIC-0001 — daniel-ospina/tortoise #3442

Source issue: https://github.com/daniel-ospina/tortoise/issues/3442  
Resolution PR: https://github.com/daniel-ospina/tortoise/pull/5474  
Merged resolution: `1917852e17ffe741f37ca419c2c433c741112159`

### Observed signal

The required `python-ci / changes` job failed on run `34748148065`, job
`103701145755`. Re-running the failed work on the same head/diff passed.

The original issue correctly treated the event as ambiguous because the failing
job had no retrievable logs or step breakdown.

### Corrected ground truth

The merged resolution records that the failing job executed zero steps and never
acquired a runner:

- `steps: []`;
- empty `runner_name`;
- `runner_id: 0`;
- the check-run annotation said the job repeatedly failed to be acquired after
  five attempts.

The rerun acquired a runner and completed successfully. Therefore the observed
failure was a runner-acquisition/infrastructure failure, not evidence that a test
or selector was flaky.

For CI Retry Gate, this is a bounded rerun candidate **only when zero execution
is positively established**. The evidence is not "rerun passed"; the evidence is
"the failed attempt never began executing user steps."

### Secondary defect discovered by the repair

The investigation also found a real workflow defect in the changed-set
derivation:

```text
git diff "$BASE...HEAD" || git diff "$BASE" HEAD
```

The fallback asks a different question, and a swallowed failure could leave an
empty changed set that mapped to a smaller smoke suite while still allowing a
green result.

PR #5474 replaced that behavior with one canonical merge-base diff, an
absent-base guard, and an empty-changed-set guard. Its recorded verification
included 182 passing tests plus mutation checks for the new workflow pins.

This yields a second gate lesson:

```text
diff unavailable / invalid / unexpectedly empty
→ do not silently reduce coverage
→ HOLD / BLOCK / fail closed
```

## Gate interpretation

PIC-0001 contributes two distinct classifications:

1. **Runner acquisition failure** — retry may be admissible when retained
   evidence proves no user step executed and no side effect could have occurred.
2. **Changed-set derivation uncertainty** — retrying or accepting a green result
   is not sufficient; the evidence basis itself is invalid, so certification must
   fail closed until the diff is computed canonically.

The case must never be simplified to:

```text
FAIL → rerun PASS → flaky
```

## Relationship to D03

This corpus improves falsification pressure while D03 recruitment remains
blocked. It can reveal bad assumptions in the frozen contract or adapters, but
it does not change the D03 readiness state and does not create a
held-out-generalization claim.

```text
public incident corpus = external replay evidence
D03 = independent held-out implementation + maintainer-owned cohort
```

Both are valuable; they prove different things.
