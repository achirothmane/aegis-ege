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


## Case PIC-0002 — lidge-jun/opencodex #1563

Source issue: https://github.com/lidge-jun/opencodex/issues/1563  
Resolution PR: https://github.com/lidge-jun/opencodex/pull/1575  
Merged resolution: `be3597ff2db1c2941ff15d04f65f1bfc6389c4a3`

A single native-profile test on hosted macOS failed at `6016.60ms` against a
`6000ms` Bun harness deadline, while Linux CI and local macOS were clean and a
plain rerun of the identical commit passed.

The repair did **not** change product behavior. PR #1575 gave that test its own
10-second harness budget, left the product SQLite lock deadline and
`CODEX_BUSY` semantics unchanged, and recorded 5/5 focused passes under a
2-core limit.

Gate lesson:

```text
known harness-timeout signature
+ product behavior unchanged
+ no conflicting failure evidence
→ bounded rerun candidate

rerun pass alone
→ NOT sufficient to declare a test flaky
```

Classification: `TEST_HARNESS_TIMEOUT_MARGIN`.

## Case PIC-0003 — herdrdev/herdr #3451

Source issue: https://github.com/herdrdev/herdr/issues/3451  
Resolution PR: https://github.com/herdrdev/herdr/pull/3453  
Merged resolution: `69585b01d0297b50e302c98f883d705dec92834d`

The macOS job intermittently failed before the actual expiry assertion because
the fixture's metadata TTL was only **1 ms**. The first run could observe the
metadata after it had already expired; the rerun on the same commit passed.

PR #3453 changed the fixture TTL to 60 seconds and then advanced directly to the
captured deadline. The test therefore continued to verify expiry semantics
without depending on scheduler or wall-clock speed. The focused test then passed
100 consecutive runs.

Gate lesson:

```text
known fixture race signature
+ no product-failure evidence
→ bounded rerun candidate

same commit + rerun pass
→ still requires causal classification
```

Classification: `TEST_FIXTURE_WALL_CLOCK_RACE`.

## Case PIC-0004 — frappe/draw #546

Source issue: https://github.com/frappe/draw/issues/546  
Resolution PR: https://github.com/frappe/draw/pull/547  
Merged resolution: `affaabd607bfec327867d3c170b81bb2f9bfdf3d`

This case is a critical counterexample to the assumption that the same repository
commit means the same execution inputs.

Draw CI installed Frappe from the unpinned `develop` branch. Commit
`6ba7424` passed earlier, but after `frappe/frappe#41626` changed
`sanitize_html`, a rerun of that unchanged Draw commit failed. The local
repository tree did not change; an upstream dependency did.

The repair exempted the JSON document field from the HTML sanitizer and added a
regression test.

Gate lesson:

```text
same repository commit
≠ same dependency graph
≠ same execution environment

unpinned external input drift
→ HOLD
→ reconstruct or pin input provenance before classification
```

Classification: `ENVIRONMENT_DEPENDENCY_DRIFT`.

This case also means that a retry gate must bind its decision to more than
`head_sha`. Where external mutable inputs exist, the evidence should retain the
resolved dependency/environment identity that actually executed.


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
