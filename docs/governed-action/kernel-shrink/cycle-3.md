# Cycle 3: live closure/custody merge trials

Baseline: merged #238, `48083a69307fd9b482ac45bea146346720e09ea8`.
This cycle attempts semantic reduction in the live independent evaluator. It
does not demote another simulation or claim a smaller production surface.

The candidate is to retain **exact trusted admission + effect custody** and
derive the third obligation, independently sufficient closure evidence, from
those two. Two plausible substitutions are compiled into the actual
`evidenceverify/verify.go`, one at a time:

| Alternative | Live relation removed | Replacement |
| --- | --- | --- |
| `custody-as-commit` | Independent destination receipt for this exact attempt | Derive the receipt's effect, attempt, owner, generation, authority and transition from the admitted request/custody tuple when a receipt is absent |
| `commit-as-closure` | Current observed state equals the independently required after-state | Treat an exact historical commit as sufficient closure |

The first alternative is stronger than deleting one field comparison: it
eliminates the need for a separate causal receipt entirely. The second keeps
every exact commit join and removes only the postcondition relation. Neither
changes the independent policy's `EXACT_EFFECT` requirement, signatures, roots,
admission checks or historical continuity checks.

## Minimal separating witnesses

### Same admission and custody, different cause

The native control and `foreign-attempt` world both reserve two attempts for
one exact effect and advance both durable custody records to `CROSSING`.
Exactly one native transaction executes: the requested attempt in the control,
the other attempt in the counterexample. Both worlds have the same trusted
admission, both retained custody tuples, intended observed state and tally of
one effect. The test asserts byte equality of this projection across the two
worlds. The foreign effect is produced by `ExecuteFenced`; no effect row is
forged or edited.

Only the destination's receipt identifies which attempt actually committed.
An honest observation cannot supply a receipt for the unexecuted attempt.
With the live evaluator unchanged, the requested attempt is `UNKNOWN`, with
`STATE_ONLY` causality, and its producer's false exact-effect `CLOSED` claim is
unsupported. With `custody-as-commit`, the actual consumer returns `CLOSED`,
`EXACT_COMMIT_RECORD` and `claims_supported=true` for that false claim.

This is a bounded indistinguishability argument: a decision using only the
equal retained projection cannot answer both worlds correctly. Reintroducing
an authenticated causal read inside a unified custody object could work, but
would retain the erased relation under a different representation.

### Same exact cause, current postcondition no longer holds

The `changed-postcondition` witness needs one attempt, one genuine native
commit and one later update to the target digest. The exact owned receipt,
authority at commit, admission and retained custody remain valid. The current
state no longer satisfies the required after-state.

The unchanged evaluator reports `UNKNOWN` closure and still reports
`EXACT_COMMIT_RECORD` causality and `VALID_AT_COMMIT`. The changed state does
not erase the proven historical effect. With `commit-as-closure`, the real
consumer wrongly supports `CLOSED`. A policy requiring only a historical
occurrence would ask a different question; changing the relying party's
obligation is not a reduction preserving this profile.

These witnesses are small separating cases, not a machine-checked proof of
globally smallest traces across every possible architecture.

## Execution and assurance

`scripts/run_semantic_closure.py` pins the exact live evaluator blob from #238,
runs all three unchanged controls, compiles each alternative, requires failure
at its intended regression assertion **and** a supported false `CLOSED`
judgment, restores the exact source bytes, and reruns all controls. Compilation
errors, skipped cases and unrelated test failures cannot count as witnesses.

Unit mode invokes the real evaluator with trusted signatures, independent
policy and the actual journal producer. All three unit claims are retained in
trusted history, demonstrating that authenticated history can faithfully
preserve an unsupported claim. Native mode builds the actual
`aegis-evidence-inspect` production consumer for each alternative and passes
only two local inputs to a fresh process. The consumer receives no database
credentials, signing keys or runtime adapter. Native observation-only runtime recovery
also independently returns the corresponding `CLOSED` or `UNKNOWN`, without
dispatching an effect or changing the one-effect tally.

The composite CI job requires the original six #235 native cases plus the
three new controls with no skips. It then executes both live alternatives
against fresh native effects and the real consumer. The original #236
independent claim-strength corpus, 142 standalone test outcomes, 176 runtime
traces, historical source pins and earlier ten relation-removal witnesses are
retained. A passing local unit result is not labeled a native run.

Native scope remains fixture-provisioned signing roots, PostgreSQL destination
fencing and one PostgreSQL failure domain. The original succession corpus
continues to distinguish native effect/succession evidence from simulation
Genesis. This cycle does not upgrade either claim to independent operator
reproduction or physical Genesis evidence.

## Result and limits

Both candidate merges fail the tested independent closure obligation. No
production semantic relation is removed. Runtime carriers remain four and
retained obligations remain three:

| Retained obligation | Role still needed in this profile |
| --- | --- |
| Trusted admission | Exact request accepted under independently trusted authorization |
| Effect custody | Durable ownership/cardinality despite possible effect escape and uncertainty |
| Truthful closure | Evidence answering the relying party's independent question, with exact cause and required current state kept distinct |

This establishes necessity of the two tested closure relations relative to the
retained projection. It does not prove all three obligations globally
irreducible, four carrier types necessary, or an Aegis-specific novel primitive.
The novelty classification remains **useful composition of known mechanisms**.
The next candidate may unify representations while retaining these relations,
or test a different live relation; it cannot infer causal truth from custody or
current state from an historical receipt.
