# D03-A — Public held-out incident corpus falsification v1

Status: **ACTIVE — SUPPLEMENTAL HELD-OUT FALSIFICATION, NOT D03 PASS**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

## Purpose

D03-A removes external-maintainer response latency from the **unseen-case
generalization** work. It selects public incidents only after the K06 freeze and
maps their externally documented root causes/fixes into the already frozen K07
boundary evaluator.

It does **not** replace the independent-implementation requirement of D03.

## Evidence rule

Each corpus entry must have:

1. an external repository not owned by `achirothmane`;
2. a closed public incident with a concrete consequence;
3. public root-cause evidence;
4. a public fix, fixed release, or maintainer-confirmed corrected behavior;
5. a kernel mapping written only after freeze;
6. an expected historical disposition derived from the unchanged frozen
   relations;
7. where a fixed counterpart exists, a positive mapping showing the contract
   does not collapse into deny-all.

The public incident is ground truth for what happened. The mapping into kernel
facts is authored by us and is therefore **not** independent implementation
evidence.

## v1 corpus

The corpus currently contains eleven reference mappings sourced from ten
closed public issues across seven external repositories:

- OpenMeter: migration-baseline completeness and concurrent billing-result
  attribution;
- Hatchet: redelivery/idempotency, lost completion observation causing duplicate
  child work, and exact durable cancellation identity;
- Infisical: migration rollback state ownership;
- External Secrets Operator: credential lifecycle state binding when a recreated
  controller object would otherwise regenerate and overwrite an existing credential;
- Argo Workflows: stale workflow reconciliation after completion, where an older
  resourceVersion could otherwise recreate a pod for an already-finished execution;
- Terraform AWS Provider: an external AWS effect created successfully but lost from
  Terraform state, so re-apply could create another orphaned effect;
- Tortoise #3442: two deliberately separated facets from one investigation:
  a **positive execution-boundary case** where the failed job acquired no runner
  and executed zero steps, and a **negative selection-integrity case** where a
  non-canonical changed-set fallback could silently reduce test coverage.

The exact issue/fix references and merged commit identities are recorded in
`testdata/governed-action/d03a/corpus-v1.json`.

## Execution

The test harness builds a safe baseline `k07Input`, applies only the
incident-specific fact overrides, and sends the result through the same
`evaluateK07` function used by K07.

The corpus is therefore forbidden from:

- adding a D03-specific evaluator;
- changing evaluator ordering to fit an incident;
- changing the frozen oracle;
- relabeling a failed mapping after seeing the result;
- claiming that external maintainers implemented the contract.

For every historical unsafe trace the evaluator must produce the preregistered
safety disposition. A public incident may also contribute a positive historical
boundary case when the external evidence establishes that no prior effect crossed
the relevant boundary; such a case must be explicitly marked
`historical_valid_trace=true` and must exercise useful permitted behavior.

For every fixed counterpart that exists, the evaluator must produce the
preregistered useful disposition.

## Falsification rule

If a well-grounded public incident exposes a material safety distinction that
the frozen relations cannot express without a new semantic rule, D03-A records
that as a **falsification failure**. The case is not repaired by editing v1.

If the incident is merely outside the contract's declared claim scope, it is
recorded as out-of-scope rather than counted as a pass.

## Relationship to D03

D03-A can support:

- unseen-case generalization evidence;
- cross-domain counterexample coverage;
- discovery of missing frozen distinctions.

D03-A cannot support:

- independent implementability;
- maintainer independence;
- the D03 PASS gate by itself;
- D04 unblocking by itself.

The existing D03 readiness state remains `BLOCKED_UNSTARTED` for the
independent-participant requirement while D03-A runs in parallel.

## v1 selection integrity

Selection occurred after K06/K07/D01/D02 and after the frozen oracle identity
was fixed. None of these incidents may be used to silently redesign
`candidate-kernel-contract-v1` before evaluation.

Normative change: **NO**  
Runtime change: **NO**


## Reference case — External Secrets Operator #6640 / PR #6641

`refreshPolicy: CreatedOnce` used the `ExternalSecret` object's own status as its
one-time sync memory. Recreating that controller object reset the status even
when the target Secret still existed. With the stateless Password generator,
the next reconcile could mint a new password and overwrite the Secret.

The reported production consequence was stronger than a cosmetic resync: the
Kubernetes Secret changed while Keycloak's already-bootstrapped admin credential
did not. The stored credential and the real downstream authority therefore
diverged.

D03-A maps this as a `StateBinding` / `DecisionBasis` failure: target existence
and the credential value actually accepted by the downstream authority are
consequence-relevant state. Recreated controller status cannot stand in for
that binding.

The historical mapping must therefore produce
`DEFER_MISSING_RELEVANT_STATE`.

PR #6641 merged as
`40b04db4543fe3a6e6bab90447cb018a5871c25d`. It added `CreateOrMerge`,
clarified the `CreatedOnce` lifecycle, and added tested generate-once/freeze
behavior using explicit target immutability. That fixed configuration provides
the positive useful counterpart without changing the frozen kernel evaluator.

## Reference case — Argo Workflows #16294 / PR #16357

Argo Workflows recorded a stale reconciliation hazard: after the real workflow
had completed successfully, an older still-Running workflow object could be
processed again and reach the missing-pod creation path. The issue records two
distinct pod UIDs for the same logical workflow execution; another reporter
observed an already-completed step run again hours later.

The related bookkeeping defect was isolated in #16305: completed workflow state
was not reliably compared with stale informer copies before reconciliation.
PR #16357 replaced the older caches with UID-keyed `lastWrittenVersions` and
ordered Kubernetes `resourceVersion` comparison. Stale copies older than a
completed/deleted state are dropped before effectful reconciliation. The PR
merged as `a7a7a8dfb53a35314b81616ec35b5e3f7270b250`; a maintainer later
confirmed that #15090 and #16357 should fix #16294.

D03-A maps the historical trace to `StateBinding` / `DecisionBasis`: the current
workflow completion state is consequence-relevant. An older Running snapshot
cannot authorize a new pod effect once a newer completed state exists.

The unchanged frozen evaluator must therefore return `REJECT_BEFORE_EFFECT`
when `relevant_state_current=false`. The fixed counterpart remains a useful
`ALLOW_BOUND_EFFECT` path when current state is bound and an effect is actually
required.

## Reference case — Terraform AWS Provider #49231 / PR #49250

`aws_bedrockagentcore_memory_strategy` could call AWS successfully and create a
strategy, then fail locally while asserting a single result from the unfiltered
strategy list. Terraform therefore returned an error after the real external
effect had already occurred.

The consequence is exactly the dangerous boundary D03-A wants to pressure:
the new strategy remained active in AWS but was absent from Terraform state.
A subsequent apply did not reconcile the first effect; it created another
strategy and failed again, accumulating orphaned external state.

D03-A maps the historical trace to `EffectIdentity` / `ExecutionAttempt` /
`ClosureObligation`: after a possible prior effect exists, a second create is
not a safe retry merely because the local state write failed.

The unchanged frozen evaluator must therefore return `REJECT_SECOND_EFFECT`
when `possible_effect_exists=true`, substitution is requested, and no safe
substitution/idempotency proof exists.

PR #49250 merged as
`079f694ee03602059af6e534d3b14297907ad639`. It filters the returned
strategy set before asserting a single result, allowing the successful external
effect to be identified and recorded instead of being misclassified as a failed
creation. The fixed counterpart remains a useful `ALLOW_BOUND_EFFECT` path.

## Reference case — Tortoise #3442 / PR #5474

This incident is intentionally not flattened into “fail then rerun passed =
flaky test.”

The original cited `changes` job (job `103701145755`) executed zero steps.
The merged PR records `runner_name=""`, `runner_id=0`, and a check-run
annotation that the job failed to be acquired after five attempts. The rerun on
the same head/diff acquired a runner and the `changes` job passed in 11
seconds.

D03-A therefore records:

1. **TORTOISE-3442-A — positive boundary case.** If authoritative evidence shows
   that the prior attempt never acquired an executor and executed no steps, that
   attempt did not create a possible prior effect merely because the check
   concluded failure. Under otherwise unchanged valid bindings, a bounded new
   attempt may be admissible. This does not classify every fail→pass sequence as
   a flaky test.
2. **TORTOISE-3442-B — negative selection-integrity case.** PR #5474 separately
   found that the old changed-file derivation could fall back from the canonical
   merge-base question to a different two-ref diff, and could turn an
   unavailable/empty changed set into a smaller smoke suite that still reported
   green. Under the frozen kernel mapping, that is an inadequate DecisionBasis /
   profile for the claim and must DEFER rather than silently ALLOW.

PR #5474 merged as
`1917852e17ffe741f37ca419c2c433c741112159` and reports 182 passing
verification tests plus mutation checks for the canonical-diff and empty-set
guards.

This split preserves both pieces of ground truth: the runner-acquisition event
was not fixed by the workflow patch, while the changed-set defect was.
