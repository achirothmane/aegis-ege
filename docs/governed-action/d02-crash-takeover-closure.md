# D02 — Aegis/EEP closure, crash and takeover exercise

Status: **COMPLETE — design-visible domain experiment**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

D02 exercises the already-frozen CE3–CE8 relations on the two approved
design-visible substrates:

- one isolated KinD node-drain mutation through Aegis;
- the existing loopback synthetic CRM HTTP fixture through EEP.

EEP remains an Aegis subsystem. This is not a third independent domain and does
not count as D03.

## Experiment boundaries

### Kubernetes

The real boundary in CI is an isolated KinD cluster. D02 uses:

- native Node cordon / Pod eviction;
- Kubernetes Lease ownership for the mutation fence;
- Kubernetes ConfigMap `resourceVersion` as the shared checkpoint CAS;
- the existing node-drain checkpoint/recovery code;
- fresh node-drain authorization for the remaining exact Pod set after process
  loss.

The D02 takeover test creates a new adapter instance after the injected crash,
so recovery does not rely on the old worker's in-memory state.

### EEP CRM

The CRM destination is a local cooperative `httptest` HTTP server. It supports
the profile's destination/account headers and conditional `If-Match` write.
It is deliberately labeled **synthetic/cooperative** and does not prove that an
external CRM vendor supports equivalent CAS.

Before PATCH, EEP still requires:

- exact signed Permit/evidence/plan binding;
- durable attempt claim;
- authorization journal;
- dispatch-intent journal;
- transition to `POSSIBLE_EFFECT`.

D02 adds only observation-only closure recovery for a retained attempt. Recovery
does not dispatch PATCH and does not treat wakeup, process restart, callback or
old start authority as permission for a new effect.

## D02 bounded closure behavior

`ReconcileAttempt`:

- loads the deterministic existing attempt;
- verifies signed historical action identity and exact
  destination/account/plan/profile binding;
- does **not** use expired start authority to create another PATCH;
- performs only bounded postcondition GET observations;
- completes the retained attempt only when the domain's existing closure rule
  permits it;
- otherwise retains the unresolved state and custody.

`RetireAttemptUnknown`:

- is an explicit administrative disposition for an unresolved fixed attempt;
- creates no new mutation;
- journals the UNKNOWN disposition before the state transition;
- persists the attempt as `RETIRED_UNKNOWN`;
- retains destination/account/customer/observation-handle identity as residual
  custody;
- does not make replay safe.

A closure-journal outage therefore leaves the attempt unresolved rather than
manufacturing retirement.

## CE3–CE8 evidence map

| Case | Native fault boundary | Required D02 result |
|---|---|---|
| CE3 | lost provider response after PATCH may have committed | no substitution or blind replay; observation can resolve the same effect |
| CE4 | journal/checkpoint gap | no effect before durable custody; accepted Kubernetes effect is reconciled after restart |
| CE5 | observation unavailable/contradictory | UNKNOWN retained; later observation may close; permanent gap may retire UNKNOWN with residual custody |
| CE6 | takeover race | stale pre-crash authority stops on current-state revalidation; a fresh contender is independently fenced by the Kubernetes Lease; old authorization cannot resume the changed remainder |
| CE7 | unrelated/partial destination change | no false VERIFIED |
| CE8 | stale destination version | destination If-Match/CAS rejects stale write |

Machine-readable schedules live at
`testdata/governed-action/d02/fault-schedules.json`.

## Required positive paths

D02 retains the existing positive tests for:

- normal conditional CRM mutation and durable completion;
- normal guarded KinD cordon/eviction;
- restart replay without duplicate CRM mutation;
- fresh-authorization Kubernetes recovery;
- routine CRM observation recovery without human review.

Deny-all therefore cannot satisfy D02.

## Claim limits

D02 does **not** prove:

- external CRM CAS support;
- production cluster failover;
- universal provider compensation;
- independent adoption;
- held-out generalization;
- TPM deployment;
- operator-value improvement.

No K01–K05 artifact or frozen vector is modified by D02.


## Completion evidence

Implementation PR: `achirothmane/aegis-ege#86`

- exact reviewed head:
  `6ea1cb3c49f37540d1a992cdb27f4594a99fc713`;
- squash merge:
  `f71f89bff0ad5ba243f3e42a75060a6ec95f1d2f`;
- final CI run `36673322497` / #430: **success**;
- unit job `109752835870`: **success**;
- KinD integration job `109752931918`: **success**;
- frozen normative oracle remains
  `37e2e0a0867fa78df37f9d4243a1c4107d62094b`;
- final D02 fault-schedule blob:
  `13f16231857257df1c10c1d9e6fab5ed9b0776e1`.

Exact machine-readable completion evidence is recorded in
`testdata/governed-action/d02/completion.json`.

### Falsification record

The first D02 KinD run, `36673051760`, did not pass. Its unit job succeeded,
but integration job `109752193264` failed because the experiment expected the
stale pre-crash worker to reach the Kubernetes Lease and receive
`EXECUTION_LOCK_HELD`.

Instead, the real implementation stopped that stale authorization earlier with:

`RESOURCE_VERSION_CHANGED + EXECUTION_PLAN_CHANGED`

That was not converted into a kernel semantic change or hidden by weakening the
safety condition. The experiment was decomposed into two separately testable
claims:

1. stale pre-crash authority must be stopped by current-state revalidation
   before another effect; and
2. a current-state contender that otherwise reaches the mutation boundary must
   be stopped by the real Kubernetes Lease while takeover owns it.

The final KinD run proves both paths, as well as shared checkpoint
`resourceVersion` conflict handling.

### D02 completion decision

D02 is complete for its design-visible scope because:

- CE3–CE8 have deterministic executable fault schedules;
- no EEP effect escapes before durable attempt/journal custody;
- an accepted or possible CRM effect survives observer/process ambiguity without
  blind replay;
- observation-only recovery can close the same fixed effect after start
  authority expiry without dispatching another PATCH;
- permanent observation uncertainty can be disposed as
  `RETIRED_UNKNOWN` only after closure evidence is journaled, while residual
  durable custody remains;
- Kubernetes crash recovery reconciles the accepted exact Pod effect from a
  shared checkpoint;
- stale authority cannot resume the changed remainder;
- the real Kubernetes Lease blocks a competing executor at the mutation
  boundary;
- the ConfigMap `resourceVersion` acts as the claimed checkpoint CAS;
- fresh authorization is required before remaining Kubernetes mutation resumes;
- ordinary positive CRM and Kubernetes actions remain usable.

D02 still does **not** establish an external CRM provider CAS guarantee,
production failover, independent-domain validation, operator value, or a
demonstrated platform kernel.
