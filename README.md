# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, sufficient, and still valid at execution time?

## Problem

Identity and policy may permit an action even when the operational state that justified it has changed between observation, dry-run, authorization, and execution.

StateLatch v0.1 focuses on one narrow Kubernetes node-drain path:

```text
Observe
  ↓
Preflight
  ↓
Verify evidence + blast radius
  ↓
Build state-bound plan
  ↓
Server-side dry-run
  ↓
Mint plan-bound authorization
  ↓
Final live revalidation
  ↓
Experimental mutation gate
  ↓
Cordon
  ↓
Revalidate remaining plan
  ↓
Evict one Pod
  ↓
Observe deletion
  ↓
Repeat or stop
```

Any state drift, PDB denial, expired authorization, identity mismatch, or optimistic-concurrency conflict stops the execution path.

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch
go test ./...
```

The main CI also creates a temporary KinD cluster and runs live Kubernetes integration tests.

## Safe-by-default adapter

The normal constructors keep real mutations disabled:

```go
NewForConfig(config)
NewWithExecutor(reader, executor)
```

They can inspect state, preflight, dry-run, and mint/revalidate authorizations, but `ExecuteAuthorizedNodeDrain(...)` returns:

```text
ESCALATE / REAL_EXECUTION_UNAVAILABLE
```

Real mutations currently require the explicitly named experimental path:

```go
NewForConfigWithExperimentalMutations(config)
```

This opt-in exists for controlled KinD integration work. Production mutation enablement is not part of v0.1.

## State-bound execution plan

The plan is built from Kubernetes-observed state, not agent-supplied state.

```text
NODE
  name=node-7
  uid=<observed node uid>
  health=<observed health>
  resourceVersion=928441

CORDON_NODE
  node=node-7
  resourceVersion=928441

EVICT_POD
  pod=default/api-a
  uid=<observed pod uid>
  stateDigest=<drain-relevant semantic digest>
```

StateLatch computes a deterministic SHA-256 `plan_digest` over the complete ordered plan and binds it into the authorization.

For Pods, the plan digest intentionally does **not** bind to raw `resourceVersion`. Live KinD testing showed that Kubernetes can change Pod `resourceVersion` because of status/controller churn even when drain-relevant state has not changed.

Instead, StateLatch binds to a semantic Pod state digest covering:

- UID and node assignment
- labels
- controlling workload identity
- mirror/static-pod marker
- `emptyDir` presence
- phase and Ready state
- deletion state

Raw Pod `resourceVersion` is retained for observation/audit.

The Node side remains stricter: Node UID and health are part of the authorized plan, while the cordon request uses the current observed Node `resourceVersion` as an optimistic-concurrency precondition.

## Preparation

`PrepareNodeDrainExecution(...)` requires Kubernetes to accept:

1. a server-side dry-run cordon;
2. a server-side dry-run eviction for every planned Pod.

Pod eviction uses a UID delete precondition, preventing a same-name replacement Pod from being treated as the original object.

No execution authorization is exposed until all current gates and dry-runs pass.

A Node `resourceVersion` conflict during dry-run is treated as state drift:

```text
ESCALATE / RESOURCE_VERSION_CHANGED
```

It is not misclassified as a policy denial.

## Final live revalidation

`RevalidateNodeDrainAuthorization(...)` re-reads Kubernetes state, reruns drain preflight, rebuilds the execution plan, recomputes its digest, and validates the short-lived authorization.

```text
same drain-relevant state + same plan digest + valid TTL
→ ALLOW

Pod labels / owner / UID / readiness / phase / node assignment changed
→ ESCALATE / EXECUTION_PLAN_CHANGED

raw Pod resourceVersion changed but semantic state did not
→ plan remains valid

Node resourceVersion changed before execution
→ ESCALATE / RESOURCE_VERSION_CHANGED

PDB now blocks the drain
→ BLOCK / PDB_DISRUPTION_BLOCKED

authorization expired
→ ESCALATE / AUTHORIZATION_EXPIRED
```

## Guarded experimental execution

With the experimental mutation constructor, `ExecuteAuthorizedNodeDrain(...)` performs:

```text
final authorization revalidation
→ real cordon with Node resourceVersion precondition
→ verify Node UID + health + cordon state
→ rerun live Pod/PDB preflight
→ compare remaining semantic Pod set
→ real Eviction API call with Pod UID precondition
→ wait until that Pod UID is absent
→ revalidate remaining state
→ repeat
→ final empty-plan revalidation
```

The execution loop never blindly consumes the plan after authorization. It re-reads live state before every eviction.

If another actor modifies the Node between final revalidation and cordon, Kubernetes returns an optimistic-concurrency conflict and StateLatch returns:

```text
ESCALATE / RESOURCE_VERSION_CHANGED
```

If the world changes after cordon, the remaining evictions are stopped.

## Drain preflight

Implemented checks include:

```text
DaemonSet pod
→ BLOCK / DAEMONSET_POD_REQUIRES_IGNORE

Unmanaged pod
→ BLOCK / UNMANAGED_POD_REQUIRES_FORCE

emptyDir
→ BLOCK / EMPTYDIR_DATA_REQUIRES_DELETE

PDB disruption capacity insufficient
→ BLOCK / PDB_DISRUPTION_BLOCKED

PDB status stale
→ ESCALATE / PDB_STATUS_STALE

PDB state unavailable
→ ESCALATE / PDB_EVIDENCE_UNAVAILABLE
```

Mirror/static Pods are recorded and skipped.

## Live integration evidence

GitHub Actions runs unit tests plus a temporary KinD Kubernetes cluster.

Current live scenarios prove that:

- server-side cordon + eviction dry-runs do not persist mutations;
- a healthy Pod protected by a zero-disruption PDB is rejected by Kubernetes and StateLatch returns `BLOCK`;
- a drain-relevant Pod change after authorization produces `ESCALATE / EXECUTION_PLAN_CHANGED`;
- experimental guarded execution performs a **real cordon** and a **real Pod eviction** in KinD;
- when a semantic Pod change is injected immediately after the real cordon, StateLatch detects it before eviction and stops;
- raw Node optimistic-concurrency conflicts fail closed instead of being retried blindly.

These are live integration tests against a real temporary Kubernetes API server, not mocked client behavior.

## Implemented

- evidence freshness and contradiction gates
- distinct-source requirements
- Kubernetes-derived blast radius
- live Node / Pod / PDB reads
- drain preflight
- deterministic execution-plan generation
- Node UID + health binding
- drain-relevant semantic Pod state digest
- deterministic plan digest
- state-bound authorization
- server-side dry-run cordon and eviction
- Pod UID eviction precondition
- final live revalidation
- guarded real cordon + eviction loop behind explicit experimental opt-in
- in-flight revalidation before every eviction
- bounded observation of accepted Pod evictions
- optimistic-concurrency drift classification
- default mutation lock
- unit + KinD live integration CI

## Not implemented yet

- production mutation enablement
- graceful termination/retry policy comparable to mature drain tooling
- exact `kubectl drain` parity
- production-grade recovery/rollback after a partial drain
- Prometheus evidence adapter/cache
- multi-source live evidence
- production daemon / API surface
- AWS/GCP, SSH, databases, PLC, or financial execution

## Guarantees and limits

StateLatch currently proves a guarded execution primitive, not a production-ready drain replacement.

There is still an unavoidable race between a userspace re-read and a later API mutation. StateLatch reduces that race with Kubernetes-enforced Node `resourceVersion` and Pod UID preconditions plus the Eviction API's own live PDB enforcement.

If state changes outside those server-enforced preconditions, StateLatch can only detect it at the next live revalidation boundary. Production use therefore requires more work on recovery, observability, execution semantics, and operational policy.

Real mutations are disabled by default.

## Docs

- [Kubernetes node-drain adapter](docs/kubernetes-node-drain.md)
- [Server-side dry-run](docs/server-dry-run.md)
- [Guarded experimental execution](docs/guarded-real-execution.md)
- [Decision contract](docs/decision-contract.md)

## Current status

`v0.1-prealpha` — tested decision kernel + Kubernetes drain preflight + state-bound authorization + server-side dry-run + final and in-flight live revalidation + guarded real KinD mutation execution. Production mutation mode is intentionally disabled.

## Design principle

**Evidence before action.**
