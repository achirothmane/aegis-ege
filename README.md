# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, sufficient, and still valid at execution time?

## Problem

Identity and policy may permit an action even when the operational state that justified it has changed between observation, dry-run, and execution.

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
ALLOW / BLOCK / ESCALATE
```

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch
go test ./...
```

The main CI also creates a temporary KinD cluster and runs live Kubernetes integration tests.

## State-bound execution plan

The plan is built from Kubernetes-observed state, not agent-supplied state:

```text
CORDON_NODE
  node=node-7
  resourceVersion=928441

EVICT_POD
  pod=default/api-a
  uid=<observed uid>
  stateDigest=<drain-relevant semantic digest>
```

StateLatch computes a deterministic SHA-256 `plan_digest` over the complete ordered plan and binds it into the authorization.

For Pods, the plan digest intentionally does **not** bind to raw `resourceVersion`. A live KinD test showed that Kubernetes can change Pod `resourceVersion` because of status/controller churn between observation and dry-run even when drain-relevant state has not changed.

Instead, StateLatch binds to a semantic Pod state digest covering drain-relevant inputs:

- UID and node assignment
- labels
- controlling workload identity
- mirror/static-pod marker
- `emptyDir` presence
- phase and Ready state
- deletion state

Raw Pod `resourceVersion` is retained for observation/audit, but resourceVersion-only churn does not invalidate an otherwise unchanged drain plan.

## Server-side dry-run

`PrepareNodeDrainExecution(...)` requires Kubernetes to accept:

1. a server-side dry-run cordon;
2. a server-side dry-run eviction for every planned Pod.

The Node cordon remains bound to the observed Node `resourceVersion`.

Pod eviction uses a UID delete precondition, preventing a same-name replacement Pod from being treated as the original object.

No execution authorization is exposed until all current gates and dry-runs pass.

## Final live revalidation

Immediately before any future real mutation, callers must use:

```go
RevalidateNodeDrainAuthorization(...)
```

This re-reads live Kubernetes state, reruns drain preflight, rebuilds the execution plan, recomputes its digest, and validates the short-lived authorization.

```text
same drain-relevant state + same plan digest + valid TTL
→ ALLOW

Pod labels / owner / UID / readiness / phase / node assignment changed
→ ESCALATE / EXECUTION_PLAN_CHANGED

raw Pod resourceVersion changed but semantic state did not
→ plan remains valid

Node resourceVersion changed
→ ESCALATE / RESOURCE_VERSION_CHANGED

PDB now blocks the drain
→ BLOCK / PDB_DISRUPTION_BLOCKED

authorization expired
→ ESCALATE / AUTHORIZATION_EXPIRED
```

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

Mirror/static pods are recorded and skipped.

## Live integration evidence

GitHub Actions now runs both unit tests and live KinD integration tests.

The current live scenarios prove that:

- server-side cordon + eviction dry-runs can pass without persisting either mutation;
- a healthy Pod protected by a zero-disruption PDB is rejected by the Kubernetes Eviction API, and StateLatch returns `BLOCK`;
- a drain-relevant live Pod change after authorization causes final revalidation to return `ESCALATE / EXECUTION_PLAN_CHANGED`.

These are integration tests against a real temporary Kubernetes API server, not mocked client behavior.

## Implemented

- evidence freshness and contradiction gates
- distinct-source requirements
- Kubernetes-derived blast radius
- live Node / Pod / PDB reads
- drain preflight
- deterministic execution-plan generation
- drain-relevant semantic Pod state digest
- deterministic plan digest
- state-bound authorization
- server-side dry-run cordon and eviction
- Pod UID eviction precondition
- final live revalidation
- unit + KinD live integration CI

## Not implemented yet

- real node cordon
- real Pod eviction
- graceful termination / retry execution loop
- exact `kubectl drain` parity
- Prometheus evidence adapter/cache
- multi-source live evidence
- production daemon / API surface
- AWS/GCP, SSH, databases, PLC, or financial execution

## Guarantees and limits

A passing dry-run plus passing live revalidation is stronger than local simulation, but it is not a guarantee that a later mutation will succeed.

Cluster state can change after revalidation. A future real execution path must therefore keep server-enforced identity/state preconditions on the actual mutation requests and fail closed if the world changes again.

StateLatch does not execute production mutations yet.

## Docs

- [Kubernetes node-drain adapter](docs/kubernetes-node-drain.md)
- [Server-side dry-run](docs/server-dry-run.md)
- [Decision contract](docs/decision-contract.md)

## Current status

`v0.1-prealpha` — tested decision kernel + Kubernetes drain preflight + server-side dry-run + final live plan revalidation, with KinD integration coverage. Production mutation is not implemented.

## Design principle

**Evidence before action.**
