# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, sufficient, and still valid at execution time?

## Problem

Identity and policy may permit an action even when the operational state that justified it has changed between observation, dry-run, and execution.

StateLatch v0.1 focuses on one narrow path for Kubernetes node drains:

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

## State-bound execution plan

The plan is built from Kubernetes-observed state, not agent-supplied state:

```text
CORDON_NODE
  node=node-7
  resourceVersion=928441

EVICT_POD
  pod=default/api-a
  uid=<observed uid>
  resourceVersion=<observed rv>
```

StateLatch computes a deterministic SHA-256 `plan_digest` across the complete ordered plan and binds that digest into the authorization.

Changing any bound execution input — including a Pod UID/resourceVersion, Node resourceVersion, target set, or step ordering — changes the digest.

## Server-side dry-run

`PrepareNodeDrainExecution(...)` requires Kubernetes to accept:

1. a server-side dry-run cordon;
2. a server-side dry-run eviction for every planned Pod.

Evictions carry UID and `resourceVersion` delete preconditions.

A preparation authorization is exposed only after all current gates and dry-runs pass.

## Final live revalidation

Immediately before any future real mutation, callers must use:

```go
RevalidateNodeDrainAuthorization(...)
```

This path re-reads live Kubernetes state, reruns drain preflight, rebuilds the execution plan, recomputes its digest, and validates the short-lived authorization.

Examples:

```text
same live state + same plan digest + valid TTL
→ ALLOW

Pod resourceVersion / UID / target set changed
→ ESCALATE / EXECUTION_PLAN_CHANGED

Node resourceVersion changed
→ ESCALATE / RESOURCE_VERSION_CHANGED
  (+ EXECUTION_PLAN_CHANGED because the plan changed)

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

## Implemented

- evidence freshness and contradiction gates
- distinct-source requirements
- Kubernetes-derived blast radius
- live Node / Pod / PDB reads
- drain preflight
- deterministic execution-plan generation
- deterministic plan digest
- state-bound authorization
- server-side dry-run cordon and eviction
- Pod UID + resourceVersion eviction preconditions
- final live revalidation
- TOCTOU invalidation for Node and complete drain plan

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

A passing dry-run plus passing live revalidation is stronger than local simulation, but it is still not a mathematical guarantee that a later mutation will succeed.

Cluster state can change after revalidation. A future real execution path must therefore keep the same Node and Pod preconditions on the actual mutation requests so state drift fails closed at the API server too.

StateLatch does not execute production mutations yet.

## Docs

- [Kubernetes node-drain adapter](docs/kubernetes-node-drain.md)
- [Server-side dry-run](docs/server-dry-run.md)
- [Decision contract](docs/decision-contract.md)

## Current status

`v0.1-prealpha` — tested decision kernel + Kubernetes drain preflight + server-side dry-run preparation + final live plan revalidation.

## Design principle

**Evidence before action.**
