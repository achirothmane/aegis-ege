# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, sufficient, and still valid at execution time?

It is not a general AI governance platform. `v0.1` focuses on a narrow primitive for Kubernetes node-drain actions: **observe → preflight → verify → server dry-run → authorize**.

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch
go test ./...
```

## Current node-drain path

```text
Agent proposes drain
        ↓
Read Kubernetes state
        ↓
Drain preflight
        ↓
Evidence + blast-radius gates
        ↓
Build state-bound execution plan
        ↓
Server-side dry-run
  - cordon node
  - evict each candidate pod
        ↓
ALLOW / BLOCK / ESCALATE
```

The trusted `resourceVersion`, Pod UID/resourceVersion, blast radius, and PDB state come from Kubernetes — not from the agent.

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

## State-bound execution plan

When preflight and the generic decision kernel pass, StateLatch builds a deterministic plan:

```text
1. CORDON_NODE
   node=node-7
   resourceVersion=928441

2. EVICT_POD
   pod=default/api-a
   uid=<observed uid>
   resourceVersion=<observed rv>

3. EVICT_POD
   pod=default/api-b
   uid=<observed uid>
   resourceVersion=<observed rv>
```

The eviction dry-run uses Kubernetes delete preconditions for both Pod UID and `resourceVersion`.

## Server-side dry-run gate

`PrepareNodeDrainExecution` is the execution-readiness path.

It does not expose an execution authorization unless:

1. preflight returns `ALLOW`;
2. evidence/risk gates return `ALLOW`;
3. Kubernetes accepts a server-side dry-run of the cordon;
4. Kubernetes accepts server-side dry-run eviction for every planned Pod;
5. the short-lived authorization has not expired during preparation.

Failure semantics:

```text
No server dry-run capability
→ ESCALATE / SERVER_DRY_RUN_UNAVAILABLE

Cordon dry-run rejected
→ BLOCK / SERVER_DRY_RUN_CORDON_REJECTED

Any eviction dry-run rejected
→ BLOCK / SERVER_DRY_RUN_EVICTION_REJECTED
```

See:
- [`docs/kubernetes-node-drain.md`](docs/kubernetes-node-drain.md)
- [`docs/server-dry-run.md`](docs/server-dry-run.md)
- [`docs/decision-contract.md`](docs/decision-contract.md)

## Implemented

- evidence freshness
- claim-scoped contradiction detection
- distinct-source requirements
- blast-radius hard limits
- state-bound authorization
- TOCTOU invalidation checks
- live Kubernetes Node / Pod / PDB reads
- DaemonSet / unmanaged / emptyDir / mirror / PDB preflight
- state-bound execution-plan generation
- server-side dry-run cordon
- server-side dry-run eviction
- Pod UID + resourceVersion eviction preconditions
- in-cluster and kubeconfig client construction

## Not implemented yet

- real node cordon
- real Pod eviction
- waiting for graceful termination
- exact `kubectl drain` parity
- Prometheus evidence adapter/cache
- multi-source live evidence
- production daemon / API surface
- AWS/GCP, SSH, databases, PLC, or financial execution

## Important limit

A passing server dry-run is stronger evidence than local simulation, but it is **not a guarantee that the later real drain will succeed**. Dry-run mutations are not persisted, cluster state can change immediately afterward, and individual dry-run evictions do not consume disruption budget.

StateLatch therefore still requires state validation immediately before any future real execution.

## Current status

`v0.1-prealpha` — tested decision kernel + Kubernetes node-drain preflight + server-side dry-run preparation. Production mutation is not implemented.

## Design principle

**Evidence before action.**
