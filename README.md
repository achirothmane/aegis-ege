# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, and sufficient **right now**?

It is not a general AI governance platform. `v0.1` focuses on one narrow primitive: deciding whether a proposed Kubernetes action should be **ALLOW**, **BLOCK**, or **ESCALATE** based on independently observed state.

## Problem

Identity and policy can say an action is permitted while the operational state behind that action is stale, contradictory, too risky, or no longer the state that was originally checked.

```text
Agent proposes action
        |
        v
Observe current state
        |
        v
Drain preflight
        |
        v
Verify evidence + blast radius
        |
        v
Bind ALLOW to exact state
        |
   +----+----+----------+
   |         |          |
 ALLOW     BLOCK     ESCALATE
```

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch
go test ./...
```

CI runs the same suite on Go 1.25.

## First live Kubernetes primitive

StateLatch contains a read-only Kubernetes adapter for **node-drain assessment**.

Using the official Go client, it reads live cluster state and derives:

```text
Node metadata.resourceVersion
Node Ready condition
Pods scheduled on the node
PodDisruptionBudgets
Observed timestamp
```

Before the decision kernel can mint an `ALLOW`, the drain preflight checks for:

```text
DaemonSet-managed pods
unmanaged pods
emptyDir data
mirror/static pods
PodDisruptionBudget capacity
stale or unavailable PDB evidence
```

The agent does **not** supply the trusted `resourceVersion`, affected-pod count, or PDB state.

See [`docs/kubernetes-node-drain.md`](docs/kubernetes-node-drain.md).

## Preflight semantics

Examples:

```text
DaemonSet pod + ignore-daemonsets=false
→ BLOCK / DAEMONSET_POD_REQUIRES_IGNORE

Unmanaged pod + force=false
→ BLOCK / UNMANAGED_POD_REQUIRES_FORCE

emptyDir + delete-emptydir-data=false
→ BLOCK / EMPTYDIR_DATA_REQUIRES_DELETE

matching PDB permits fewer disruptions than targeted pods
→ BLOCK / PDB_DISRUPTION_BLOCKED

matching PDB status is stale
→ ESCALATE / PDB_STATUS_STALE

PDB state cannot be read
→ ESCALATE / PDB_EVIDENCE_UNAVAILABLE
```

Mirror/static pods are recorded and skipped rather than treated as evictable workload pods.

## State-bound authorization

When preflight and all hard gates pass, `ALLOW` carries a short-lived authorization bound to:

```text
action_id
action
target
resource_version
evidence_digest
valid_until
```

A changed resource version, action, target, or expired authorization invalidates execution.

## Decision contract

StateLatch v0.1 exposes three decisions:

- `ALLOW` — required gates passed and a state-bound authorization was minted.
- `BLOCK` — a hard safety predicate failed.
- `ESCALATE` — evidence or binding information is insufficient for autonomous execution.

See [`docs/decision-contract.md`](docs/decision-contract.md).

## v0.1 scope

Implemented:

- evidence freshness
- claim-scoped contradiction detection
- distinct-source requirements
- blast-radius hard limits
- state-bound authorization
- TOCTOU invalidation checks
- live Kubernetes node read
- live `resourceVersion` capture
- Kubernetes-derived active-pod blast radius
- drain preflight for DaemonSets, unmanaged pods, emptyDir, mirror pods, and PDBs
- in-cluster and kubeconfig client construction

Not implemented yet:

- actually cordoning or draining a Kubernetes node
- eviction execution
- server-side dry-run of mutations
- exact `kubectl drain` parity
- Prometheus evidence adapter/cache
- multi-source live evidence
- AWS/GCP, SSH, databases, PLC, or financial execution
- dashboard / SaaS

## Current guarantees

The current node-drain assessment path does not mint an autonomous authorization when:

- required evidence is stale;
- evidence for the same claim contradicts;
- blast radius exceeds the configured hard limit;
- required independent sources are missing;
- state-binding information is incomplete;
- drain preflight finds a configured hard blocker;
- required PDB evidence is stale or unavailable.

A minted authorization is invalidated if it expires or if its action, target, or resource version changes before execution.

## Important limits

The drain preflight is intentionally conservative. Its PDB check compares targeted matching pods against the PDB's current `disruptionsAllowed` and requires `observedGeneration == generation`.

It does **not** yet reproduce every nuance of `kubectl drain` or the Eviction API, including all unhealthy-pod eviction-policy cases, orphaned-controller lookup, or exact eviction ordering.

## Current status

`v0.1-prealpha` — tested decision kernel + read-only Kubernetes node-drain preflight. Production mutation is not implemented.

## Design principle

**Evidence before action.**
