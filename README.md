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

StateLatch now contains a read-only Kubernetes adapter for **node-drain assessment**.

Using the official Go client, it reads live cluster state and derives:

```text
Node metadata.resourceVersion
Node Ready condition
Active pods scheduled on the node
Observed timestamp
```

That state is translated into the decision kernel:

```text
Kubernetes API
     |
     +--> node_health evidence
     +--> resourceVersion
     +--> active-pod blast radius
               |
               v
        StateLatch decision
               |
      ALLOW / BLOCK / ESCALATE
```

The agent does **not** supply the trusted `resourceVersion` or blast-radius count.

See [`docs/kubernetes-node-drain.md`](docs/kubernetes-node-drain.md).

## Example

If Kubernetes reports three active pods on `node-7` while policy allows at most two:

```text
Action:          drain node-7
resourceVersion: 928441
Active pods:     3
Maximum allowed: 2

→ BLOCK
→ BLAST_RADIUS_EXCEEDED
```

When all hard gates pass, `ALLOW` carries a short-lived authorization bound to:

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
- in-cluster and kubeconfig client construction

Not implemented yet:

- actually draining or mutating a Kubernetes node
- Kubernetes server-side dry-run
- eviction/PDB/DaemonSet-aware drain simulation
- Prometheus evidence adapter/cache
- multi-source live evidence
- AWS/GCP, SSH, databases, PLC, or financial execution
- dashboard / SaaS

## Current guarantees

The current decision kernel does not autonomously allow an action when:

- required evidence is stale;
- evidence for the same claim contradicts;
- blast radius exceeds the configured hard limit;
- required independent sources are missing;
- state-binding information is incomplete.

A minted authorization is invalidated if it expires or if its action, target, or resource version changes before execution.

## Important limit

The first Kubernetes blast-radius metric is intentionally conservative: it counts non-terminal pods scheduled on the target node. It does **not** yet claim to reproduce the exact set of pods that `kubectl drain` would evict.

## Current status

`v0.1-prealpha` — tested decision kernel + read-only Kubernetes node-drain adapter. Production mutation is not implemented.

## Design principle

**Evidence before action.**
