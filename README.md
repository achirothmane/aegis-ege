# StateLatch

**Evidence-gated authorization for autonomous Kubernetes actions.**

StateLatch asks one extra question before automation changes production:

> Is the world-state evidence that justified this action still fresh, consistent, and sufficient **right now**?

It is not a general AI governance platform. `v0.1` focuses on one narrow primitive: deciding whether a proposed Kubernetes action should be **ALLOW**, **BLOCK**, or **ESCALATE** based on independently observed evidence.

## Problem

Identity and policy can say an action is permitted while the operational evidence behind the action is stale, contradictory, or no longer valid.

```text
Agent proposes action
        |
        v
Identity allows it? -------- no --> BLOCK
        |
       yes
        v
Policy allows it? ---------- no --> BLOCK
        |
       yes
        v
Evidence fresh + consistent + sufficient?
        |
   +----+----+
   |         |
  yes        no
   |         |
   v         v
 ALLOW   BLOCK / ESCALATE
```

## 60-second quickstart

Requires Go 1.24+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch
go test ./...
```

## First scenario

An agent proposes draining `node-7`.

```text
Kubernetes state:    Ready
Prometheus source A: unhealthy
Prometheus source B: healthy
Evidence age:        72s
Allowed age:         10s
Affected pods:       31
```

Expected decision:

```json
{
  "decision": "BLOCK",
  "reason_codes": [
    "EVIDENCE_STALE",
    "EVIDENCE_CONTRADICTED"
  ]
}
```

No production action is executed.

## Decision contract

StateLatch v0.1 exposes three decisions:

- `ALLOW` — required evidence gates passed and a short-lived state-bound authorization was minted.
- `BLOCK` — a hard safety predicate failed.
- `ESCALATE` — evidence or binding information is insufficient for autonomous execution.

A successful `ALLOW` is bound to the exact action, target, resource version, evidence snapshot digest, and validity window. If the execution-time state no longer matches, the authorization becomes invalid.

See [`docs/decision-contract.md`](docs/decision-contract.md).

## v0.1 scope

In scope:

- Kubernetes action requests
- evidence freshness
- claim-scoped contradiction detection
- distinct-source requirements
- blast-radius hard limits
- explicit reason codes
- state-bound authorization
- first TOCTOU invalidation checks

Not in scope yet:

- live Kubernetes API integration
- Prometheus adapter/cache
- AWS/GCP
- SSH or databases
- PLC / OPC-UA / Modbus
- financial execution
- dashboards / SaaS
- general digital twins
- adaptive reliability scoring
- multi-node consensus

## Current guarantees

The current decision kernel does not autonomously allow an action when:

- required evidence is stale;
- evidence for the same claim contradicts;
- blast radius exceeds the configured hard limit;
- required independent sources are missing;
- state-binding information is incomplete.

A minted authorization is invalidated if it expires or if its action, target, or resource version changes before execution.

## Current status

`v0.1-prealpha` — contract-first decision kernel. Live Kubernetes state collection and execution are not implemented yet.

## Design principle

**Evidence before action.**
