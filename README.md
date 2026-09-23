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

- `ALLOW` — required evidence gates passed.
- `BLOCK` — a hard safety predicate failed.
- `ESCALATE` — evidence is insufficient for autonomous execution but does not justify a hard block.

An `ALLOW` must eventually be bound to the state that justified it, so a changed `resourceVersion`, expired evidence lease, or mutated action invalidates the authorization before execution.

See [`docs/decision-contract.md`](docs/decision-contract.md).

## v0.1 scope

In scope:

- Kubernetes action requests
- evidence freshness
- evidence contradiction detection
- hard safety predicates
- explicit reason codes
- state-bound authorization contract

Not in scope yet:

- AWS/GCP
- SSH or databases
- PLC / OPC-UA / Modbus
- financial execution
- dashboards / SaaS
- general digital twins
- adaptive reliability scoring
- multi-node consensus

## Guarantee we want to prove

StateLatch should never convert stale or contradictory required evidence into an autonomous `ALLOW`.

That guarantee is more important than a single aggregate confidence score.

## Current status

`v0.1-prealpha` — contract-first prototype.

## Design principle

**Evidence before action.**
