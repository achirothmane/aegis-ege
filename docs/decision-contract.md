# StateLatch v0.1 decision contract

## Purpose

The decision engine evaluates whether a proposed production action has enough trustworthy, current world-state evidence to proceed autonomously.

The engine returns one of:

- `ALLOW`
- `BLOCK`
- `ESCALATE`

## Decision semantics

- `BLOCK` means a hard safety predicate is known to have failed.
- `ESCALATE` means the system does not have enough independent evidence to authorize the action autonomously.
- `ALLOW` means the currently implemented hard gates passed.

## Evidence model

Every observation is attached to an explicit claim:

```text
Claim:      node_health
Source:     prometheus-a
Value:      unhealthy
ObservedAt: ...
```

Contradiction is evaluated **within a claim**, not across unrelated facts.

For example, these observations do not contradict one another:

```text
node_health = healthy
cpu_pressure = high
```

But these do:

```text
node_health / prometheus-a = healthy
node_health / prometheus-b = unhealthy
```

## Blast radius model

Blast radius is a hard action-risk bound, not a confidence score.

For a Kubernetes node drain, the first concrete unit can be the number of affected pods:

```text
blast_radius     = 31
max_blast_radius = 10
→ BLOCK / BLAST_RADIUS_EXCEEDED
```

In the current decision kernel, the caller supplies the numeric blast radius. This is intentionally temporary. The Kubernetes adapter must eventually derive it independently from live cluster state rather than trusting a value proposed by an agent.

## Hard-gate rule

A high aggregate score must never compensate for failure of a mandatory safety predicate.

For `v0.1`, these predicates begin with:

1. required evidence is within its maximum allowed age;
2. fresh observations of the same claim do not contradict one another;
3. action blast radius stays within its configured hard limit;
4. the configured minimum number of distinct evidence sources is present.

Duplicate observations from the same source count as one source.

Current limitation: `RequiredSourceCount` is request-wide. A later step may make source requirements claim-specific when the action contract requires different evidence thresholds for different claims.

Later gates may include Kubernetes server-side dry-run, invariants, and state-version binding.

## Reason codes

Initial reason codes:

```text
EVIDENCE_STALE
EVIDENCE_CONTRADICTED
INSUFFICIENT_EVIDENCE
BLAST_RADIUS_EXCEEDED
```

Reason codes are machine-readable.

## State-bound authorization

A future `ALLOW` result must carry enough information to detect time-of-check/time-of-use invalidation before execution.

Target shape:

```json
{
  "decision": "ALLOW",
  "action_id": "act_123",
  "target": "deployment/api",
  "evidence_digest": "sha256:...",
  "resource_version": "928441",
  "valid_until": "2026-09-23T12:00:05Z",
  "max_blast_radius": 5
}
```

Execution must be re-evaluated when any bound property is no longer valid.
