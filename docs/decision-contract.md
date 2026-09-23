# StateLatch v0.1 decision contract

## Purpose

The decision engine evaluates whether a proposed production action has enough trustworthy, current world-state evidence to proceed autonomously.

The engine returns one of:

- `ALLOW`
- `BLOCK`
- `ESCALATE`

## Decision semantics

- `BLOCK` means a hard safety predicate is known to have failed.
- `ESCALATE` means the system does not have enough evidence or state-binding information to authorize the action autonomously.
- `ALLOW` means the currently implemented hard gates passed and a short-lived state-bound authorization was minted.

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

In the current decision kernel, the caller supplies the numeric blast radius. This is temporary. The Kubernetes adapter must eventually derive it independently from live cluster state rather than trusting a value proposed by an agent.

## Hard-gate rule

A high aggregate score must never compensate for failure of a mandatory safety predicate.

For `v0.1`, these predicates currently include:

1. required evidence is within its maximum allowed age;
2. fresh observations of the same claim do not contradict one another;
3. action blast radius stays within its configured hard limit;
4. the configured minimum number of distinct evidence sources is present;
5. an `ALLOW` has enough binding data to attach execution to a specific action, target, resource version, evidence snapshot, and validity window.

Duplicate observations from the same source count as one source.

Current limitation: `RequiredSourceCount` is request-wide. A later step may make source requirements claim-specific.

## Reason codes

Current reason codes:

```text
EVIDENCE_STALE
EVIDENCE_CONTRADICTED
INSUFFICIENT_EVIDENCE
BLAST_RADIUS_EXCEEDED
INSUFFICIENT_STATE_BINDING
AUTHORIZATION_EXPIRED
RESOURCE_VERSION_CHANGED
ACTION_CHANGED
TARGET_CHANGED
```

## State-bound authorization

An `ALLOW` includes:

```json
{
  "decision": "ALLOW",
  "authorization": {
    "action_id": "act-drain-node-7",
    "action": "drain",
    "target": "node/node-7",
    "resource_version": "928441",
    "evidence_digest": "sha256:...",
    "valid_until": "2026-09-23T12:00:05Z"
  }
}
```

Before execution, `ValidateAuthorization` rejects the authorization when:

```text
validity window expired → AUTHORIZATION_EXPIRED
resourceVersion changed → RESOURCE_VERSION_CHANGED
action or action ID changed → ACTION_CHANGED
target changed → TARGET_CHANGED
```

The evidence digest is deterministic and binds the authorization to the evidence snapshot for traceability. Runtime comparison against a newly collected evidence snapshot is not implemented yet; that will belong to the live adapter/re-evaluation path.

This closes the first TOCTOU gap between "state checked" and "action executed" without pretending the system already has a live Kubernetes integration.
