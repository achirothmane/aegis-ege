# StateLatch v0.1 decision contract

## Purpose

StateLatch decides whether a proposed production action has enough trustworthy, current, state-bound evidence to proceed autonomously.

The engine returns:

- `ALLOW`
- `BLOCK`
- `ESCALATE`

## Semantics

- `BLOCK`: a hard safety predicate is known to have failed.
- `ESCALATE`: evidence, state binding, or authorization validity is insufficient for autonomous execution.
- `ALLOW`: all currently implemented mandatory gates passed.

## Hard gates

For v0.1 these include:

1. evidence freshness;
2. no contradiction within the same claim;
3. blast radius within the configured hard limit;
4. required distinct evidence sources present;
5. action / target / resource-version state binding;
6. short authorization TTL;
7. for prepared Kubernetes drains, a bound execution-plan digest.

For the Kubernetes drain adapter, blast radius is derived from live preflight eviction candidates rather than supplied by the agent.

## Reason codes

```text
EVIDENCE_STALE
EVIDENCE_CONTRADICTED
INSUFFICIENT_EVIDENCE
BLAST_RADIUS_EXCEEDED
INSUFFICIENT_STATE_BINDING
AUTHORIZATION_EXPIRED
RESOURCE_VERSION_CHANGED
EXECUTION_PLAN_CHANGED
ACTION_CHANGED
TARGET_CHANGED
```

Kubernetes-specific preflight and dry-run reason codes are added by the adapter layer.

## Authorization

A prepared drain authorization includes bindings equivalent to:

```json
{
  "action_id": "act-drain-node-7",
  "action": "drain",
  "target": "node/node-7",
  "resource_version": "928441",
  "evidence_digest": "sha256:...",
  "plan_digest": "sha256:...",
  "valid_until": "2026-09-23T12:00:05Z"
}
```

`evidence_digest` binds the decision to the observed evidence snapshot for traceability.

`plan_digest` binds the authorization to the complete deterministic Kubernetes execution plan.

## Authorization validation

`ValidateAuthorization` rejects an authorization when:

```text
TTL expired
→ AUTHORIZATION_EXPIRED

Node/resource version changed
→ RESOURCE_VERSION_CHANGED

execution plan digest changed
→ EXECUTION_PLAN_CHANGED

action/action ID changed
→ ACTION_CHANGED

target changed
→ TARGET_CHANGED
```

## Final live Kubernetes revalidation

`RevalidateNodeDrainAuthorization(...)` performs the live adapter-level TOCTOU check.

It:

1. re-reads Node and Pods;
2. re-reads and reevaluates PDB state;
3. reruns drain preflight;
4. rebuilds the deterministic drain plan;
5. recomputes `plan_digest`;
6. validates resource version, plan digest, target, action, and TTL.

A preflight hard failure remains `BLOCK`.

State drift such as an expired authorization or changed execution plan returns `ESCALATE`, forcing a fresh preparation instead of autonomous continuation.

A mismatched action or target is treated as `BLOCK`.

## Remaining boundary

Final revalidation narrows the TOCTOU window but cannot remove it by itself. Future real mutation requests must retain Kubernetes state preconditions so a change after revalidation is rejected by the API server.
