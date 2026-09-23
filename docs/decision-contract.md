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

## Hard-gate rule

A high aggregate score must never compensate for failure of a mandatory safety predicate.

For `v0.1`, these predicates begin with:

1. required evidence is within its maximum allowed age;
2. fresh observations about the same operational fact do not contradict one another;
3. the configured minimum number of distinct evidence sources is present.

Duplicate observations from the same source count as one source.

Later gates may include blast-radius limits, Kubernetes server-side dry-run, invariants, and state-version binding.

## Reason codes

Initial reason codes:

```text
EVIDENCE_STALE
EVIDENCE_CONTRADICTED
INSUFFICIENT_EVIDENCE
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
