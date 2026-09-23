# Kubernetes node-drain adapter

StateLatch v0.1 implements a read-only preparation path for a proposed Kubernetes node drain.

## Inputs taken from Kubernetes

The adapter reads:

- Node object and `metadata.resourceVersion`;
- Node `Ready` condition;
- Pods scheduled on the node;
- Pod UID and `resourceVersion`;
- PodDisruptionBudgets.

The agent does not provide these trusted values.

## Preflight

Before an execution plan is built, StateLatch checks:

- DaemonSet-managed Pods;
- mirror/static Pods;
- unmanaged Pods;
- `emptyDir` data;
- matching PDB disruption capacity;
- PDB status freshness.

A preflight `BLOCK` or `ESCALATE` prevents plan authorization.

## Execution plan

For an allowed candidate, StateLatch builds:

```text
CORDON_NODE(node, nodeResourceVersion)
EVICT_POD(namespace/name, podUID, podResourceVersion)
EVICT_POD(...)
```

Eviction candidates are sorted by namespace/name so plan generation is deterministic.

The generic blast-radius gate uses the preflight-derived evictable Pod count.

## Server-side dry-run

The live client performs:

### Cordon

A merge patch sets:

```text
spec.unschedulable = true
```

with:

```text
metadata.resourceVersion = observed node version
dryRun = All
```

### Eviction

Each Pod uses the `policy/v1` Eviction API with:

```text
DeleteOptions.DryRun = [All]
Preconditions.UID = observed Pod UID
Preconditions.ResourceVersion = observed Pod resourceVersion
```

This makes the dry-run fail if the named Pod has been replaced or its state version no longer matches the plan.

## Execution-readiness API

Use:

```go
PrepareNodeDrainExecution(...)
```

for the strongest current gate.

`EvaluateNodeDrain(...)` remains an assessment method. It should not be treated as equivalent to successful server-side execution preparation.

## Fail-closed behavior

```text
dry-run executor unavailable
→ ESCALATE

cordon rejected by API/admission/state precondition
→ BLOCK

any eviction rejected
→ BLOCK

authorization expires while preparing
→ ESCALATE
```

No failed preparation exposes an execution authorization.

## Limits

This does not execute a drain.

Server-side dry-run does not persist state. Therefore:

- a dry-run cordon does not actually make the node unschedulable;
- dry-run evictions do not decrement PDB disruption budget;
- concurrent cluster changes can invalidate the plan after dry-run;
- exact `kubectl drain` behavior is not reproduced yet;
- unhealthy-Pod eviction-policy nuances and orphaned controller resolution are still incomplete.

These are explicit remaining execution-safety gaps.
