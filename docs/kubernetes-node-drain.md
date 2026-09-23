# Kubernetes node-drain adapter

StateLatch v0.1 implements a read-only preparation and revalidation path for a proposed Kubernetes node drain.

## Trusted live inputs

The adapter reads from Kubernetes:

- Node object and `metadata.resourceVersion`;
- Node `Ready` condition;
- Pods scheduled on the node;
- Pod UID and `resourceVersion`;
- PodDisruptionBudgets.

The agent does not provide these trusted values.

## Preflight

StateLatch checks:

- DaemonSet-managed Pods;
- mirror/static Pods;
- unmanaged Pods;
- `emptyDir` data;
- PDB disruption capacity;
- PDB status freshness.

A preflight `BLOCK` or `ESCALATE` prevents execution authorization.

## Deterministic execution plan

For an allowed candidate:

```text
CORDON_NODE(node, nodeResourceVersion)
EVICT_POD(namespace/name, podUID, podResourceVersion)
EVICT_POD(...)
```

Eviction candidates are sorted by namespace/name.

The complete ordered plan is hashed into `plan_digest`.

## Preparation

Use:

```go
PrepareNodeDrainExecution(...)
```

It performs:

```text
live read
→ preflight
→ evidence/risk decision
→ build plan
→ plan digest
→ server-side dry-run
→ plan-bound short-lived authorization
```

## Final live revalidation

Use immediately before future real execution:

```go
RevalidateNodeDrainAuthorization(...)
```

It performs a new live read and preflight, rebuilds the plan, then compares current state against the authorization.

Examples:

```text
same plan
→ ALLOW

Pod UID/resourceVersion changed
→ ESCALATE / EXECUTION_PLAN_CHANGED

Node resourceVersion changed
→ ESCALATE / RESOURCE_VERSION_CHANGED

current PDB blocks drain
→ BLOCK / PDB_DISRUPTION_BLOCKED

TTL expired
→ ESCALATE / AUTHORIZATION_EXPIRED
```

## Server-side operations used during preparation

### Cordon dry-run

A merge patch sets:

```text
spec.unschedulable = true
metadata.resourceVersion = observed node version
dryRun = All
```

### Eviction dry-run

Each Pod uses `policy/v1` Eviction with:

```text
DeleteOptions.DryRun = [All]
Preconditions.UID = observed Pod UID
Preconditions.ResourceVersion = observed Pod resourceVersion
```

## Limits

StateLatch still does not execute a real drain.

Final live revalidation narrows state drift between preparation and execution, but the future mutation path must preserve the same resource-version and UID preconditions because state can still change after revalidation.
