# Kubernetes node-drain adapter

StateLatch v0.1 implements preparation, revalidation, and an explicitly opt-in guarded real-execution path for a proposed Kubernetes node drain. Real mutations are disabled by default.

## Trusted live inputs

The adapter reads from Kubernetes:

- Node object and `metadata.resourceVersion`;
- Node `Ready` condition;
- Pods scheduled on the node;
- Pod UID and raw `resourceVersion`;
- drain-relevant Pod semantic state;
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
EVICT_POD(namespace/name, podUID, podStateDigest)
EVICT_POD(...)
```

Eviction candidates are sorted by namespace/name.

The complete ordered plan is hashed into `plan_digest`.

### Pod state binding

A Pod's raw `resourceVersion` is observed but is not part of the plan identity.

Live KinD testing showed that Kubernetes may update Pod `resourceVersion` due to status/controller churn between observation and dry-run. Treating every such change as execution drift caused false invalidation.

The plan instead binds to a semantic digest containing:

```text
namespace
name
UID
nodeName
labels
controller identity
mirror annotation
emptyDir presence
phase
Ready condition
deletion state
```

This means status noise that does not affect drain semantics is ignored, while changes that can alter preflight, PDB matching, identity, or eviction meaning invalidate the plan.

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

Use immediately before guarded execution:

```go
RevalidateNodeDrainAuthorization(...)
```

It performs a new live read and preflight, rebuilds the plan, then compares current state against the authorization.

```text
same semantic plan
→ ALLOW

drain-relevant Pod state changed
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
```

UID prevents a replacement Pod with the same namespace/name from being mistaken for the authorized object.

## Guarded experimental execution

The default adapter cannot perform real mutations.

For KinD integration work only, the explicit experimental constructor enables `ExecuteAuthorizedNodeDrain(...)`.

The execution path:

```text
final revalidation
→ real cordon with Node resourceVersion precondition
→ verify Node UID + health + cordon state
→ rerun Pod/PDB preflight
→ compare remaining semantic Pod set
→ real eviction with Pod UID precondition
→ wait for that UID to disappear
→ revalidate before the next eviction
```

Node resourceVersion conflicts are not retried blindly. They return `ESCALATE / RESOURCE_VERSION_CHANGED`.

## Live integration tests

The KinD CI now exercises five live Kubernetes scenarios:

1. dry-run cordon and eviction are accepted but not persisted;
2. a healthy ReplicaSet Pod protected by a zero-disruption PDB is rejected by the Eviction API and by StateLatch;
3. a label change after preparation changes the semantic plan digest and causes final revalidation to escalate;
4. guarded experimental execution persists a real cordon and real eviction;
5. a semantic change injected after cordon stops execution before eviction.

The PDB fixture explicitly marks the synthetic test Pod `Running` and `Ready=True`, because Kubernetes treats `Pending` Pods differently for eviction.

## Limits

The real execution path is experimental and default-disabled.

StateLatch does not yet provide production-grade drain retry, rollback, observability, or exact `kubectl drain` parity. State can still change inside the final userspace-to-API race window, so production semantics require additional server-enforced constraints and recovery work.
