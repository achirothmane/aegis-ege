# Kubernetes node-drain adapter

StateLatch v0.1 includes a read-only assessment path for a proposed Kubernetes node drain.

## What it reads

The adapter uses `client-go` to query the Kubernetes API directly.

For a target node it reads:

1. the Node object;
2. `metadata.resourceVersion`;
3. the Node `Ready` condition;
4. Pods whose `spec.nodeName` matches the target node;
5. PodDisruptionBudgets.

The Pod lookup uses a field selector instead of trusting the caller to provide affected resources.

## Drain preflight

Before `EvaluateNodeDrain` reaches the generic decision kernel, StateLatch evaluates drain-specific conditions.

### DaemonSet-managed Pods

By default:

```text
DaemonSet pod present
→ BLOCK
→ DAEMONSET_POD_REQUIRES_IGNORE
```

If `IgnoreDaemonSets=true`, DaemonSet Pods are excluded from the evictable count.

### Mirror / static Pods

Pods with the mirror annotation are recorded as:

```text
MIRROR_POD_SKIPPED
```

They are not counted as evictable Pods.

### Unmanaged Pods

A Pod without one of the currently recognized workload controllers requires explicit force policy:

```text
ForceUnmanagedPods=false
→ BLOCK
→ UNMANAGED_POD_REQUIRES_FORCE
```

Current recognized controller kinds are:

```text
ReplicationController
ReplicaSet
DaemonSet
StatefulSet
Job
```

### emptyDir

If an evictable Pod uses `emptyDir`:

```text
DeleteEmptyDirData=false
→ BLOCK
→ EMPTYDIR_DATA_REQUIRES_DELETE
```

### PodDisruptionBudgets

For every matching PDB, StateLatch first checks whether:

```text
status.observedGeneration == metadata.generation
```

If not:

```text
→ ESCALATE
→ PDB_STATUS_STALE
```

For a current PDB status, StateLatch counts candidate Pods on the node that match the PDB selector.

If:

```text
matching target pods > status.disruptionsAllowed
```

then:

```text
→ BLOCK
→ PDB_DISRUPTION_BLOCKED
```

If PDB state cannot be read at all:

```text
→ ESCALATE
→ PDB_EVIDENCE_UNAVAILABLE
```

This is deliberately fail-closed.

## Derived state

The adapter produces:

```text
NodeName
ResourceVersion
NodeHealth
ActivePods
ObservedAt
```

The preflight additionally derives:

```text
EvictablePods
SkippedMirrorPods
SkippedDaemonSetPods
Findings
```

The generic blast-radius gate uses the preflight's `EvictablePods`, not a value supplied by the agent.

## Decision handoff

Only when preflight returns `ALLOW` does `EvaluateNodeDrain` invoke the generic decision kernel:

```text
Action          = drain
Target          = node/<name>
ResourceVersion = value read from Kubernetes
BlastRadius     = preflight-derived evictable pods
Evidence claim  = node_health
Evidence source = kubernetes-api
```

A preflight `BLOCK` or `ESCALATE` cannot mint a state-bound authorization.

## Live client construction

The adapter supports:

- `NewInCluster()` for a Pod running inside Kubernetes;
- `NewFromKubeconfig(path)` for an external process;
- `NewForConfig(config)` when the caller already owns a `rest.Config`.

The service account or kubeconfig must have permission to read Nodes, Pods, and PDBs.

## Current multi-source behavior

This adapter contributes one independent evidence source: `kubernetes-api`.

If policy sets `RequiredSourceCount > 1`, the current node-drain path returns `ESCALATE / INSUFFICIENT_EVIDENCE` until another live adapter contributes an independent observation.

## Important limits

The preflight intentionally does not claim exact `kubectl drain` parity.

Current limitations include:

- PDB evaluation is conservative and does not yet model every `unhealthyPodEvictionPolicy` nuance;
- missing/orphaned controller objects are not independently resolved yet;
- eviction ordering is not simulated;
- admission webhooks and server-side eviction responses are not probed;
- no node cordon or Pod eviction is executed.

These are candidates for the next execution-safety layer, not hidden assumptions.

## What this does not do

This adapter remains read-only. It does not:

- cordon a node;
- evict Pods;
- invoke `kubectl drain`;
- bypass Kubernetes RBAC;
- claim that a production drain is safe merely because preflight returned `ALLOW`.

`ALLOW` currently means that the implemented evidence, preflight, risk, and state-binding gates passed.
