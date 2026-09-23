# Kubernetes node-drain adapter

StateLatch v0.1 includes its first live infrastructure adapter: a read-only assessment path for a proposed Kubernetes node drain.

## What it reads

The adapter uses `client-go` to query the Kubernetes API directly.

For a target node it reads:

1. the Node object;
2. `metadata.resourceVersion`;
3. the Node `Ready` condition;
4. Pods whose `spec.nodeName` matches the target node.

The Pod lookup uses a Kubernetes field selector instead of listing every Pod and trusting the caller to provide affected resources.

## Derived state

The adapter produces:

```text
NodeName
ResourceVersion
NodeHealth
ActivePods
ObservedAt
```

`ActivePods` counts Pods whose phase is not `Succeeded` or `Failed`.

This is a conservative first blast-radius metric. It is not yet an exact drain planner: DaemonSets, mirror/static Pods, eviction rules, PodDisruptionBudgets, local storage, and other drain-specific behavior are not modeled yet.

## Decision handoff

`EvaluateNodeDrain` builds the decision request itself:

```text
Action          = drain
Target          = node/<name>
ResourceVersion = value read from Kubernetes
BlastRadius     = active pods observed on the node
Evidence claim  = node_health
Evidence source = kubernetes-api
```

The agent therefore cannot lower the blast-radius value or substitute an older resource version in this path.

## Live client construction

The adapter supports:

- `NewInCluster()` for a Pod running inside Kubernetes;
- `NewFromKubeconfig(path)` for an external process;
- `NewForConfig(config)` when the caller already owns a `rest.Config`.

## Current multi-source behavior

This adapter contributes one independent evidence source: `kubernetes-api`.

If policy sets `RequiredSourceCount > 1`, the current node-drain path will return `ESCALATE / INSUFFICIENT_EVIDENCE` until another live adapter, such as Prometheus, contributes an independent observation.

## What this does not do

This adapter is read-only. It does not:

- cordon a node;
- evict Pods;
- invoke `kubectl drain`;
- perform server-side dry-run;
- bypass Kubernetes RBAC;
- guarantee that a drain is operationally safe.

Those capabilities require separate execution and invariant layers.
