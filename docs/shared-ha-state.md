# M9 — shared durable state and HA recovery

M9 removes the production dependency on process-local checkpoint and replay files.

## Shared checkpoint store

Production state can now use Kubernetes ConfigMaps as a shared checkpoint backend.

Each checkpoint is stored under a deterministic name derived from ActionID.

Load returns the ConfigMap resourceVersion as an opaque StoreVersion.

Update requires that exact version.

If another replica updates first:

stale replica update
→ Kubernetes conflict
→ ErrDrainCheckpointConflict
→ fail closed

StateLatch never silently overwrites newer checkpoint progress.

## Version propagation

The execution/recovery path now recognizes version-aware checkpoint stores.

After every successful shared save, the returned store version is propagated back into the in-memory checkpoint before the next mutation boundary.

Existing memory/file stores remain supported for tests and local development.

## Shared replay guard

Execution replay claims can also be stored as Kubernetes ConfigMaps.

The claim uses atomic create semantics.

Replica A:
claim authorization
→ ConfigMap created

Replica B:
claim same authorization
→ AlreadyExists
→ EXECUTION_REPLAY_REJECTED

This prevents the same state-bound authorization from being consumed by two daemon replicas.

## Cross-replica recovery proof

The KinD M9 recovery test uses:

- replica A with an injected post-eviction interruption;
- Kubernetes-backed shared checkpoint storage;
- a distinct adapter instance acting as replica B.

Replica B:

1. loads the checkpoint created by replica A;
2. reconstructs live world state;
3. reconciles the eviction Kubernetes already accepted;
4. requires fresh authorization for the remainder;
5. resumes the drain;
6. commits the shared checkpoint as COMPLETED.

No process-local checkpoint memory is shared between the two adapters.

## Production daemon default

When mutation mode is enabled, state-latchd now defaults to:

state-backend=kubernetes

with a configurable state namespace.

The file backend remains available for local/single-process development.

M13 packaging will provide a dedicated StateLatch namespace and least-privilege RBAC for these ConfigMaps.

## Current HA boundary

M9 makes checkpoint and replay state shared, versioned, and restart-safe.

It does not yet provide:

- external database replication;
- multi-cluster state;
- cross-cluster failover;
- immutable audit storage;
- automatic garbage collection of old claims/checkpoints.

Those are not required for the single-cluster v1 node-drain product.
