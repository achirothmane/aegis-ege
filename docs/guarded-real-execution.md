# Guarded experimental execution

StateLatch contains a real Kubernetes node-drain execution primitive, but it is intentionally disabled by default.

## Explicit opt-in

The normal constructor is read/dry-run/revalidation only:

```go
adapter, err := NewForConfig(config)
```

Calling `ExecuteAuthorizedNodeDrain(...)` on that adapter returns:

```text
ESCALATE / REAL_EXECUTION_UNAVAILABLE
```

The experimental mutation path must be selected explicitly:

```go
adapter, err := NewForConfigWithExperimentalMutations(config)
```

v0.1 uses this path only for controlled KinD integration tests. It is not a production-mode switch.

## Execution sequence

Given a previously prepared, plan-bound authorization:

```text
ExecuteAuthorizedNodeDrain
  ↓
RevalidateNodeDrainAuthorization
  ↓
real CORDON_NODE using observed Node resourceVersion
  ↓
verify:
  - authorization TTL
  - action + target
  - Node UID
  - Node health
  - node still unschedulable
  - current Pod/PDB preflight
  - remaining semantic Pod set
  ↓
real EVICT_POD using Pod UID precondition
  ↓
wait until that exact UID is absent
  ↓
re-read everything
  ↓
next eviction or stop
  ↓
final empty-plan revalidation
```

## Fail-closed behavior

Examples:

```text
Node changes before real cordon
→ ESCALATE / RESOURCE_VERSION_CHANGED

Pod semantic state changes after cordon
→ ESCALATE / EXECUTION_PLAN_CHANGED

node becomes schedulable again
→ ESCALATE / EXECUTION_CORDON_STATE_CHANGED

PDB becomes restrictive
→ BLOCK / PDB_DISRUPTION_BLOCKED

Eviction API sees a PDB race
→ BLOCK / PDB_DISRUPTION_BLOCKED

authorization expires mid-execution
→ ESCALATE / AUTHORIZATION_EXPIRED

accepted eviction is not observed before timeout
→ ESCALATE / EXECUTION_EVICTION_NOT_OBSERVED
```

StateLatch does not automatically retry a Node resourceVersion conflict with a newer version. Doing so would bypass the state version that was actually revalidated.

## Why revalidate between evictions

A drain is not one atomic Kubernetes operation.

After the node is cordoned:

- PDB state can change;
- labels can change and alter PDB matching;
- a workload can be replaced;
- a Pod can disappear or a new Pod can appear;
- authorization can expire;
- another actor can uncordon or change the Node.

Therefore the authorized plan is treated as a sequence of state transitions, not a batch of mutations that may be replayed blindly.

## Server-enforced preconditions

StateLatch currently relies on Kubernetes for the final race window:

### Node

The real cordon carries the observed Node `resourceVersion`.

If another writer modifies the Node first, Kubernetes rejects the patch.

### Pod

The real Eviction object carries the observed Pod UID as a delete precondition.

A replacement Pod with the same name cannot be mistaken for the authorized object.

### PDB

The real Eviction API evaluates current disruption policy again at mutation time.

This is important because StateLatch's preflight and the mutation cannot be one atomic transaction.

## Live KinD evidence

The CI suite performs real mutations against a temporary cluster.

It verifies:

1. an authorized unmanaged test Pod can be prepared, dry-run, revalidated, then actually drained;
2. the target Node remains cordoned;
3. the exact Pod is actually removed;
4. a semantic Pod-label change injected after the real cordon is detected before the eviction and the Pod remains;
5. mutation execution is disabled on the default adapter.

## Current limitations

This is not yet a production drain implementation.

Missing areas include:

- mature termination and retry handling;
- rollback/recovery after partial execution;
- exact `kubectl drain` behavior across all workload edge cases;
- production observability and audit persistence;
- explicit production enablement and operational controls;
- stronger server-side enforcement for semantic conditions that cannot be represented as Kubernetes preconditions.

The experimental execution path demonstrates the StateLatch primitive:

**authorization remains attached to the verified state throughout a multi-step real action, rather than being checked only once before execution.**
