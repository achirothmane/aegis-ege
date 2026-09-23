# Execution locking

StateLatch uses Kubernetes `coordination.k8s.io/v1 Lease` objects to enforce a single active StateLatch executor per mutation target.

Real mutations remain experimental and disabled by default.

## Why authorization is not enough

Authorization answers:

```text
Is this exact action justified by the verified state?
```

The execution Lease answers a different question:

```text
Is this StateLatch executor the only cooperating executor allowed to mutate this target right now?
```

Both gates must pass before a real node-drain mutation.

## Lock key

The lock target for the current node-drain adapter is:

```text
node/<node-name>
```

StateLatch derives a deterministic Lease name from SHA-256(target), so two independent StateLatch processes targeting the same Node converge on the same Kubernetes Lease object.

Each execution attempt receives a random 128-bit holder identity.

The action ID is intentionally **not** used as the holder identity: two concurrent processes can carry the same action ID and must still contend as separate executors.

## Acquisition

Before final mutation-time revalidation:

```text
Acquire Lease
→ Revalidate authorization and live plan
→ checkpoint if enabled
→ mutate
```

An active Lease owned by another holder produces:

```text
ESCALATE / EXECUTION_LOCK_HELD
```

No cordon or eviction is attempted.

If the Lease API is unavailable, RBAC denies access, or no lock manager is configured:

```text
ESCALATE / EXECUTION_LOCK_UNAVAILABLE
```

Real execution fails closed.

## Renewal

The default Lease duration is 30 seconds.

It can be configured through:

```go
NodeDrainPolicy{
    ExecutionLockDuration: 30 * time.Second,
}
```

StateLatch renews in two ways:

1. background renewal approximately every one-third of the Lease duration;
2. synchronous renewal/ownership verification before every real mutation boundary.

If `holderIdentity` changes, the Lease disappears, or renewal cannot prove continuing ownership:

```text
ESCALATE / EXECUTION_LOCK_LOST
```

No subsequent mutation is issued.

## Release and crash behavior

On normal completion or a controlled stop, StateLatch releases the Lease.

If the process crashes, the Lease remains until its duration expires.

A new executor cannot acquire the same target while the old Lease is still active. After expiry, a new unique holder may take ownership and then perform the normal StateLatch recovery flow:

```text
expired Lease
→ new executor acquires Lease
→ reconcile checkpoint with Kubernetes reality
→ fresh authorization if work remains
→ resume verified remainder
```

The Lease does not make an old authorization reusable.

## Namespace

By default, execution Leases are stored in:

```text
kube-system
```

The namespace is configurable:

```go
NodeDrainPolicy{
    ExecutionLockNamespace: "state-latch-system",
}
```

A dedicated namespace is preferable for a deployed installation because it gives a clean RBAC and audit boundary.

## RBAC

The mutation identity needs Lease access in the configured namespace:

```yaml
apiGroups: ["coordination.k8s.io"]
resources: ["leases"]
verbs: ["get", "create", "update", "delete"]
```

Read/dry-run-only StateLatch usage does not require the mutation lock path.

## Live KinD evidence

The integration suite proves the concurrency gate against a real Kubernetes API server:

```text
holder A acquires Lease for node/X
→ holder B obtains a valid StateLatch authorization
→ holder B attempts real execution
→ ESCALATE / EXECUTION_LOCK_HELD
→ Node remains schedulable
→ Pod remains present
→ holder A releases Lease
→ holder B obtains fresh authorization
→ guarded drain can execute
```

The unit suite also injects lock loss after cordon and verifies that no Pod eviction follows.

## Important boundary: coordination is not fencing

Kubernetes Lease is a coordination primitive for cooperating StateLatch executors.

It does **not** prevent:

- `kubectl` from changing the Node;
- another controller from changing Pods;
- an actor that ignores the Lease from issuing its own mutation.

StateLatch still relies on:

- Node `resourceVersion` optimistic-concurrency checks;
- Pod UID preconditions;
- live PDB enforcement;
- in-flight semantic revalidation;
- postflight outcome verification.

There is also a residual interval between the last Lease verification and completion of an individual Kubernetes API mutation. A stronger future production design may need a fencing epoch/token that the mutation target itself enforces.

The current guarantee is narrower:

> **Among cooperating StateLatch executors, only the current non-expired Lease holder may enter the real mutation path for a Node.**
