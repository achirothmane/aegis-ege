# Execution capability fencing

Aegis-EGE can bind an execution permit to a short-lived, single-use execution capability.

This layer closes a gap that a signed permit and live resource-version checks do not close by themselves: a decision may be valid when issued but stale, superseded, revoked, or bound to a different resource incarnation by the time execution starts.

## Capability fence

When capability fencing is enabled, the signed permit carries:

```text
authority_domain
authority_term
decision_epoch
revocation_epoch
target_identity
state_binding_digest
```

The state-binding digest commits to:

```text
target type/name
stable target identity
resource version
plan digest
```

For the Kubernetes node-drain adapter, `target_identity` is the Node UID. Re-creating a Node with the same name therefore does not preserve an old capability.

## Trusted authority boundary

The agent does not choose authority terms, decision epochs, or revocation epochs.

Embedded deployments enable the layer with:

```go
server.Config{
    RequireCapabilityFencing: true,
    CapabilityFenceAuthority: authority,
    ReplayGuard:              executionClaimStore,
}
```

`CapabilityFenceAuthority` is independent of the agent and exposes two operations:

```text
Issue(scope)   -> authority_domain, authority_term, decision_epoch, revocation_epoch
Current(scope) -> current authority/decision/revocation coordinates
```

A production implementation must provide a monotonic, linearizable decision epoch for the scoped action and a fencing authority term that changes on authority failover.

Aegis deliberately does not synthesize placeholder epochs.

## Execution ordering

The EGE execution path becomes:

```text
authenticate
-> verify signed permit
-> bind permit to outer intent
-> validate EBA bundle (when enabled)
-> consequence admission
-> refresh authoritative state evidence
-> compare authority term
-> compare decision epoch
-> compare revocation epoch
-> compare stable target identity
-> compare state-binding digest
-> transition ISSUED -> CLAIMED atomically
-> guarded mutation execution
-> transition CLAIMED -> CONSUMED on known completion
```

The capability claim is now a durable state machine:

```text
ISSUED
  |
  v
CLAIMED
  |\
  | \__ proven no mutation started -> ABORTED
  |
  +---- known execution return ----> CONSUMED
```

Both `CONSUMED` and `ABORTED` are terminal. `ABORTED` records that the mutation controller was never entered; it does **not** make the same capability reusable.

Atomicity is enforced by the backing store:

- filesystem: an `O_CREATE|O_EXCL` claim marker admits exactly one claimant and state transitions are persisted with fsync + atomic rename;
- Kubernetes: the shared ConfigMap moves from `ISSUED` to `CLAIMED` through a resourceVersion-protected update, so concurrent replicas cannot both win.

The replay key includes all capability fencing coordinates. Two concurrent attempts using the same capability therefore converge on the same lifecycle record.

## Fail-closed transitions

Execution is rejected when:

- authority term changes: `CAPABILITY_AUTHORITY_CHANGED`
- a newer decision epoch supersedes the permit: `CAPABILITY_DECISION_SUPERSEDED`
- revocation epoch changes: `CAPABILITY_REVOKED`
- target UID/identity changes: `CAPABILITY_TARGET_CHANGED`
- resource-version or plan binding changes: `CAPABILITY_STATE_CHANGED`
- the authority/state refresh cannot be completed: `CAPABILITY_FENCE_UNAVAILABLE`

No capability is moved from `ISSUED` to `CLAIMED` before these checks pass.

If the request context is canceled after the atomic claim but before the mutation controller is entered, Aegis records `ABORTED` using a detached finalization context.

Once the mutation controller has been entered, an execution error is treated as potentially ambiguous. The capability remains `CLAIMED` rather than being reopened. Recovery must reconcile external reality and obtain fresh authority for any remaining work.

## What this does not claim yet

This PR is a userspace/control-plane fencing layer.

It does **not** yet claim that:

- the kernel independently enforces the capability;
- a non-cooperating external actor is fenced;
- authority terms are persisted by a built-in Raft/etcd implementation;
- execution receipts independently prove the resulting effect.

Those belong to the next layers:

```text
control-plane capability fence
-> durable claim state machine
-> kernel DecisionCapsule enforcement
-> independent EffectReceipt
```

The current guarantees are testable:

> A capability-fenced EGE execution cannot enter the mutation controller when its trusted authority term, scoped decision epoch, revocation epoch, stable target identity, resource version, or plan binding no longer matches the current execution context.

> A capability can move from `ISSUED` to `CLAIMED` at most once across cooperating executors. After a known execution return it becomes `CONSUMED`; if and only if Aegis proves the mutation controller was never entered it may become terminal `ABORTED`. Ambiguous post-entry failures remain fail-closed in `CLAIMED`.
