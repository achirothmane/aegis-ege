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
-> atomically claim replay state
-> guarded mutation execution
```

The replay claim remains atomic:

- filesystem guard: `O_CREATE|O_EXCL`
- Kubernetes shared guard: atomic ConfigMap create

The replay key now includes all capability fencing coordinates. Two concurrent attempts using the same capability converge on the same claim key.

## Fail-closed transitions

Execution is rejected when:

- authority term changes: `CAPABILITY_AUTHORITY_CHANGED`
- a newer decision epoch supersedes the permit: `CAPABILITY_DECISION_SUPERSEDED`
- revocation epoch changes: `CAPABILITY_REVOKED`
- target UID/identity changes: `CAPABILITY_TARGET_CHANGED`
- resource-version or plan binding changes: `CAPABILITY_STATE_CHANGED`
- the authority/state refresh cannot be completed: `CAPABILITY_FENCE_UNAVAILABLE`

No replay claim is consumed before these checks pass.

## What this does not claim yet

This PR is a userspace/control-plane fencing layer.

It does **not** yet claim that:

- the kernel independently enforces the capability;
- a non-cooperating external actor is fenced;
- a capability claim has a durable `ISSUED -> CLAIMED -> CONSUMED/ABORTED` state machine;
- authority terms are persisted by a built-in Raft/etcd implementation;
- execution receipts independently prove the resulting effect.

Those belong to the next layers:

```text
control-plane capability fence
-> durable claim state machine
-> kernel DecisionCapsule enforcement
-> independent EffectReceipt
```

The current guarantee is narrower and testable:

> A capability-fenced EGE execution cannot enter the mutation controller when its trusted authority term, scoped decision epoch, revocation epoch, stable target identity, resource version, or plan binding no longer matches the current execution context.
