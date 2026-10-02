# Independent monotonic capability root

This layer strengthens execution capability fencing against a coordinated rollback of mutable authority state.

The existing capability fence already requires the signed permit to match the live authority coordinates:

```text
authority_domain
authority_term
decision_epoch
revocation_epoch
```

That is sufficient only while the authority source that reports the current coordinates remains trustworthy. If all mutable copies of that source can be restored together to an older state, a formerly valid capability could otherwise appear current again.

## Contract

Aegis now provides `IndependentRootCapabilityAuthority`, a decorator around the existing `CapabilityFenceAuthority`.

```text
mutable coordination/witness
          |
          v
CapabilityFenceAuthority
          |
          +--------------------+
          |                    |
          v                    v
 independent monotonic root   live mutable snapshot
          |                    |
          +--------- compare --+
                    |
                    v
             Effect Boundary
```

The independent root exposes:

```go
type CapabilityMonotonicRoot interface {
    Advance(ctx, scope, observed) (highWater, error)
    Current(ctx, scope) (highWater, error)
}
```

`Advance` is a compare-and-advance operation. A successful observation of T2 must make a later attempt to restore T1 unable to lower the returned high-water mark.

`Current` must read the high-water mark from a failure domain that is independent from mutable coordination.

## Proven execution invariant

The executable proof establishes this schedule:

```text
T1 issued
  |
  v
root = T1
  |
  v
T2 issued
  |
  v
root = T2
  |
  v
coordination = T1
witness      = T1
root         = T2
  |
  v
present T1 to /v1/ege/execute
  |
  v
CAPABILITY_DECISION_SUPERSEDED
mutation controller calls = 0
```

When mutable coordination converges back to T2, the T2 permit can execute and exactly one mutation-controller call is observed.

The same root also refuses a new issuance at T1 after T2 has already become the high-water mark.

Therefore the tested invariant is:

```text
mutable_current = Tn
AND independent_root > Tn
=> Tn cannot regain effect authority
```

The wrapper does not invent a second validation path. When the root is ahead, it returns the root snapshot as the current authority snapshot. The existing capability validator then produces the established fail-closed result:

- newer authority term -> `CAPABILITY_AUTHORITY_CHANGED`
- newer decision epoch -> `CAPABILITY_DECISION_SUPERSEDED`
- newer revocation epoch -> `CAPABILITY_REVOKED`

If the independent root is behind the mutable authority, unavailable, internally inconsistent, or from a different authority domain, the wrapper fails closed instead of silently trusting the mutable source.

## Integration

```go
rootedAuthority, err := server.NewIndependentRootCapabilityAuthority(
    mutableAuthority,
    independentRoot,
)
if err != nil {
    return err
}

cfg := server.Config{
    RequireCapabilityFencing: true,
    CapabilityFenceAuthority: rootedAuthority,
    ReplayGuard:              executionClaimStore,
}
```

## Failure-domain requirement

The interface alone does not make storage independent.

A production `CapabilityMonotonicRoot` must place its high-water state outside the rollback domain of mutable coordination. Candidate substrates include a monotonic hardware-backed counter, an external linearizable consensus service with anti-rollback controls, or another separately administered append-only authority.

A file beside the mutable coordination state, an in-process variable, or a second key in the same rollback-capable store does **not** satisfy the independence claim.

The test implementation is intentionally in-memory and exists only to falsify the Aegis boundary behavior. It is not evidence that any particular production root substrate is independently protected.
