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

Aegis provides `IndependentRootCapabilityAuthority`, a decorator around the existing `CapabilityFenceAuthority`.

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

## Content-bound persistent root

The in-memory proof above establishes the semantic boundary but does not make persistence independently trustworthy.

`AnchoredFileCapabilityMonotonicRoot` adds a durable local history whose exact head is committed in an independently protected anchor.

The anchor state is:

```text
(sequence, head_commitment)
```

where `head_commitment` is the SHA-256 hash of the exact last accepted root record and each record binds its predecessor.

A monotonic sequence by itself is **not sufficient**. With only a counter, a local ledger could be rewritten to a different valid history with the same number of records and a freshly recomputed unkeyed hash chain. The counter would still match.

The required invariant is therefore:

```text
anchor.sequence   == local_head.index
AND
anchor.commitment == local_head.record_hash
```

Any mismatch fails closed.

### Commit ordering

For a new accepted high-water state:

```text
verify local ledger against protected anchor
        |
        v
construct next hash-chained record
        |
        v
compare-and-advance protected anchor
(sequence + exact next record hash)
        |
        v
append local record
        |
        v
fsync file + directory
```

The protected anchor advances before local persistence. If the process or disk fails after the anchor advances but before the record is durable, the next read observes an anchor/ledger mismatch and fails closed. The system does not silently reconstruct or decrement the protected state.

### Falsification corpus

Executable tests cover:

```text
T1 -> T2 -> local ledger restored to T1
                         => DENY

mutable coordination = T1
mutable witness      = T1
local ledger         = T1
protected anchor     = T2 commitment
                         => DENY

same number of local records
+ locally valid recomputed hash chain
+ altered scope/history
+ protected anchor still commits to original head
                         => DENY
```

The last case is important: it distinguishes a content-bound root from a counter-only anti-rollback mechanism.

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

A production root must place the protected anchor state outside the rollback and rewrite domain of mutable coordination **and** the local root ledger. The substrate must preserve both monotonic sequence and the exact cryptographic head commitment.

Suitable implementations may include an external linearizable compare-and-set service with anti-rollback controls, a separately administered append-only authority, or hardware-backed storage that can protect both sequence and content commitment.

A file beside mutable coordination, an in-process variable, a second key in the same rollback-capable store, or a hardware counter that protects only record count does **not** satisfy the full content-binding claim.

The deterministic anchor used in CI exists to falsify Aegis boundary behavior. It is not evidence that any particular production TPM, HSM, KMS, or consensus substrate has been independently protected or operationally validated.


## M10 ExternalHeadStore backend

Aegis reuses the existing M10 `journal.ExternalHeadStore` as a concrete capability-root anchor through `ExternalHeadCapabilityRootAnchor`.

The adapter maps:

```text
CapabilityRootAnchorState.Sequence    -> ExternalHead.Sequence
CapabilityRootAnchorState.Commitment  -> ExternalHead.HeadHash
fixed capability-root protocol id     -> ExternalHead.KeyID
```

The first advance explicitly creates the sequence-zero external head before advancing to sequence one. This preserves the existing M10 compare-and-advance protocol and makes initialization behavior identical across backends.

For the v1 single-cluster production profile, `journal.KubernetesHeadStore` provides the external store:

```text
local capability root ledger
        |
        | exact head commitment
        v
Kubernetes ConfigMap
        |
        +-- resourceVersion compare-and-set
        +-- separate control-plane persistence
```

A KinD integration proof advances the capability root to T2, restores mutable coordination, witness state, and the local capability-root ledger to T1, and verifies that both `Current` and re-issuance fail closed while the Kubernetes external head remains unchanged at T2.

This establishes independence from local process/container/filesystem rollback for the tested deployment profile. It does **not** claim independence from a Kubernetes administrator who can rewrite both the application state and the capability-root ConfigMap. Deployments with that threat model must provide an `ExternalHeadStore` under a separately administered trust domain.


## TPM 2.0 NV counter backend

`TPMNVMonotonicRoot` anchors the rollbackable companion state to a TPM 2.0 NV counter.

```text
companion state generation = C
            |
            | must match
            v
TPM NV counter             = C
```

A newer snapshot is committed with a crash-recoverable sequence:

```text
persist pending state C+1
        |
        v
TPM2_NV_Increment
        |
        v
atomic pending -> committed
```

Recovery distinguishes both interruption windows. If pending exists while the TPM remains at C, the increment did not occur and pending is discarded. If the TPM is already C+1 while committed state is still C and pending is C+1, pending is promoted. Any other generation relation fails closed.

The simulator proof restores mutable coordination, mutable witness, and even the companion root state to T1 after T2 was accepted. The TPM counter remains higher, so execution is denied with `CAPABILITY_ROOT_ROLLBACK_DETECTED` before the mutation controller runs.

A second proof deletes and redefines the same NV counter handle. The newly initialized TPM counter remains greater than the prior value, so the old companion state still cannot become current.

### Claim boundary

The TPM backend protects against rollback of application/filesystem state while the TPM anti-rollback property remains trusted. It does not claim protection after physical replacement of the TPM, compromise of the TPM implementation itself, or migration to another device without an explicit root-transfer protocol.

## Cross-cluster witness proof

The next failure-domain step places the mutable capability authority and the protected root head in different Kubernetes control planes.

The KinD proof creates two independent API servers:

```text
workload cluster A
  mutable capability authority ConfigMap
        |
        | T1 -> T2
        v
local capability-root ledger
        |
        | exact head commitment
        v
witness cluster B
  KubernetesHeadStore
  resourceVersion CAS
```

After T2 is accepted, the proof deletes the mutable authority object in cluster A and recreates the historical T1 value, while also restoring the local root ledger to its T1 bytes. Cluster B is not modified and remains committed to the exact T2 root head.

Expected result:

```text
cluster A authority = T1 (recreated)
local root ledger    = T1 (restored)
cluster B witness    = T2

Current(T1) -> fail closed
Issue(T1)   -> fail closed
witness T2  -> unchanged
```

The test also asserts that workload and witness kubeconfigs resolve to different API servers, so the result is not a same-control-plane namespace separation.

This establishes resilience to destructive replacement or rollback of the tested workload-cluster authority state plus local filesystem state while the second cluster survives. It still does not prove a separately administered trust domain: a principal with credentials to both clusters could modify both failure domains. The next stronger production proof must separate administrative credentials or use an external CAS service/HSM-backed authority outside the workload operator's control.


### Credential and administrative separation proof

The cross-cluster proof now uses workload credentials rather than the CI administrator for the operational path.

Cluster A provisions a namespaced `workload-operator` ServiceAccount with ConfigMap mutation rights only in the workload namespace. Cluster B independently provisions a `capability-root-writer` ServiceAccount with the rights required by `KubernetesHeadStore` in the witness namespace.

The executable proof then presents each cluster's ServiceAccount token directly to the other cluster's API server:

```text
cluster A workload-operator token -> cluster B API server -> UNAUTHORIZED/FORBIDDEN
cluster B root-writer token       -> cluster A API server -> UNAUTHORIZED/FORBIDDEN
```

All mutable-authority changes during the T1 -> T2 -> T1 scenario use the workload-operator credential. All witness-head reads and compare-and-advance writes use only the root-writer credential.

The CI administrator credential is therefore limited to test-environment provisioning. It is not used by either operational authority path after the two identities are created.

This proves distinct runtime credentials and control-plane authentication boundaries for the tested topology. It does not prove organizational separation of the CI provisioning principal itself; production deployment still requires the witness credential and administrative ownership to be isolated from the workload operator outside the test harness.
