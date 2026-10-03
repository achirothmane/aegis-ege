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

### Provisioning authority removed before runtime proof

The CI proof now separates one-time provisioning authority from the runtime credentials used by the falsification test.

The setup phase creates both KinD control planes with admin kubeconfigs, then runs `cmd/aegis-capability-runtime-provision` to:

- create the workload and witness namespaces;
- create a namespaced `workload-operator` credential for mutable authority state;
- pre-provision the sequence-zero witness head;
- create a `capability-root-writer` credential restricted to `get/update` on exactly that pre-provisioned witness ConfigMap;
- write two narrow runtime kubeconfigs.

The ordinary KinD regression suite runs first with the workload-cluster admin kubeconfig because those pre-existing tests intentionally create cluster-scoped fixtures such as namespaces and synthetic nodes. After that regression suite completes, CI deletes both admin kubeconfigs and removes `~/.kube`. The dedicated cross-cluster witness proof then runs by itself and receives only the two narrow runtime kubeconfigs.

The executable checks prove:

```text
workload runtime credential -> create Namespace -> FORBIDDEN
witness runtime credential  -> create Namespace -> FORBIDDEN

workload token -> witness API -> UNAUTHORIZED/FORBIDDEN
witness token  -> workload API -> UNAUTHORIZED/FORBIDDEN

root-writer -> delete witness head -> FORBIDDEN
root-writer -> protocol CAS update -> ALLOWED
```

The workload operator can still delete and recreate its own mutable authority object, which is deliberate for the rollback scenario. After that state and the local root ledger are restored to T1, the separately protected witness remains T2 and execution fails closed.

This closes the in-repository runtime/provisioning credential boundary. It still does not establish independent organizational ownership: the GitHub repository/workflow owner can change the provisioning code itself. Proving that stronger boundary requires a witness service, account, or administrative domain whose owner is outside the workload repository's authority.

## Executable crash-window proof

The TPM root recovery protocol is exercised at the three consequential interruption boundaries:

```text
1. pending(C+1) durable
   TPM still C
   process dies
   -> restart discards uncommitted pending
   -> committed Tn remains current

2. pending(C+1) durable
   TPM increments to C+1
   process dies before promotion
   -> restart promotes pending
   -> Tn+1 remains current
   -> old Tn is still superseded at Effect Boundary

3. TPM increments to C+1
   pending(C+1) is unavailable/lost
   -> restart cannot reconstruct authority safely
   -> CAPABILITY_ROOT_ROLLBACK_DETECTED
   -> mutation controller calls = 0
```

The third case is deliberately fail-closed. A counter value proves that a newer root transition occurred, but without the durable pending snapshot Aegis does not invent or infer which authority snapshot was committed.

## TPM device identity binding

A monotonic counter is not sufficient if the application can silently attach an old companion state to a different TPM whose counter happens to match. The TPM root now binds every committed state to the deterministic endorsement-primary identity derived from the TPM endorsement hierarchy.

At provisioning:

```text
TPM endorsement primary
        |
        v
stable TPM object Name
        |
        v
SHA-256 device identity
        |
        +-- stored inside sealed root state
        +-- covered by the state digest
```

On every recovery and Effect Boundary revalidation, Aegis recreates the same endorsement primary from the live TPM and compares the observed identity with the identity enrolled in the root state.

The executable proof uses two independent TPM simulator instances with different fixed hierarchy seeds. TPM-A creates the authorized root state and permit. TPM-B is provisioned at the same NV handle and its counter is advanced to the exact same generation. The companion state from TPM-A is then copied onto TPM-B:

```text
TPM-A counter = C
TPM-A state.device_identity = A
permit = valid under A
        |
        | copy companion state
        v
TPM-B counter = C
same NV handle
same generation
TPM-B live endorsement identity = B
        |
        v
CAPABILITY_ROOT_DEVICE_CHANGED
        |
        v
mutation controller calls = 0
```

The test deliberately equalizes the mutable generation coordinate so a counter-only check cannot distinguish the two devices. The remaining discriminator is the enrolled endorsement identity.

This distinguishes a monotonic-state failure from a device-root replacement. A device identity change is not treated as rollback and is not repaired implicitly.

The root-state format is now `aegis.ege/tpm-nv-monotonic-root/v2`. Existing v1 companion state does not silently migrate because it contains no device binding. It fails closed and requires an explicit migration or reprovisioning procedure.

### Claim boundary

This proves software-visible binding to the TPM endorsement hierarchy in the TPM2 simulator model. It does not claim resistance to a compromised TPM implementation that reproduces the enrolled endorsement identity, nor does it define a cross-device root migration protocol. Legitimate TPM replacement therefore requires an explicit separately authorized migration path rather than automatic reset.

## Authorized TPM replacement / root migration

Device identity binding deliberately rejects a copied root state on a different TPM. Legitimate hardware replacement therefore requires a separate authorization path rather than an implicit reset.

A migration authorization binds one exact transition:

```text
migration_id
source_device_identity
source_state_digest
source_generation
destination_device_identity
destination_generation
destination_nv_index
not_before
expires_at
```

The complete payload is signed with an Ed25519 migration authority key. The destination verifies the signature and validity window before reading or changing its TPM counter.

The migration path then requires:

```text
source state digest == authorized source digest
source device        == authorized source device
source generation    == authorized source generation

destination TPM identity   == authorized destination identity
destination generation     == authorized destination generation
destination NV handle      == authorized destination NV handle
destination authority set  == empty
```

Only then does it create a new destination generation using the same crash-consistent protocol:

```text
persist pending destination state
        |
        v
TPM2_NV_Increment
        |
        v
atomic pending -> committed
```

The new committed state records:

```text
predecessor_device_identity
migration_source_state_digest
migration_authorization_digest
```

so the replacement does not erase its provenance.

### Executable migration proof

The positive proof creates TPM-A and TPM-B from independent simulator hierarchy seeds. TPM-A owns an active capability root. TPM-B is freshly provisioned and empty.

An exact signed A -> B authorization is issued. A mismatched destination authorization is rejected without changing TPM-B's counter. The exact authorization then migrates the root, advances TPM-B exactly once, preserves the complete capability-authority snapshot set, and records the signed migration commitment.

After the server switches to TPM-B, the permit that was valid under the exact migrated source state remains executable because the migration explicitly authorized continuity of that state.

Replaying the same signed migration is rejected as `ErrTPMRootMigrationReplay`.

A separate falsification test verifies that expired and forged authorizations are rejected before the destination counter changes.

### Claim boundary

This v1 protocol proves explicit software-visible authorization for a root transition between two TPM identities. It does not prove that the migration signer is organizationally independent, nor does it remotely attest the destination TPM inside the migration function itself. A production profile should issue the signed migration authorization only after independently verifying both enrolled device identities and the intended replacement event.
