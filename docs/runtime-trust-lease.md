# Runtime Trust Lease / Continuous Revalidation v1

Admission proves that a workload was allowed to start.

It does **not** prove that a long-running workload should keep the same authority indefinitely.

Runtime Trust Lease v1 adds a short-lived, renewable trust contract for the current running generation.

## Governing invariant

> A workload that remains alive must not retain protected runtime authority beyond the evidence window that justified it.

The runtime chain is:

```text
attested workload activation
        |
        v
fresh TPM + IMA remote ALLOW
        |
        v
signed RuntimeTrustLease
        |
        v
apply lease to RUNNING lifecycle
        |
        v
periodic evaluation
   |            |
   |            +--> KEEP_RUNNING
   |
   +--> RENEW_REQUIRED
   |
   +--> REVOKE
            |
            v
read current kernel fence
            |
            v
revocation_epoch++
            |
            v
network DecisionCapsules fail closed
            |
            v
host-signed RUNTIME_TRUST_REVOKED observation
            |
            v
standard reconciliation QUARANTINE
```

## Runtime Trust Lease

A signed lease binds:

```text
lease_id
lease_epoch
device_id
workload_id
generation
lifecycle_epoch
activation_digest
workload_spec_digest
target_cgroup
target_cgroup_id
bootstrap_digest
policy_digest
remote_decision_id
remote_decision_digest
remote_verified_at
authority_id
issued_at
expires_at
```

The lifecycle authority signs the lease.

The lease does not carry raw TPM evidence. It references the already signed remote attestation decision.

## Lease lifetime

The configured lease TTL cannot extend trust past the remote attestation freshness boundary.

```text
lease_expires_at =
  min(
    now + lease_ttl,
    remote_verified_at + max_attestation_age
  )
```

Therefore a runtime lease cannot make an old TPM + IMA decision valid for longer than policy allows.

## Lifecycle ledger binding

While a workload is RUNNING, the durable lifecycle ledger may contain:

```text
runtime_trust_epoch
runtime_trust_lease_digest
runtime_trust_expires_at
```

These fields identify the **only current runtime lease**.

A lease application must advance exactly:

```text
runtime_trust_epoch N -> N+1
```

The first lease is epoch 1.

Replaying an already applied lease fails because the expected next epoch has changed.

Runtime trust state is cleared when the workload:

- exits;
- starts a new generation;
- becomes EXITED_UNKNOWN;
- becomes QUARANTINED.

A lease therefore cannot cross a generation or lifecycle transition.

## Renewal

Renewal requires:

1. the exact currently applied lease;
2. a valid signature from the lifecycle authority;
3. exact device/workload/generation/lifecycle lineage;
4. the same activation, workload spec, cgroup, bootstrap and policy;
5. strictly newer remote attestation evidence;
6. a different remote decision digest;
7. renewal before the current lease expires.

The new lease increments `lease_epoch` exactly once.

If renewal is missed and the lease expires, the correct path is revocation, not retroactive renewal.

## Runtime evaluation

The lifecycle authority emits one signed runtime decision:

```text
KEEP_RUNNING
RENEW_REQUIRED
REVOKE
```

### KEEP_RUNNING

The currently applied lease is valid and matches current policy.

### RENEW_REQUIRED

A newer signed remote ALLOW exists while the current lease is still valid.

The authority should issue and apply a new lease before the current one expires.

### REVOKE

Current authority must be removed.

v1 produces REVOKE for:

```text
runtime lease expired
runtime policy digest superseded
newer remote BLOCK
remote device/bootstrap identity changed
```

A supplied remote decision cannot be replayed backwards.

If its digest differs from the lease's remote decision, its `verified_at` must be strictly newer than the evidence that created the lease.

Remote timestamps outside the configured future clock skew are rejected.

## Policy digest

Runtime policy is referenced by a SHA-256 digest.

Changing the digest while a workload still holds a lease causes:

```text
RUNTIME_POLICY_SUPERSEDED
-> REVOKE
```

The new policy does not silently inherit authority from the prior policy.

A new lease must be issued under the new policy after the appropriate evidence path.

## Kernel revocation

The cgroup network adapter already fences DecisionCapsules by:

```text
boot_id_hash
authority_term
decision_epoch
revocation_epoch
```

Runtime containment does **not** accept a caller-provided next revocation epoch.

Aegis reads the current pinned fence first:

```text
bpftool -j map lookup ...
```

then performs:

```text
next = current
next.revocation_epoch++
write next fence
```

This avoids regressing the kernel fence because of an old userspace snapshot.

The ordering is:

```text
read current fence
-> advance kernel revocation
-> observe live process identity
-> sign containment evidence
```

If evidence production fails after the fence update, network authority remains revoked.

That failure mode is deny-biased.

## bpftool fence reader

The pinned map store now supports reading the current fence through JSON output and decoding the fixed 56-byte ABI.

Default maps are:

```text
/sys/fs/bpf/aegis-ege/maps/aegis_capsules
/sys/fs/bpf/aegis-ege/maps/aegis_fences
```

## Runtime containment evidence

After kernel revocation, the enrolled host attestor signs a standard recovery observation with state:

```text
RUNTIME_TRUST_REVOKED
```

It binds:

```text
runtime trust decision digest
activation digest
persistent process identity
current boot identity
expected + observed cgroup path/inode
observation time
```

The process must still be the exact Activation Receipt v2 process in the exact signed cgroup.

If the process disappeared or identity changed during containment, the command fails rather than inventing a runtime-quarantine fact.

Crash/orphan reconciliation handles that different situation.

## Standard QUARANTINE integration

Runtime Trust does not create a second quarantine system.

The lifecycle authority verifies:

```text
signed RuntimeTrustDecision(REVOKE)
+
host-signed RUNTIME_TRUST_REVOKED observation
+
Activation Receipt v2
+
current RUNNING lifecycle state
```

and emits the existing:

```text
SignedWorkloadReconciliationDecision(
  outcome = QUARANTINE
)
```

Therefore the existing commands remain valid after runtime containment:

```text
aegis-reconcile-apply
aegis-reconcile-observe
aegis-quarantine-approve
aegis-quarantine-release-decide
aegis-quarantine-release-apply
```

No parallel release protocol is introduced.

## Important containment boundary

Runtime Trust Lease v1 revokes the authority currently enforced by the implemented kernel adapter:

```text
cgroup network connect
```

It does **not** automatically:

- kill the workload;
- freeze the cgroup;
- block filesystem operations;
- block process creation;
- revoke capabilities not yet represented by kernel adapters.

The workload process may therefore remain alive after network revocation.

Its lifecycle becomes QUARANTINED only after the signed reconciliation decision is applied.

Before Operator Release, remediation must prove that the original process is no longer live, using the existing quarantine-clearance path.

Future BPF-LSM/process/filesystem adapters can reuse the same runtime trust decision and add their own revocation fences.

## Commands

### 1. Issue the first runtime lease

Run after the workload has an Activation Receipt and RUNNING lifecycle state:

```bash
go run ./cmd/aegis-runtime-trust-issue \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -remote-decision remote-attestation-decision.json \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -host-attestor-pub host-attestation.pub \
  -policy-digest sha256:<runtime-policy-digest> \
  -out runtime-trust-lease.json
```

### 2. Apply the lease

```bash
go run ./cmd/aegis-runtime-trust-apply \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -lease runtime-trust-lease.json \
  -lifecycle-authority-pub lifecycle-authority.pub
```

### 3. Evaluate current runtime trust

Without new remote evidence:

```bash
go run ./cmd/aegis-runtime-trust-evaluate \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -activation workload-activation-receipt.json \
  -lease runtime-trust-lease.json \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -host-attestor-pub host-attestation.pub \
  -policy-digest sha256:<runtime-policy-digest> \
  -out runtime-trust-decision.json
```

A newer remote decision can be supplied with:

```text
-remote-decision
-remote-verifier-pub
```

### 4. Renew before expiry

Obtain fresh remote attestation, then issue a new lease using:

```text
-previous-lease runtime-trust-lease.json
```

Apply the renewed lease with `aegis-runtime-trust-apply`.

### 5. Contain REVOKE

When evaluation returns `REVOKE`:

```bash
sudo go run ./cmd/aegis-runtime-trust-contain \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -activation workload-activation-receipt.json \
  -decision runtime-trust-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -host-attestor-key host-attestation.key \
  -out runtime-trust-recovery-observation.json
```

This updates the current network fence first.

### 6. Convert containment evidence to standard QUARANTINE

```bash
go run ./cmd/aegis-runtime-trust-reconcile \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -activation workload-activation-receipt.json \
  -observation runtime-trust-recovery-observation.json \
  -runtime-decision runtime-trust-decision.json \
  -host-attestor-pub host-attestation.pub \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -out runtime-trust-quarantine-decision.json
```

Apply it through the existing command:

```bash
go run ./cmd/aegis-reconcile-apply \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -decision runtime-trust-quarantine-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub
```

The normal Operator Release protocol then governs recovery.

## Current boundary

Implemented:

```text
signed short-lived runtime trust leases
lease epoch rollback protection
remote-attestation freshness cap
strictly newer evidence for renewal
runtime policy digest fencing
KEEP_RUNNING / RENEW_REQUIRED / REVOKE decisions
old remote-decision replay rejection
future timestamp skew rejection
current kernel fence lookup
atomic revocation_epoch advancement
network authority fail-closed revocation
host-signed runtime containment evidence
standard reconciliation QUARANTINE integration
lifecycle clearing across exit/restart/quarantine
```

Not yet implemented:

```text
automatic periodic scheduler/watchdog
automatic TPM attestation refresh
automatic cgroup freeze or kill
BPF-LSM filesystem/process revocation
multi-action-class transactional revocation
distributed runtime trust ledger
Kubernetes/systemd supervisor integration
```

## Final invariant

> Starting safely is not enough. A long-running workload retains protected authority only while a current signed runtime lease remains bound to the same generation, lifecycle epoch, policy, host evidence, activation and kernel enforcement scope.
