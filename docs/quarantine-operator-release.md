# Quarantine Recovery / Operator Release v1

`QUARANTINED` is intentionally not a restartable lifecycle state.

It represents a condition where Aegis found evidence that is unsafe to resolve automatically, such as a matching process outside the signed cgroup or an unverifiable legacy activation.

The release protocol is therefore:

```text
QUARANTINED
    |
    v
post-remediation host observation
    |
    +-- original process still live? ------> stay QUARANTINED
    |
    v
safe clearance evidence
    |
    v
fresh TPM + IMA remote ALLOW
    |
    v
operator-signed approval
    |
    v
lifecycle-authority release decision
    |
    v
atomic ledger transition
epoch N -> N+1
QUARANTINED -> EXITED_UNKNOWN
    |
    v
fresh one-shot restart grant
```

## Governing invariant

> Human approval cannot replace evidence. It may authorize a transition only after the quarantined process has been proven inactive and the host has passed fresh hardware-rooted attestation.

## Safe clearance states

The automatic release path accepts only recovery observations that prove the original activation process can no longer be the live process:

```text
ABSENT
BOOT_CHANGED
PID_REUSED
```

It rejects:

```text
MATCH_RUNNING
CGROUP_MISMATCH
UNVERIFIABLE
LEGACY_UNVERIFIABLE
```

A live matching process, or a state that cannot be verified, remains quarantined.

Legacy Activation Receipt v1 does not carry persistent process identity and therefore cannot use this automatic release path.

## Quarantine lineage

A post-quarantine clearance observation is signed by the enrolled host attestor and binds:

```text
device_id
workload_id
generation
activation_id
activation_digest
prior_recovery_digest
expected process identity
expected cgroup path + inode
current boot identity
observation state
observed_at
```

`prior_recovery_digest` must equal the reconciliation decision digest currently stored in the QUARANTINED ledger.

This prevents a clearance observation from a different quarantine event from being reused.

## Fresh remote attestation

The release protocol requires a signed remote decision with:

```text
decision = ALLOW
device_id = quarantined device
bootstrap_digest = prior admission bootstrap digest
verified_at > clearance_observation.observed_at
```

The remote decision must also still be within the configured attestation freshness window.

Therefore an attestation taken before remediation cannot authorize release.

## Operator approval

The operator signs an approval only after the clearance observation and fresh remote attestation exist.

The approval binds:

```text
approval_id
device_id
workload_id
generation
current_lifecycle_epoch
requested_lifecycle_epoch
activation_digest
quarantine_recovery_digest
clearance_observation_digest
remote_decision_digest
operator_id
case_reference
reason
issued_at
expires_at
```

The requested epoch must be exactly:

```text
current_epoch + 1
```

The human reason and case reference are audit context, not substitutes for machine evidence.

## Authority separation

Four roles remain independent:

```text
host attestor
  signs what the host observes

remote verifier
  signs hardware-rooted host-state ALLOW/BLOCK

operator
  approves the exceptional release based on exact evidence

lifecycle authority
  decides and signs the actual lifecycle transition
```

The operator key cannot directly mint a restart grant.

The lifecycle authority private key used for release must correspond to the same trusted lifecycle public key used to verify the quarantine lineage.

## Lifecycle epoch fencing

The durable lifecycle state now carries:

```text
lifecycle_epoch
```

New lifecycles start at epoch 1.

Legacy state without an explicit epoch is normalized to epoch 1.

A successful quarantine release performs:

```text
epoch N -> N+1
```

Restart decisions carry the lifecycle epoch and must match the current ledger.

This invalidates restart authority issued before the quarantine release.

## Release decision

After verifying all evidence and the operator approval, the lifecycle authority signs:

```text
RELEASE_TO_EXITED_UNKNOWN
```

with bindings to:

```text
device/workload/generation
previous lifecycle epoch
new lifecycle epoch
activation digest
quarantine recovery digest
clearance observation digest
remote decision digest
operator approval digest
decision validity window
authority id
```

The release decision is short-lived for application.

After it has been applied, its signature remains valid as historical lineage even after the application window expires.

## Atomic application

Applying the release requires the durable ledger to still be exactly:

```text
state = QUARANTINED
generation = signed generation
epoch = signed previous epoch
activation_digest = signed activation digest
recovery_digest = signed quarantine digest
```

The transition becomes:

```text
state = EXITED_UNKNOWN
epoch = signed new epoch
recovery_digest = release decision digest
```

A second application of the same release decision fails because the state and epoch no longer match.

## Restart after release

The normal restart evaluator accepts the signed quarantine release artifact.

It produces a restart decision only if:

- the ledger is `EXITED_UNKNOWN`;
- the release digest equals the current `recovery_digest`;
- the ledger epoch equals the release's new epoch;
- the remote decision is the same release-approved decision and is still fresh;
- restart budget is not exhausted;
- workload, cgroup and bootstrap identities remain unchanged.

The result is still:

```text
REQUIRE_FRESH_GRANT
```

The pre-quarantine grant remains permanently consumed.

## Commands

### 1. Observe after remediation

The existing recovery observer is reused against the QUARANTINED state:

```bash
sudo go run ./cmd/aegis-reconcile-observe \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -activation workload-activation-receipt.json \
  -host-attestor-key host-attestation.key \
  -out quarantine-clearance-observation.json
```

Do not continue unless the observation is one of:

```text
ABSENT
BOOT_CHANGED
PID_REUSED
```

### 2. Perform fresh TPM + IMA attestation

The remote decision must be newer than the clearance observation.

### 3. Operator approval

```bash
go run ./cmd/aegis-quarantine-approve \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant prior-workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -quarantine-decision workload-reconciliation-decision.json \
  -clearance-observation quarantine-clearance-observation.json \
  -remote-decision fresh-remote-attestation-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -host-attestor-pub host-attestation.pub \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -operator-key operator.key \
  -operator-id oncall-operator \
  -case INC-2026-001 \
  -reason "process remediated and host re-attested" \
  -out quarantine-operator-approval.json
```

### 4. Lifecycle release decision

```bash
go run ./cmd/aegis-quarantine-release-decide \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant prior-workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -quarantine-decision workload-reconciliation-decision.json \
  -clearance-observation quarantine-clearance-observation.json \
  -remote-decision fresh-remote-attestation-decision.json \
  -operator-approval quarantine-operator-approval.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -host-attestor-pub host-attestation.pub \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -operator-pub operator.pub \
  -out quarantine-release-decision.json
```

### 5. Apply release

```bash
go run ./cmd/aegis-quarantine-release-apply \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -decision quarantine-release-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -out workload-lifecycle-after-release.json
```

### 6. Evaluate restart in the new epoch

```bash
go run ./cmd/aegis-restart-evaluate \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant prior-workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -quarantine-release quarantine-release-decision.json \
  -remote-decision fresh-remote-attestation-decision.json \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -host-attestor-pub host-attestation.pub \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -out workload-restart-decision.json
```

Then issue a fresh one-shot restart grant through the existing restart admission issuer.

## Current boundary

Implemented:

```text
post-quarantine clearance evidence
fresh post-clearance remote attestation gate
operator-signed approval
case/reason audit binding
independent lifecycle release decision
atomic QUARANTINED -> EXITED_UNKNOWN transition
lifecycle epoch N -> N+1
old-epoch restart fencing
fresh-grant-only restart after release
```

Not yet implemented:

```text
multi-operator / quorum approval
hardware-backed operator signing keys
external incident-management integration
distributed lifecycle epoch store
automatic emergency process termination
automatic operator notification
```

## Final invariant

> QUARANTINED is not a human override prompt. It is a state that can be released only when machine evidence proves the unsafe process is gone, hardware-rooted attestation proves the remediated host state, an accountable operator approves the exact evidence set, and the lifecycle authority advances to a new epoch.
