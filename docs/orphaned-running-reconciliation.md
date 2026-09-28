# Orphaned RUNNING Reconciliation v1

This layer repairs the ambiguity left when the workload process and the Aegis supervisor do not fail together.

A lifecycle record may say `RUNNING` after:

- the supervisor crashed while the workload kept running;
- the workload exited before the supervisor persisted EXITED;
- the host rebooted;
- the PID was later reused;
- the workload moved outside its signed cgroup.

Aegis must not guess.

## Activation receipt v2

New workload starts emit `workload-activation-receipt/v2`.

In addition to the existing activation lineage it binds a persistent Linux process identity:

```text
boot_id_hash
process_start_time_ticks
executable_device
executable_inode
```

The signed activation already binds:

```text
PID
target cgroup path
target cgroup inode
workload spec digest
grant digest
```

The combination prevents a later process that reused the same PID from being mistaken for the original workload.

v1 activation receipts remain verifiable for compatibility, but they are not eligible for automatic crash reconciliation.

## Evidence before decision

Recovery keeps observation separate from authority.

### Host observation

The enrolled host attestor signs:

```text
activation digest
generation
expected process identity
observed process identity
expected cgroup id
observed cgroup id
observation state
observed_at
```

Observation states:

```text
MATCH_RUNNING
ABSENT
BOOT_CHANGED
PID_REUSED
CGROUP_MISMATCH
LEGACY_UNVERIFIABLE
UNVERIFIABLE
```

### Lifecycle decision

The lifecycle authority verifies the signed observation and current ledger lineage, then emits one of:

```text
KEEP_RUNNING
MARK_EXITED_UNKNOWN
QUARANTINE
```

The host cannot mutate lifecycle truth merely by claiming that a process disappeared.

## Decision semantics

### KEEP_RUNNING

Used only when:

```text
boot id matches
PID exists
starttime matches
executable device/inode match
cgroup inode matches
```

The ledger remains RUNNING.

### MARK_EXITED_UNKNOWN

Used when there is strong evidence that the original process cannot still be the activated workload:

- PID is absent;
- host boot changed;
- PID exists but persistent process identity differs.

Aegis does **not** synthesize an exit code.

The ledger becomes:

```text
EXITED_UNKNOWN
recovery_digest = signed reconciliation decision digest
```

### QUARANTINE

Used when the truth is unsafe to collapse into a normal exit:

- matching live process is outside the signed cgroup;
- activation receipt is legacy v1 and lacks persistent process identity;
- process state cannot be verified reliably.

The ledger becomes `QUARANTINED`.

Normal restart paths reject QUARANTINED state. Explicit operator recovery is required.

## Recovered restart

`EXITED_UNKNOWN` cannot restart from old evidence.

The recovered restart evaluator requires:

```text
remote_attestation.verified_at
>
reconciliation.decided_at
```

Until then the result is:

```text
REQUIRE_REATTESTATION
```

After a fresh TPM + IMA ALLOW, the evaluator may return:

```text
REQUIRE_FRESH_GRANT
```

subject to the normal restart budget, bootstrap binding, freshness and backoff rules.

The resulting restart decision binds:

```text
previous_recovery_digest
```

instead of a fabricated exit receipt.

Exactly one of:

```text
previous_exit_digest
previous_recovery_digest
```

must be present in a restart decision.

## Commands

Reconcile an orphaned RUNNING lifecycle:

```bash
sudo go run ./cmd/aegis-lifecycle-reconcile \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -activation workload-activation-receipt.json \
  -host-attestor-pub host-attestation.pub \
  -host-attestor-key host-attestation.key \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -observation-out workload-recovery-observation.json \
  -decision-out workload-reconciliation-decision.json
```

After `MARK_EXITED_UNKNOWN`, perform fresh remote attestation and evaluate restart:

```bash
go run ./cmd/aegis-recovered-restart-evaluate \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant prior-workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -reconciliation workload-reconciliation-decision.json \
  -remote-decision fresh-remote-attestation-decision.json \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -host-attestor-pub host-attestation.pub \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -out workload-recovered-restart-decision.json
```

If the result is `REQUIRE_FRESH_GRANT`, the existing restart grant issuer can mint a new one-shot admission grant.

## Current boundary

Implemented:

```text
activation receipt v2
boot-bound process identity
PID reuse detection
cgroup identity reconciliation
signed recovery observation
signed reconciliation decision
RUNNING -> EXITED_UNKNOWN
RUNNING -> QUARANTINED
RUNNING -> RUNNING recovery
post-recovery remote re-attestation gate
recovery-digest restart lineage
```

Not yet implemented:

```text
automatic supervisor daemon reconciliation loop
remote/shared reconciliation ledger
operator unquarantine protocol
kernel pidfd persistence across supervisor restart
systemd/Kubernetes reconciliation adapters
```

## Invariant

> A stale RUNNING bit is not evidence that a process is still the authorized workload. Recovery requires persistent process identity plus signed observation and an independent lifecycle decision before state is changed.
