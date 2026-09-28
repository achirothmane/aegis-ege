# Workload Lifecycle / Restart Governance v1

A one-shot workload admission grant prevents replay of a single start, but it does not by itself govern what happens after the process exits.

This layer makes every subsequent activation an explicit lifecycle decision.

## Governing rule

> A restart never reuses the previous admission grant. Every new generation requires a fresh grant, and abnormal or stale conditions may require a fresh remote TPM + IMA attestation before that grant can be issued.

## Lifecycle chain

```text
Signed Admission Grant
        |
        v
Governed Start
        |
        v
Signed Activation Receipt
        |
        v
RUNNING lifecycle state
        |
        v
process exits
        |
        v
Signed Exit Receipt
        |
        v
EXITED lifecycle state
        |
        v
Restart Evaluator
   |            |
   |            +--> BLOCK
   |
   +--> REQUIRE_REATTESTATION
   |
   +--> REQUIRE_FRESH_GRANT
                 |
                 v
        fresh admission request
                 |
                 v
       lifecycle-authorized
         fresh admission grant
                 |
                 v
          governed restart
```

## Signed exit receipt

Every governed workload exit produces a host-attestor-signed receipt containing:

```text
exit_id
activation_id
activation_digest
grant_id
grant_digest
device_id
workload_id
workload_spec_digest
target_cgroup
target_cgroup_id
process_id
exit_class
exit_code
signal
started_at
exited_at
```

Exit classes are:

```text
CLEAN
NONZERO
SIGNAL
```

The exit receipt is cryptographically linked to the activation receipt and admission grant.

## Durable lifecycle ledger

The host stores one lifecycle record per:

```text
device_id + workload_id
```

The record contains:

```text
generation
RUNNING | EXITED
activation_digest
exit_digest
restart_count_in_window
restart_window_started_at
updated_at
```

The state file is protected by a process-shared filesystem lock and updated through fsync + atomic rename.

### Concurrency

The lifecycle lock is held while a workload start is authorized and created.

Therefore two concurrent starts for the same device/workload cannot both pass the local lifecycle transition.

A `RUNNING` state rejects another start.

## Generation semantics

Initial activation creates:

```text
generation = 1
restart_count_in_window = 0
```

Every authorized restart increments generation.

A restart decision must reference exactly:

```text
previous generation
previous activation digest
previous exit digest
```

A decision from generation N cannot be reused after generation N+1 exists.

## Immutable restart identity

A restart is not an upgrade.

The signed restart decision binds:

```text
device_id
workload_id
workload_spec_digest
target_cgroup
target_cgroup_id
bootstrap_digest
```

Changing any of these requires a new lifecycle/deployment path rather than a restart:

- executable or arguments;
- environment;
- cgroup;
- cgroup identity;
- BPF bootstrap identity.

This prevents a restart authorization from becoming permission to launch a materially different workload.

## Restart outcomes

The lifecycle authority emits exactly one of:

### BLOCK

Restart is prohibited.

Examples:

- clean exit restart is disabled by policy;
- restart budget is exhausted;
- bootstrap identity changed.

### REQUIRE_REATTESTATION

The host must complete a new remote TPM + IMA attestation before restart can be authorized.

Examples:

- remote attestation is too old;
- current remote decision is not ALLOW;
- a NONZERO exit requires post-exit re-attestation;
- a SIGNAL exit requires post-exit re-attestation.

For abnormal exits, the new remote decision must have:

```text
verified_at > exit_receipt.exited_at
```

This avoids the invalid loop where an attestation taken before the failure is treated as evidence about host state after the failure.

### REQUIRE_FRESH_GRANT

The host state is acceptable for restart, but the previous grant remains permanently consumed.

The admission authority must issue a new workload admission grant.

## Restart budget

The policy defines:

```text
max_restarts_per_window
restart_window
```

Example:

```text
3 restarts / 10 minutes
```

When the budget is exhausted, restart is BLOCKED.

When the window expires, the counter resets and a new window begins.

## Exponential backoff

A restart decision also carries a signed `not_before`.

Backoff is deterministic:

```text
delay = min(
  base_backoff * 2^restart_count,
  max_backoff
)
```

with overflow-safe integer duration arithmetic.

The deadline is anchored to the failure:

```text
not_before =
  max(
    evaluation_time,
    exit_time + delay
  )
```

Re-attesting later does not restart the backoff clock.

## Decision lifetime

A signed restart decision contains:

```text
evaluated_at
not_before
expires_at
```

Its validity period begins at `not_before`.

An admission authority cannot issue a restart grant before the signed backoff has elapsed.

## Restart grant issuance

Restart uses a dedicated issuer path.

The admission authority verifies:

1. lifecycle authority signature;
2. outcome is `REQUIRE_FRESH_GRANT`;
3. device/workload match;
4. workload spec matches;
5. cgroup path and inode match;
6. bootstrap digest matches;
7. current remote-decision digest matches the restart decision.

Only then can the normal admission logic mint a new one-shot grant.

## Governed process start

`aegis-attested-run` now uses the lifecycle ledger.

### First generation

No restart decision is supplied.

The start succeeds only if no lifecycle already exists.

### Later generations

A signed restart decision and lifecycle-authority public key are required.

The host checks the decision against the current EXITED state before consuming the fresh grant.

The actual process still starts through:

```text
CLONE_INTO_CGROUP
```

so lifecycle governance does not weaken cgroup-bound activation.

## Fail-closed state transition

Start sequence:

```text
lock lifecycle
verify state
verify restart decision if needed
consume fresh admission grant
create process in cgroup
sign activation receipt
persist RUNNING
unlock lifecycle
```

If persisting RUNNING fails after process creation, Aegis kills the child.

The consumed grant remains consumed.

## Exit sequence

```text
wait for process
classify exit
sign exit receipt
lock lifecycle
verify current RUNNING activation digest
persist EXITED + exit digest
unlock
```

If EXITED persistence fails, the signed exit receipt is still returned with an error so recovery can preserve evidence rather than invent state.

## Commands

### Initial run

```bash
sudo go run ./cmd/aegis-attested-run \
  -grant workload-admission-grant.json \
  -issuer-pub admission-authority.pub \
  -spec workload-spec.json \
  -consumption-dir /var/lib/aegis/consumed-workload-grants \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -host-attestor-key host-attestation.key \
  -receipt workload-activation-receipt.json \
  -exit-receipt workload-exit-receipt.json
```

### Evaluate restart

```bash
go run ./cmd/aegis-restart-evaluate \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -device node-01 \
  -workload payments-worker \
  -prior-grant workload-admission-grant.json \
  -activation workload-activation-receipt.json \
  -exit workload-exit-receipt.json \
  -remote-decision remote-attestation-decision.json \
  -remote-verifier-pub remote-verifier.pub \
  -admission-issuer-pub admission-authority.pub \
  -host-attestor-pub host-attestation.pub \
  -lifecycle-key lifecycle-authority.key \
  -lifecycle-authority-id prod-lifecycle \
  -out workload-restart-decision.json
```

If the result is `REQUIRE_REATTESTATION`, perform a fresh TPM + IMA attestation and run the evaluator again with the new signed remote decision.

### Issue fresh restart grant

After the evaluator returns `REQUIRE_FRESH_GRANT` and `not_before` has elapsed:

```bash
go run ./cmd/aegis-admission-restart-issue \
  -request fresh-workload-admission-request.json \
  -remote-decision remote-attestation-decision.json \
  -restart-decision workload-restart-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -remote-verifier-pub remote-verifier.pub \
  -issuer-key admission-authority.key \
  -issuer-id prod-workload-admission \
  -out workload-restart-admission-grant.json
```

### Restart

```bash
sudo go run ./cmd/aegis-attested-run \
  -grant workload-restart-admission-grant.json \
  -issuer-pub admission-authority.pub \
  -spec workload-spec.json \
  -consumption-dir /var/lib/aegis/consumed-workload-grants \
  -lifecycle-dir /var/lib/aegis/workload-lifecycle \
  -restart-decision workload-restart-decision.json \
  -lifecycle-authority-pub lifecycle-authority.pub \
  -device node-01 \
  -host-attestor-key host-attestation.key \
  -receipt workload-activation-receipt-generation-2.json \
  -exit-receipt workload-exit-receipt-generation-2.json
```

## Security state

The lifecycle ledger is security-relevant local state.

Deleting it is not equivalent to “retry.”

Operational recovery from a lost ledger must be treated as creation of a new lifecycle/deployment and should require explicit operator policy.

A privileged attacker that can arbitrarily modify Aegis binaries, keys, cgroups, and lifecycle storage remains outside this layer's local threat boundary.

## Current boundary

Implemented:

```text
signed exit receipts
durable RUNNING / EXITED ledger
generation fencing
restart budget
failure-anchored exponential backoff
post-exit re-attestation policy
fresh-grant-only restart
immutable workload identity across restart
lifecycle-authorized restart grant issuance
concurrent local start exclusion
signed lifecycle decisions
```

Not yet implemented:

```text
distributed lifecycle ledger
automatic network transport between host/verifier/admission authority
systemd/Kubernetes native restart-controller integration
container/OCI lifecycle specialization
graceful-drain policy before planned restart
health-check based restart causes

```

## Crash reconciliation

Orphaned RUNNING state is now reconciled through process-bound activation receipt v2, signed recovery observations, and an independent lifecycle authority decision. Recovery may preserve RUNNING, mark EXITED_UNKNOWN, or quarantine the lifecycle. EXITED_UNKNOWN requires post-recovery TPM + IMA attestation before a fresh restart grant can be issued.

See [orphaned-running-reconciliation.md](orphaned-running-reconciliation.md).

## Invariant

> A process exit destroys the authority used for that generation. A later generation requires an explicit lifecycle decision and a newly issued one-shot admission grant; abnormal or stale conditions require new hardware-rooted evidence first.
