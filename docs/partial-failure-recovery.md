# Partial failure and recovery

StateLatch treats a multi-step drain as a stateful execution, not as a command that can be blindly replayed after an interruption.

Real mutations remain experimental and disabled by default.

## Recovery invariant

After a partial execution, StateLatch does **not** assume that the last local write reflects what Kubernetes actually did.

The recovery sequence is:

```text
checkpoint
+
current Kubernetes reality
        ↓
reconcile
        ↓
remaining authorized state
        ↓
fresh authorization required
        ↓
resume only the remainder
```

Kubernetes is the source of truth for whether an authorized Pod UID is still present.

## Checkpoint model

`DrainExecutionCheckpoint` stores:

```text
action ID
node name / UID / health
original plan digest
active plan digest
originally authorized Pods
completed Pod UIDs
cordon state
RUNNING / PAUSED / COMPLETED
last decision
last reason codes
updated_at
```

The original authorized Pod set is preserved across resume attempts. A fresh authorization may bind only to the remaining subset.

## Stores

StateLatch exposes the `DrainCheckpointStore` interface.

### Memory store

```go
store := NewMemoryDrainCheckpointStore()
```

Useful for tests and single-process experiments. It does not survive process loss.

### File store

```go
store, err := NewFileDrainCheckpointStore("/var/lib/state-latch/checkpoints")
```

The file store:

- creates the checkpoint directory with restrictive permissions;
- writes a temporary file;
- fsyncs the file;
- atomically renames it over the per-action checkpoint file;
- derives the filename from SHA-256(actionID), avoiding path traversal through action IDs.

This is a local durability primitive, not an HA/distributed journal.

## Starting checkpointed execution

```go
report, err := adapter.ExecuteAuthorizedNodeDrainWithCheckpointStore(
    ctx,
    authorization,
    nodeName,
    policy,
    store,
)
```

Before the first real mutation, StateLatch writes the initial checkpoint.

After a real cordon is accepted, it records `Cordoned=true` before moving on.

After each eviction is both accepted **and observed absent by UID**, that UID is added to `CompletedPodUIDs`.

If a checkpoint write fails, execution stops with:

```text
ESCALATE / EXECUTION_CHECKPOINT_UNAVAILABLE
```

No later mutation is attempted.

## Ambiguous mutation outcome

A critical failure mode is:

```text
Eviction API accepts request
→ Pod disappears
→ process crashes before checkpoint update
```

On restart, the checkpoint may say the Pod is incomplete even though Kubernetes already removed it.

`InspectDrainRecovery(...)` reconciles this safely:

1. load the last checkpoint;
2. re-read Node, Pods, and PDBs;
3. for each originally authorized Pod UID not marked completed:
   - if that exact UID is absent, mark it reconciled/completed;
   - if it remains, keep it in the remaining set;
4. rerun preflight;
5. require the live evictable set to equal the expected remaining semantic set.

This avoids replaying an already-completed eviction.

## Recovery outcomes

`InspectDrainRecovery(...)` returns one of:

```text
COMPLETED
→ all originally authorized Pod UIDs are satisfied/absent

REAUTHORIZATION_REQUIRED
→ state is reconcilable and work remains

BLOCKED
→ current preflight has a hard blocker such as a PDB

DIVERGED
→ current state no longer matches the recoverable remainder
```

Useful reason codes include:

```text
RECOVERY_REAUTHORIZATION_REQUIRED
RECOVERY_STATE_DIVERGED
RECOVERY_CHECKPOINT_NOT_FOUND
EXECUTION_CHECKPOINT_UNAVAILABLE
```

## Fresh authorization is mandatory

A two-Pod authorization cannot be reused after one Pod has already been removed.

That old authorization remains bound to the old plan digest.

Recovery therefore requires:

```text
InspectDrainRecovery
→ REAUTHORIZATION_REQUIRED
→ PrepareNodeDrainExecution again on current live state
→ obtain new authorization for remaining plan
→ ResumeAuthorizedNodeDrain
```

`ResumeAuthorizedNodeDrain(...)` revalidates that the fresh authorization's live Pod set exactly equals the checkpoint's remaining authorized set before any mutation.

## Cordon handling during resume

If the checkpoint and live state agree that the Node is already cordoned, resume does not issue a second cordon mutation.

If the checkpoint says the Node was cordoned but the Node is now schedulable:

```text
ESCALATE / EXECUTION_CORDON_STATE_CHANGED
```

Recovery does not silently re-cordon and continue.

## Live KinD evidence

CI contains a real partial-failure scenario:

```text
2 authorized Pods
→ real cordon
→ Kubernetes accepts eviction of Pod A
→ injected interruption returned before completion checkpoint
→ checkpoint still shows no completed Pod
→ recovery observes Pod A UID is absent
→ reconciles Pod A as completed
→ old two-Pod authorization is rejected
→ fresh one-Pod authorization is created
→ resume evicts only Pod B
→ checkpoint becomes COMPLETED
```

This validates recovery against a real temporary Kubernetes API server.

## Current limits

The checkpoint mechanism is intentionally narrow.

It does not yet provide:

- rollback or compensation for already-applied mutations;
- distributed locking against two StateLatch executors using the same action ID;
- an HA/shared checkpoint backend;
- a cryptographically tamper-evident append-only event log;
- retention, compaction, or operator tooling;
- automatic policy for a Pod that remains terminating after an accepted eviction.

Those are separate production-readiness concerns. The v0.1 recovery guarantee is narrower:

> **Never blindly replay a partially completed drain. Re-read reality, reconcile exact identities, require a fresh authorization for the remainder, then continue only from verified state.**
