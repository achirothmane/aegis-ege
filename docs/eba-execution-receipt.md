# EBA ExecutionReceipt and feedback evidence

Aegis-EGE now emits an `eba.integration/v0.1` `ExecutionReceipt` for
completed execution reports from `POST /v1/ege/execute`.

The receipt closes the protocol-level loop without inventing a new audit
subsystem. StateLatch already has execution/outcome structures and a
tamper-evident journal; this artifact is the interoperable Evidence-before-
Action representation of the execution result returned by Aegis.

## Semantics

For the Kubernetes drain profile:

```text
execution decision ALLOW    -> receipt outcome SUCCEEDED
execution decision BLOCK    -> receipt outcome BLOCKED
execution decision ESCALATE -> receipt outcome ESCALATED
```

`SUCCEEDED` means the guarded execution report completed with `ALLOW`. It
does not claim any observation that is not present in that execution report.

The receipt contains:

- `request_ref` bound to the intent;
- `decision_ref` bound to the signed permit;
- `action_digest` bound to intent/kind/target/action/resource-version/plan;
- start and finish timestamps;
- execution outcome and reason codes;
- top-level resource change results;
- `produced_evidence_refs`;
- SHA-256 integrity.

## Receipt -> Evidence

Aegis also derives a separate `kind: Evidence` artifact with:

```text
evidence_type: execution_receipt
source_ref: <receipt id>
subject: exact intent/kind/target
claims:
  outcome
  plan_digest
  action_digest
  decision_ref
  resource_changes_digest
```

The receipt references this Evidence artifact, and the Evidence artifact
references the receipt.

This makes the next loop explicit:

```text
Execute
  ↓
ExecutionReceipt
  ↓
Evidence
  ↓
future EASL / assumption evaluation
```

The current PR deliberately does not invent an EASL persistence API. The
artifacts are returned to the caller and their IDs are included in Aegis audit
logging. Automatic ingestion should be added only when a real state/evidence
consumer exists.

## Existing journal relationship

The receipt does not replace the StateLatch tamper-evident journal.

```text
StateLatch journal:
  AUTHORIZATION -> EXECUTION -> OUTCOME
  local tamper-evident audit history

EBA ExecutionReceipt:
  cross-component execution artifact
  -> interoperable Evidence
```

They serve related but distinct boundaries.
