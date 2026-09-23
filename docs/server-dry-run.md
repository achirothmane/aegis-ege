# Server-side dry-run

StateLatch uses Kubernetes server-side dry-run as a production-adjacent verification gate without persisting the proposed mutation.

## Why server-side instead of local-only simulation

A server dry-run reaches Kubernetes validation and admission logic and is evaluated by the API server while avoiding persistence.

For the node-drain path, StateLatch dry-runs:

1. the Node cordon patch;
2. every planned Pod eviction.

## State binding

The cordon request carries the observed Node `resourceVersion`.

Each eviction carries preconditions for:

```text
Pod UID
Pod resourceVersion
```

This protects against a same-name Pod being recreated or changed between observation and dry-run.

## Decision semantics

```text
all dry-run operations accepted
→ preparation may return ALLOW + authorization

dry-run capability unavailable
→ ESCALATE

cordon dry-run rejected
→ BLOCK

one or more eviction dry-runs rejected
→ BLOCK
```

## What it proves

A passing report proves that, at the time each request was evaluated, Kubernetes accepted the proposed operation under the state preconditions and server-side validation/admission rules reached by that request.

## What it does not prove

It does not prove that a later real drain will succeed.

Dry-run requests are not persisted. In particular, multiple independent dry-run evictions do not mutate PDB state between requests. StateLatch therefore keeps a separate aggregate PDB preflight and must still revalidate state immediately before future real execution.
