# Server-side dry-run

StateLatch uses Kubernetes server-side dry-run as a production-adjacent verification gate without persisting the proposed mutation.

## What is dry-run

For a node drain StateLatch dry-runs:

1. the Node cordon patch;
2. every planned Pod eviction.

The cordon is bound to the observed Node `resourceVersion`.

Every eviction carries:

```text
Pod UID
Pod resourceVersion
```

as delete preconditions.

## What happens after dry-run

A successful dry-run does not directly authorize a future mutation forever.

StateLatch computes a deterministic digest of the full plan and embeds it in a short-lived authorization.

Before any future real execution:

```text
Re-read live cluster
→ rerun preflight
→ rebuild plan
→ recompute plan digest
→ validate TTL + resourceVersion + plan digest
```

Only an unchanged, still-valid plan can return `ALLOW`.

## What server dry-run proves

It proves that, at the moment each request was evaluated, Kubernetes accepted the proposed operation under the reached validation/admission path and supplied state preconditions.

## What it does not prove

Dry-run requests are not persisted.

Therefore:

- a dry-run cordon does not actually make the node unschedulable;
- dry-run evictions do not consume PDB disruption budget;
- multiple dry-run evictions are not a persisted sequential drain;
- cluster state may change after the dry-run.

StateLatch compensates with aggregate PDB preflight plus final live plan revalidation.

The future real execution path must still use state preconditions on actual mutations.
