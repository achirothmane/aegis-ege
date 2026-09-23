# Server-side dry-run

StateLatch uses Kubernetes server-side dry-run as a production-adjacent verification gate without persisting the proposed mutation.

## What is dry-run

For a node drain StateLatch dry-runs:

1. the Node cordon patch;
2. every planned Pod eviction.

The cordon is bound to the observed Node `resourceVersion`.

Every eviction carries the observed Pod UID as a delete precondition.

## Why Pod resourceVersion is not a hard eviction precondition

Live KinD integration exposed a real race: Kubernetes can update a Pod's raw `resourceVersion` between observation and dry-run due to status/controller activity even when nothing relevant to drain safety changed.

Hard-binding eviction to that raw version produced false rejection.

StateLatch therefore separates:

```text
object identity → Pod UID precondition at Kubernetes API
drain semantics → semantic Pod state digest inside plan_digest
raw resourceVersion → audit/observation metadata
```

The semantic digest covers labels, owner identity, node assignment, mirror status, `emptyDir`, phase, readiness, deletion state, and UID.

## What happens after dry-run

A successful dry-run does not authorize a future mutation indefinitely.

StateLatch embeds the deterministic plan digest in a short-lived authorization.

Before future real execution:

```text
re-read live cluster
→ rerun preflight
→ rebuild semantic plan
→ recompute plan digest
→ validate TTL + node resourceVersion + plan digest
```

Only a still-valid plan can return `ALLOW`.

## What live CI now verifies

Against a temporary KinD Kubernetes cluster:

- server dry-run cordon is accepted and does not persist `spec.unschedulable=true`;
- server dry-run eviction is accepted and the Pod remains present;
- a healthy Pod protected by a zero-disruption PDB is rejected by the Eviction API;
- StateLatch blocks the same PDB-protected preparation;
- a drain-relevant live label change invalidates the authorized plan during revalidation.

## What dry-run does not prove

Dry-run requests are not persisted.

Therefore:

- a dry-run cordon does not actually make the node unschedulable;
- dry-run evictions do not consume PDB disruption budget;
- multiple dry-run evictions are not a persisted sequential drain;
- cluster state may change after the dry-run.

StateLatch compensates with aggregate PDB preflight plus final live plan revalidation.

The future real execution path must still use server-enforced preconditions on actual mutations.
