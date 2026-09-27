# Ambiguous mutation outcome boundary

Aegis-EGE treats mutation outcome uncertainty as an execution-layer problem, not as an EASL epistemic-state primitive.

This boundary is now supported by evidence from two different mutation domains.

## Invariant

> If a mutation request may have been applied but its outcome is not yet confirmed, do not blindly replay it. Re-read reality, reconcile exact state, and require fresh authority before continuing.

This is different from the EASL subject-state invariant.

EASL answers whether a justification still holds for the state that was observed. Mutation ambiguity begins after a write may already have crossed the external system boundary.

## Domain 1 — Kubernetes partial execution

Aegis-EGE already handles the ambiguous-outcome case in the node-drain path.

A representative failure is:

```text
Eviction request accepted
→ Pod disappears
→ executor crashes before checkpoint update
```

The local checkpoint can therefore be stale relative to Kubernetes reality.

Aegis-EGE does not blindly replay the eviction. Recovery performs:

```text
checkpoint
+ current Kubernetes reality
→ reconcile exact Pod UIDs and node state
→ derive remaining work
→ require fresh authorization
→ resume only the verified remainder
```

Reference implementation:

- `internal/kubeadapter/recovery.go`
- `docs/partial-failure-recovery.md`

This makes Kubernetes the source of truth for whether an authorized mutation actually took effect.

## Domain 2 — GitHub Actions rerun mutation

CI Retry Gate independently exercises the same safety shape.

For mutating GitHub API calls, transport ambiguity is not retried automatically. A POST interrupted by an incomplete response performs one transport attempt and then fails closed.

Reference consumer:

`achirothmane/workflow-failure-lab`

Reference test:

`test_github_api_does_not_retry_post_on_incomplete_response`

The selective rerun path also reports an unconfirmed write as:

```text
SELECTIVE_MUTATION_UNCONFIRMED
```

rather than issuing another POST from the same justification.

The external consumer E2E further proves that after an accepted selective rerun, the old workflow-state epoch is not reused for a second write.

## Shared rule

The shared execution rule is:

```text
intent
→ authorization
→ state revalidation
→ mutation attempt
→ outcome known?
    yes → continue from confirmed state
    no  → do not replay blindly
          re-read reality
          reconcile
          obtain fresh authority if work remains
```

The domains differ in mechanics:

- Kubernetes can reconcile object identity and live presence.
- GitHub Actions exposes workflow attempts and job execution timestamps.

The common safety property is **reconciliation before replay**, not a shared domain model.

## Why this does not belong in EASL

EASL currently owns:

- evidence sufficiency;
- freshness;
- contradiction;
- assumption dependencies;
- temporal validity;
- subject-state binding.

It does not own:

- write acknowledgement semantics;
- idempotency;
- external mutation receipts;
- checkpoint durability;
- replay orchestration;
- compensation;
- recovery scheduling.

Adding mutation-result states to EASL would mix epistemic justification with execution recovery.

## Extraction status

This concept has cross-domain evidence, but it is **not yet promoted to a standalone shared runtime primitive**.

Current evidence justifies a boundary and an invariant:

> **Never replay an ambiguous mutation from old authority. Reconcile external reality first.**

A reusable execution primitive should be extracted only if another implementation begins duplicating concrete reconciliation machinery such as:

- mutation identity;
- outcome state;
- external observation;
- confirmed-applied / confirmed-not-applied / unknown;
- fresh-authority requirement for the remainder.

Until then, Aegis-EGE keeps Kubernetes recovery logic local and CI Retry Gate keeps GitHub-specific mutation handling local.

## Relationship to subject-state binding

The two invariants compose:

```text
before write:
    subject-state binding
    → old justification invalid after state drift

after uncertain write:
    reconciliation-before-replay
    → old authority cannot justify blind repetition
```

Together they enforce a wider rule:

> **Evidence before action, and reality before replay.**
