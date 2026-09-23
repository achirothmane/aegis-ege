# Adoption Gate

StateLatch has enough engineering proof for the current Kubernetes node-drain thesis.

The next bottleneck is **external adoption**, not additional architecture.

## Rule

Do not add a new major capability, cloud adapter, database adapter, or broad platform surface until external usage produces evidence that justifies it.

Internal benchmark improvement alone is not enough.

## Signals

We track three different kinds of evidence.

### 1. Attention

At least one of:

- 25+ downloads of the `v0.2.0-prealpha` release asset;
- 10+ GitHub stars from accounts other than the author.

Attention is useful, but it is **not sufficient** to pass the BUILD gate.

### 2. Real usage

At least **3 independent external users** must do one of the following:

- run the KinD/live benchmark suite successfully;
- run StateLatch against their own Kubernetes cluster;
- integrate or adapt the node-drain assurance path in another repository;
- provide reproducible feedback from a real Kubernetes workflow.

A star, page view, or anonymous clone does not count as real usage.

### 3. Intent / pain

At least **1 external real-workload signal** must show that the project solves or almost solves a problem someone actually cares about.

Examples:

- issue describing a real automation/drain safety problem;
- external PR or fork adapting StateLatch to a real workflow;
- request for a specific integration based on attempted usage;
- evidence that the user is considering the project instead of an existing policy/revalidation approach.

Feature requests without attempted use are weaker evidence and do not automatically pass this gate.

## Decision rule

### BUILD

Proceed with the next major capability only when:

```text
real usage >= 3 independent users
AND
real-workload intent >= 1 signal
```

Attention is supporting evidence, not a substitute.

### RETEST

If after 30 days:

```text
release downloads >= 25
but
real usage < 3
```

do **not** add features.

Investigate:

- onboarding friction;
- unclear use case;
- quickstart failure;
- positioning;
- missing packaging;
- mismatch between benchmark value and user value.

### DISTRIBUTE

If after 30 days:

```text
release downloads < 25
AND
little/no external usage
```

treat this primarily as a discovery/distribution problem.

Work on:

- README clarity;
- GitHub topics and description;
- relevant developer communities;
- benchmark write-up;
- issue/replay write-ups that demonstrate the problem;
- discoverability through Kubernetes/SRE/agent-infrastructure channels.

Do not respond by expanding the product surface.

### KILL / PAUSE

Pause major development if repeated distribution attempts produce:

```text
attention
but no attempted use
or
attempted use but no recurring pain
or
users consistently prefer simpler live-policy/revalidation approaches
```

The falsification benchmark exists to test technical differentiation. Adoption evidence must test whether that differentiation matters to users.

## What we measure

For every release/adoption cycle record:

| Metric | Meaning |
| --- | --- |
| release asset downloads | attention / curiosity |
| unique external issue authors | attempted use or pain |
| external PRs/forks tied to use | integration intent |
| confirmed live/KinD runs | real usage |
| repeat users | retention |
| requests tied to real workflows | product pull |
| paid interest | monetization signal |

Do not use stars alone as the success metric.

## Current baseline

At the start of `v0.2.0-prealpha`:

```text
confirmed external users: 0
confirmed external integrations: 0
paid users: 0
```

This file should be updated only when there is externally verifiable evidence.

## Next engineering rule

Until the BUILD gate passes:

- bug fixes are allowed;
- benchmark/incident replays are allowed when they test existing claims;
- onboarding/documentation improvements are allowed;
- packaging/release improvements are allowed;
- security fixes are allowed;
- major new capability work is paused.

**Evidence before action applies to product development too.**
