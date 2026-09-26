# Aegis-EGE evidence composition

Aegis-EGE can now evaluate a **composition policy** before minting an execution permit.

The control path is:

```text
Execution Intent
→ primary Evidence Producer
→ zero or more Evidence Contributors
→ composition policy
→ ALLOW / BLOCK / ESCALATE
→ Evidence Manifest v0alpha2
→ signed state-bound permit
→ Execution Adapter
→ live revalidation
→ guarded mutation
→ outcome verification
```

## Why composition exists

A single evidence producer can be correct and still share the same failure domain as the system it observes.

Aegis therefore models evidence as named sources with explicit trust domains:

```text
source name
+ trust domain
+ evidence digest
+ observed_at
+ evidence classes
```

A composition policy can require:

- a minimum number of evidence sources;
- a minimum number of distinct trust domains;
- specific named sources.

A permit is minted only when the composition satisfies that policy.

## Fail-closed semantics

The primary producer remains responsible for the exact action/state/plan binding used by the execution adapter.

Contributors can strengthen or contradict that evidence.

If a configured contributor:

- returns `BLOCK`, the composition returns `BLOCK`;
- returns `ESCALATE`, the composition returns `ESCALATE`;
- fails to produce evidence, the composition returns `ESCALATE / INSUFFICIENT_EVIDENCE`;
- produces invalid ALLOW evidence, Aegis treats that as an invalid trusted-component output and refuses permit minting;
- does not satisfy the minimum source/trust-domain policy, Aegis returns `ESCALATE / INSUFFICIENT_EVIDENCE`.

The original primary permit binding is removed from every failed composition result.

## Manifest binding

Evidence Manifest `aegis.ege/evidence/v0alpha2` includes the composed source set.

Example:

```json
{
  "api_version": "aegis.ege/evidence/v0alpha2",
  "intent_id": "intent-1",
  "kind": "kubernetes.node_drain",
  "target": {
    "type": "kubernetes.node",
    "name": "worker-7"
  },
  "resource_version": "123",
  "evidence_digest": "sha256:primary",
  "plan_digest": "sha256:plan",
  "observed_at": "2026-09-26T20:00:00Z",
  "evidence_classes": [
    "kubernetes.authoritative-state",
    "kubernetes.pdb-preflight",
    "kubernetes.server-dry-run"
  ],
  "sources": [
    {
      "name": "statelatch.kubernetes.node_drain",
      "trust_domain": "kubernetes-control-plane",
      "digest": "sha256:primary",
      "observed_at": "2026-09-26T20:00:00Z",
      "classes": [
        "kubernetes.authoritative-state",
        "kubernetes.pdb-preflight",
        "kubernetes.server-dry-run"
      ]
    }
  ]
}
```

The source list and per-source class list are canonicalized before the manifest is hashed. Reordering sources or classes does not change the manifest digest.

The execution permit is already bound to `evidence_manifest_digest`, so every composed source is transitively bound into the signed permit without changing the execution adapter's internal authorization format.

## Current production policy

Without an external contributor configured, the Kubernetes node-drain path keeps the original one-source policy:

```text
name:         statelatch.kubernetes.node_drain
trust_domain: kubernetes-control-plane

min_sources:       1
min_trust_domains: 1
required_source:   statelatch.kubernetes.node_drain
```

A real Prometheus node-health contributor can now be enabled with:

```text
--prometheus-node-health-url=https://prometheus.example
--prometheus-trust-domain=external-observability
```

When enabled, Aegis automatically strengthens the policy to:

```text
min_sources:       2
min_trust_domains: 2
required_sources:
  - statelatch.kubernetes.node_drain
  - prometheus.node_health
```

The Prometheus sample must be fresh and must agree with the primary StateLatch node-health observation. A stale sample blocks with `EVIDENCE_STALE`; a contradictory sample blocks with `EVIDENCE_CONTRADICTED`; an unavailable configured Prometheus source causes the composition to fail closed as `ESCALATE / INSUFFICIENT_EVIDENCE`.

### Independence requirement

The Prometheus trust-domain label is an operator assertion about operational independence. Aegis rejects the exact `kubernetes-control-plane` trust-domain name for this contributor, but it cannot prove from a URL alone that Prometheus is actually independent.

To count this as genuinely independent evidence, the Prometheus deployment and the metric's data path should not merely mirror the same Kubernetes control-plane state through the same failure domain. The useful case is out-of-band observability that can detect a condition the control plane might miss or misreport.

The KinD integration path now exercises the public Aegis prepare/execute flow with the Prometheus contributor enabled and requires two named sources in two declared trust domains before the permit is accepted.

## Multi-source proof

Unit tests exercise the composition engine with synthetic independent sources and require:

```text
primary control-plane evidence
+ telemetry-plane evidence
+ simulation-plane evidence
→ three sources
→ three trust domains
→ ALLOW
```

They also prove:

- two sources in the same trust domain do not satisfy a two-domain policy;
- a contradictory contributor forces `BLOCK`;
- a missing required source forces `ESCALATE`;
- an unavailable configured contributor forces `ESCALATE`.

## Next evidence gate

Do not add a second real source solely to increase a counter.

A second production source should be added only when it contributes genuinely independent information to a concrete high-consequence action.

Candidate classes include:

```text
independent telemetry
deterministic simulation
external policy attestation
formal verification result
```

The key test is not "can Aegis ingest it?" but:

> Does this source reduce a real failure mode that the existing trust domain cannot independently detect?
