# Aegis-EGE

**Do not let automation mutate infrastructure on stale or contradictory evidence.**

Aegis-EGE is an experimental evidence-gated execution layer for AI agents and high-consequence automation.

The first proven path is deliberately narrow:

```text
Kubernetes node drain
```

An agent or automation can propose the action. Aegis-EGE decides whether the current evidence is sufficient to let that exact action execute against that exact world state.

> **Evidence before action.**

## The failure Aegis-EGE is built for

A request-time policy can be correct when it runs and still become unsafe before or during execution.

```text
policy says ALLOW
→ world state changes
→ automation executes anyway
```

Aegis-EGE instead uses:

```text
Execution Intent
→ Evidence Producer(s)
→ Evidence Composition Policy
→ ALLOW / BLOCK / ESCALATE
→ Evidence Manifest
→ Signed, state-bound Permit
→ Live Revalidation
→ Guarded Mutation
→ Outcome Verification
```

A valid signature is necessary but not sufficient. If the world changes after permit issuance, execution can still be rejected.

## One concrete falsification

The repository contains a KinD integration test that evaluates the **same node** and **same drain intent** in two paths.

Kubernetes alone:

```text
NodeReady=True
→ ALLOW
→ signed permit
```

Then with an independently declared Prometheus evidence source reporting the node unhealthy:

```text
Kubernetes: healthy
Prometheus: unhealthy
→ EVIDENCE_CONTRADICTED
→ BLOCK
→ no permit
→ no mutation
```

That proves incremental decision value: the external evidence domain can veto an action the Kubernetes-only path would otherwise authorize.

See [Prometheus falsification v1](docs/prometheus-falsification-v1.md).

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/aegis-ege
cd aegis-ege

go test ./...
go run ./cmd/moatbench
```

The first command runs the unit suite. The second runs the reproducible synthetic falsification benchmark.

CI also creates a temporary KinD cluster and runs live adversarial, integration, replay, and Aegis-EGE evidence-gating tests.

## What the benchmark currently shows

### Synthetic benchmark v1 — 40 labeled cases

| Metric | Request-time baseline | StateLatch assurance |
| --- | ---: | ---: |
| Unsafe ALLOWs | 19 | **0** |
| Unresolved/UNKNOWN ALLOWs | 4 | **0** |
| Safe blocks | 0 | **0** |
| Safe escalations | 0 | **0** |
| Postflight divergences detected | 0/2 | **2/2** |

CPU-only GitHub-runner microbenchmark from the same benchmark:

```text
Baseline   ~61 ns/scenario
StateLatch ~1.9 µs/scenario
```

These are **not production latencies**. Real Kubernetes/Prometheus network and API costs dominate.

### Live adversarial KinD benchmark v2

| Metric | Request-time baseline | StateLatch assurance |
| --- | ---: | ---: |
| Unsafe ALLOWs | 3 | **0** |
| Unresolved-source ALLOWs | 1 | **0** |
| Safe controls preserved | 2/2 | **2/2** |
| Ordinary PDB policy block | 1/1 | **1/1** |
| Postflight divergence detected | 0/1 | **1/1** |

### Source-backed incident replay v3

One replay initially falsified the system:

```text
real drain succeeds
→ Node remains cordoned
→ a new Pod appears via spec.nodeName
→ old postflight logic returns MATCH   ❌
```

The repair added the invariant:

```text
unexpected_workload_pods = 0
```

The same replay then passed without changing the success criterion.

See [Real incident replay benchmark v3](docs/real-incident-replay-v3.md).

## Evidence composition

Aegis-EGE can bind multiple named evidence sources into one Evidence Manifest and require a composition policy before permit minting.

Current source model:

```text
source name
+ trust domain
+ evidence digest
+ observed_at
+ evidence classes
```

Policy can require:

- minimum source count;
- minimum distinct trust-domain count;
- specific named sources.

When Prometheus node-health is configured, the node-drain policy becomes:

```text
statelatch.kubernetes.node_drain
+ prometheus.node_health
+ 2 declared trust domains
→ permit eligible
```

If Prometheus contradicts Kubernetes, Aegis returns `BLOCK`. If required external evidence is unavailable, Aegis fails closed with `ESCALATE`.

Important limitation: Aegis can enforce distinct declared trust-domain identities, but operational independence still depends on how the observability path is actually deployed.

See [Evidence composition](docs/evidence-composition.md).

## StateLatch: the current assurance engine

StateLatch is the Kubernetes assurance engine inside Aegis-EGE.

It provides:

- continuous Kubernetes state invalidation;
- transitive assumption dependencies;
- action-sensitive temporal validity;
- bounded read-only evidence acquisition;
- contradiction detection and fresh-evidence reconciliation;
- Node / Pod / PDB inspection;
- server-side dry-run;
- deterministic execution plans and digests;
- short-lived state-bound authorization;
- final and in-flight revalidation;
- Pod UID and semantic-state protection;
- Kubernetes Lease single-writer execution locking;
- durable replay rejection;
- persistent partial-failure checkpoints;
- postflight expected-vs-observed verification;
- signed hash-chained execution journal;
- external anti-rollback/key-custody boundaries;
- mTLS caller identity with separate PREPARE/EXECUTE permissions.

## Public Aegis-EGE protocol

Prepare:

```text
POST /v1/ege/prepare
```

A successful ALLOW can return:

```text
Evidence Manifest v0alpha2
+
Ed25519-signed execution permit
```

The permit is bound to the exact:

- intent;
- kind;
- target;
- action;
- resource version;
- evidence digest;
- Evidence Manifest digest;
- plan digest;
- expiry.

Execute:

```text
POST /v1/ege/execute
```

Before mutation, Aegis verifies the permit and StateLatch performs live revalidation.

## Prometheus external evidence

Optional daemon configuration:

```text
--prometheus-node-health-url=https://prometheus.example
--prometheus-trust-domain=external-observability
```

When configured, Prometheus becomes required evidence for node-drain permit minting.

The Prometheus sample must:

- target the exact node;
- resolve to exactly one series;
- be fresh;
- contain a supported binary health value;
- agree with the primary StateLatch observation.

## Safe-by-default mutation model

Real Kubernetes mutations are disabled by default.

Normal constructors:

```go
NewForConfig(config)
NewWithExecutor(reader, executor)
```

Experimental mutation constructors:

```go
NewForConfigWithExperimentalMutations(config)
```

Without explicit opt-in, execution cannot mutate infrastructure.

Aegis-EGE is still **pre-alpha** and is not a production-ready replacement for `kubectl drain`.

## What is not implemented

- production-ready mutation enablement;
- external fencing token enforced by mutation targets;
- mature rollback/compensation semantics;
- full `kubectl drain` parity;
- complete deployment/operations packaging;
- production hardening/RC validation;
- AWS/GCP/SSH/database/PLC adapters;
- generic arbitrary Kubernetes mutation proxy;
- automatic policy learning.

## Current product boundary

The supported real execution path is still intentionally narrow:

```text
kind:        kubernetes.node_drain
target_type: kubernetes.node
```

We are **not** adding more infrastructure adapters just to demonstrate extensibility.

The current bottleneck is external usage and product discovery, not feature count.

## Try it and report what breaks

If you run Aegis-EGE in KinD or against a non-sensitive Kubernetes workflow, report the result—even if the result is “this is too complicated” or “I would use a simpler alternative.”

[Open an adoption / real usage report](https://github.com/achirothmane/aegis-ege/issues/new?template=adoption.yml)

That feedback is the gate for major product expansion.

## Docs

- [Aegis-EGE v0 protocol](docs/aegis-ege-v0.md)
- [Evidence producers](docs/evidence-producers.md)
- [Evidence composition](docs/evidence-composition.md)
- [Prometheus falsification v1](docs/prometheus-falsification-v1.md)
- [Adapter registry](docs/adapter-registry.md)
- [Adoption gate](ADOPTION.md)
- [Kubernetes node-drain adapter](docs/kubernetes-node-drain.md)
- [Guarded experimental execution](docs/guarded-real-execution.md)
- [Execution locking](docs/execution-locking.md)
- [Partial failure and recovery](docs/partial-failure-recovery.md)
- [Tamper-evident execution journal](docs/tamper-evident-journal.md)
- [mTLS authentication and authorization](docs/mtls-authz.md)
- [Shared HA state](docs/shared-ha-state.md)
- [v1.0 completion roadmap](V1_ROADMAP.md)

## Current status

**v0.3.0-prealpha candidate**

Technical evidence currently includes:

```text
synthetic falsification
→ live KinD adversarial testing
→ source-backed incident replay
→ signed evidence-gated execution
→ multi-source evidence composition
→ Prometheus incremental-value falsification
```

This supports the tested Kubernetes node-drain safety claims. It does **not** establish production-wide superiority, a commercial moat, or broad incident coverage.

## License

Licensed under the [Apache License 2.0](LICENSE).

## Design principle

**Evidence before action.**
