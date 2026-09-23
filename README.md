# StateLatch

**Evidence before action for autonomous Kubernetes changes.**

StateLatch is an experimental runtime-assurance layer for high-consequence automation. Before an automated system changes Kubernetes, StateLatch asks:

> Is the evidence that justified this action still current, consistent, sufficient, and valid for this exact action and world state?

Today the proof target is deliberately narrow: **Kubernetes node drain**. The goal is to prove the execution-safety model before expanding the surface area.

## Why this exists

A normal request-time policy can be correct when it runs and still become unsafe milliseconds later.

Examples StateLatch is designed to catch:

```text
policy says ALLOW
→ PDB changes
→ original decision is now stale

Kubernetes says healthy
→ Prometheus says unhealthy
→ evidence conflicts

authorization was valid
→ Pod is replaced or its drain-relevant state changes
→ execution plan is no longer the authorized plan

drain finishes
→ a new workload appears directly on the cordoned node
→ expected outcome no longer matches reality
```

The control loop is:

```text
Observe
→ maintain evidence/assumptions
→ verify
→ acquire missing evidence safely
→ authorize exact action + state
→ execute
→ observe outcome
→ record divergence
```

Insufficient evidence does **not** become ALLOW:

```text
UNKNOWN → safe read-only probe → re-evaluate
still unknown → ESCALATE
contradiction → BLOCK
```

## 60-second quickstart

Requires Go 1.25+.

```bash
git clone https://github.com/achirothmane/state-latch
cd state-latch

go test ./...
go run ./cmd/moatbench
```

The second command runs the reproducible synthetic falsification benchmark and prints the baseline-vs-StateLatch comparison.

The main CI also creates a temporary KinD cluster and runs the live Kubernetes adversarial and incident-replay suites.

## What the benchmark currently shows

### Benchmark v1 — 40 labeled synthetic cases

Baseline:

```text
live primary lookup
+ fixed TTL
+ static policy
+ request-time decision
```

Current CI result:

| Metric | Baseline | StateLatch |
| --- | ---: | ---: |
| Unsafe ALLOWs | 19 | **0** |
| Unresolved/UNKNOWN ALLOWs | 4 | **0** |
| Safe blocks | 0 | **0** |
| Safe escalations | 0 | **0** |
| Postflight divergences detected | 0/2 | **2/2** |

CPU-only GitHub-runner microbenchmark from the same run:

```text
Baseline   ~61 ns/scenario
StateLatch ~1.9 µs/scenario
```

This is **not production latency**. Real Kubernetes/Prometheus network and API costs dominate these in-memory numbers.

### Benchmark v2 — live adversarial KinD corpus

Eight live cases use real Kubernetes state transitions.

Current CI result:

| Metric | Baseline | StateLatch |
| --- | ---: | ---: |
| Unsafe ALLOWs | 3 | **0** |
| Unresolved-source ALLOWs | 1 | **0** |
| Safe controls preserved | 2/2 | **2/2** |
| Ordinary PDB policy block | 1/1 | **1/1** |
| Postflight divergence detected | 0/1 | **1/1** |

The baseline is intentionally not trivial: it performs a live request-time Kubernetes preflight over Node/Pods/PDB state. It simply lacks StateLatch's continuous invalidation, independent evidence, state-bound revalidation, and postflight loop.

### Benchmark v3 — source-backed incident replay

The replay suite uses public Kubernetes issue reports as external scenario sources.

One replay **falsified StateLatch before it passed**:

```text
real drain succeeds
→ Node remains cordoned
→ a new Pod is created with spec.nodeName
→ old postflight logic returns MATCH   ❌
```

That exposed a real gap: postflight only checked the originally authorized Pod UIDs.

The repair added this invariant:

```text
unexpected_workload_pods = 0
```

The same replay then passed without changing its success criterion.

Other source-backed replays verify:

- same Pod name with a different UID invalidates the old authorization;
- a rejected cordon stops execution before any Pod eviction.

See [Real incident replay benchmark v3](docs/real-incident-replay-v3.md).

## What StateLatch adds beyond request-time policy

### 1. Continuous invalidation

A watched world-state change can invalidate an assumption **before another execution request arrives**.

```text
Kubernetes event
→ resource dependency
→ assumption invalidated
```

### 2. Transitive assumption graph

Higher-level assumptions can depend on lower-level assumptions.

```text
PDB changed
→ "PDB permits disruption" invalid
→ "node drain is safe" invalid
```

The target Node itself does not need to change.

### 3. Independent evidence

StateLatch can require distinct evidence sources.

```text
Kubernetes = healthy
Prometheus = unhealthy
→ BLOCK / EVIDENCE_CONTRADICTED
```

If evidence is missing, a bounded **READ_ONLY** probe can acquire it and force a deterministic re-evaluation.

### 4. Fresh-evidence reconciliation

Contradictions are not resolved by majority vote.

```text
historical contradiction
→ start fresh evidence epoch
→ reacquire independent sources
→ agree     → ALLOW may become possible
→ disagree  → BLOCK
→ incomplete → ESCALATE
```

### 5. Action-sensitive temporal validity

The same assumption may be fresh enough for a low-consequence action but expired for a critical one.

```text
same assumption, age 20s

LOW window = 60s
→ VALID

CRITICAL window = 5s
→ EXPIRED / BLOCK
```

Event invalidation always dominates temporal freshness.

### 6. State-bound authorization

The plan is built from Kubernetes-observed state, not agent-supplied state.

Authorization is bound to the exact execution context, including:

- action and target;
- Node identity and state;
- deterministic plan digest;
- evidence digest;
- short expiry;
- Pod identity and drain-relevant semantic state.

A same-name replacement Pod is not treated as the original object.

### 7. Revalidation during execution

With experimental mutations enabled:

```text
final live revalidation
→ cordon
→ re-read state
→ compare remaining plan
→ evict one Pod
→ observe deletion
→ revalidate
→ repeat
```

The execution loop does not blindly consume a previously authorized plan.

### 8. Single-writer execution lease

Real mutation execution now requires a Kubernetes `coordination.k8s.io/v1 Lease` for the target Node.

```text
acquire target Lease
→ revalidate
→ checkpoint
→ mutate
→ renew/verify ownership before each mutation
→ release
```

A second StateLatch executor targeting the same Node receives:

```text
ESCALATE / EXECUTION_LOCK_HELD
```

If the holder loses the Lease during execution:

```text
ESCALATE / EXECUTION_LOCK_LOST
```

and no later mutation is attempted.

See [Execution locking](docs/execution-locking.md).

### 9. Tamper-evident execution journal

M6 adds a signed append-only journal for the authorization → execution → outcome lifecycle.

```text
authorization
→ execution
→ postflight outcome
→ hash-chained JSONL
→ Ed25519-signed head anchor
```

Verification detects entry modification, reordering, middle deletion, tail truncation against the current signed anchor, anchor tampering, and missing anchors.

The journal is audit evidence only; it does not participate in ALLOW/BLOCK/ESCALATE authority.

A full rollback of both the journal and a matching older valid signed anchor requires an external monotonic/WORM reference to detect and remains outside M6.

See [Tamper-evident execution journal](docs/tamper-evident-journal.md).

### 10. Postflight outcome verification

StateLatch compares expected and observed outcome:

```text
MATCH
DIVERGED
UNKNOWN
```

For node drain, postflight checks include:

- Node remains unschedulable;
- originally evicted Pod UIDs remain absent;
- no unexpected non-terminal, non-mirror, non-DaemonSet workload appears on the drained Node.

Outcome reliability calibration exists, but it is **advisory only**. It cannot silently rewrite production authorization policy.

## Safe-by-default mutation model

Normal constructors keep real mutations disabled:

```go
NewForConfig(config)
NewWithExecutor(reader, executor)
```

Real mutation currently requires the explicitly named experimental path:

```go
NewForConfigWithExperimentalMutations(config)
```

Without that opt-in, real execution returns:

```text
ESCALATE / REAL_EXECUTION_UNAVAILABLE
```

Production mutation enablement is intentionally not part of this pre-alpha release.

## Node-drain checks

Current preflight includes:

```text
DaemonSet pod without explicit ignore
→ BLOCK

Unmanaged pod without explicit force
→ BLOCK

emptyDir without explicit delete permission
→ BLOCK

PDB disruption capacity insufficient
→ BLOCK

PDB status stale
→ ESCALATE

PDB state unavailable
→ ESCALATE
```

Mirror/static Pods are recorded and skipped according to drain semantics.

Server-side dry-run is required for the cordon and every planned eviction before an authorization is exposed.

## Partial failure and recovery

Experimental real execution can persist a checkpoint and recover from interruption.

```go
ExecuteAuthorizedNodeDrainWithCheckpointStore(...)
InspectDrainRecovery(...)
ResumeAuthorizedNodeDrain(...)
```

Recovery is state-derived:

```text
load checkpoint
→ re-read Kubernetes
→ reconcile already-observed completion
→ rebuild remaining state
→ require fresh authorization if work remains
→ resume only the current authorized remainder
```

A stale authorization is never silently reused after partial execution.

See [Partial failure and recovery](docs/partial-failure-recovery.md).

## What is implemented

- continuous Kubernetes watch invalidation;
- transitive assumption dependency graph;
- action-sensitive temporal validity;
- bounded read-only active evidence acquisition;
- independent Prometheus-compatible HTTP evidence;
- contradiction detection and fresh-epoch reconciliation;
- Node / Pod / PDB live state inspection;
- server-side dry-run cordon and eviction;
- deterministic execution plan + digest;
- state-bound short-lived authorization;
- final and in-flight revalidation;
- real guarded cordon + eviction behind explicit experimental opt-in;
- Pod UID and semantic-state protection;
- persistent partial-failure checkpoints and recovery;
- Kubernetes Lease-based single-writer execution locking;
- synchronous lock verification before each real mutation;
- live lock contention protection on KinD;
- signed hash-chained execution journal with Ed25519 head anchor;
- HTTP daemon/API with server-owned node-drain policy;
- TLS 1.3 mTLS caller identity with separate PREPARE/EXECUTE permissions;
- durable replay rejection for state-bound authorizations;
- Kubernetes-backed shared checkpoint state with resourceVersion concurrency;
- cluster-wide shared replay claims for multi-replica execution safety;
- live authorization → execution → outcome journal binding in KinD;
- postflight expected-vs-observed comparison;
- advisory reliability ledger;
- synthetic, live KinD, and source-backed incident falsification suites.

## What is not implemented

- production mutation enablement;
- external fencing token enforced by mutation targets;
- external WORM/KMS/transparency anti-rollback anchor for the journal;
- production signing-key custody / HSM integration;
- mature rollback/compensation semantics;
- full `kubectl drain` parity;
- AWS/GCP/SSH/database/PLC adapters;
- automatic policy changes from reliability calibration.

StateLatch is still a **controlled research/prototype system**, not a production-ready drain replacement.

## Adoption gate

Development is now gated by external adoption evidence rather than feature count.

**No new major capability or new infrastructure adapter is justified solely because it is technically interesting.**

The next BUILD gate requires external usage evidence. See [ADOPTION.md](ADOPTION.md) for the thresholds and decision rules.

## Docs

- [Adoption gate](ADOPTION.md)
- [Real incident replay benchmark v3](docs/real-incident-replay-v3.md)
- [Kubernetes node-drain adapter](docs/kubernetes-node-drain.md)
- [Server-side dry-run](docs/server-dry-run.md)
- [Guarded experimental execution](docs/guarded-real-execution.md)
- [Partial failure and recovery](docs/partial-failure-recovery.md)
- [Execution locking](docs/execution-locking.md)
- [Tamper-evident execution journal](docs/tamper-evident-journal.md)
- [Daemon API](docs/daemon-api.md)
- [mTLS authentication and authorization](docs/mtls-authz.md)
- [Shared HA state](docs/shared-ha-state.md)
- [v1.0 completion roadmap](V1_ROADMAP.md)
- [Decision contract](docs/decision-contract.md)

## Current status

**v0.2.0-prealpha**

The execution-safety thesis now has three evidence layers:

```text
synthetic falsification
→ live KinD adversarial testing
→ source-backed incident replay
```

That supports a differentiation claim for the tested Kubernetes drain scenarios. It does **not** establish a commercial moat, production-wide superiority, or broad incident coverage.

## Design principle

**Evidence before action.**
