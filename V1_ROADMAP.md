# StateLatch v1.0 Definition of Done

StateLatch v1.0 is a production-oriented Kubernetes node-drain assurance service.

It is not a multi-cloud automation gateway. AWS/GCP/SSH/database/PLC adapters do not block v1 completion.

## Completed foundation

- M0: continuous world-state invalidation
- M1: bounded active evidence acquisition
- M2: independent evidence and contradiction reconciliation
- M3: transitive assumption dependency graph
- M4: action-sensitive temporal validity
- M5: postflight divergence and advisory reliability calibration
- Kubernetes Lease single-writer execution locking
- M6: signed tamper-evident execution journal
- Benchmarks v1, v2, and v3

## Remaining v1 milestones

### M7 — daemon / API surface

Long-running state-latchd, health endpoint, prepare endpoint, execution endpoint with mutations disabled by default, strict request parsing, bounded bodies, server timeouts, graceful shutdown, and KinD proof that default daemon mode cannot mutate.

### M8 — caller authentication and authorization — IMPLEMENTED / pending CI merge

mTLS URI-SAN identity, separate PREPARE and EXECUTE permissions, default deny, structured identity audit records, durable single-daemon replay protection, TLS 1.3, and no mutation enablement without authentication/replay/checkpoint configuration.

### M9 — shared durable state / HA recovery — IMPLEMENTED / pending CI merge

Kubernetes-backed shared checkpoint storage, resourceVersion optimistic concurrency, cluster-wide replay claims, cross-replica recovery proof, and Kubernetes shared state as the production daemon default.

### M10 — external anti-rollback anchor and key custody

Signer interface, KMS/HSM-compatible production boundary, external latest-head or monotonic anchor, rollback detection against external state, key rotation, and historical verification.

### M11 — compensation and recovery semantics

Classify reversible and irreversible steps; safe uncordon only when StateLatch proves ownership and safety; never recreate evicted workloads blindly; operator-visible recovery state; idempotent resume; crash tests around every mutation boundary.

### M12 — Kubernetes drain compatibility contract

DaemonSets, mirror/static Pods, unmanaged Pods, emptyDir, PDBs, terminal/terminating Pods, graceful termination, replacement Pods/controllers, deleted/recreated objects, documented unsupported cases, and differential compatibility tests where appropriate.

### M13 — deployment and operations

Minimal non-root container, Helm/manifests, least-privilege RBAC, ServiceAccount, NetworkPolicy, probes, structured logs, Prometheus metrics, resource guidance, and upgrade/uninstall documentation.

### M14 — production hardening / release candidate

Race detector, parser fuzzing, concurrent-load test, lock contention stress, kill/restart chaos during execution, timeout/cancellation tests, security/dependency scanning, supported Kubernetes-version matrix, upgrade test, maintained zero-unsafe-ALLOW corpus, and release-candidate soak.

## v1.0 release gate

Tag v1.0.0 only when M7 through M14 are PASS and CI enforces the critical safety guarantees.

## Out of scope for v1.0

- AWS APIs
- GCP APIs
- SSH / bare metal
- databases
- PLC / OPC-UA
- automatic policy learning
- generic arbitrary Kubernetes mutation proxy
- multi-cloud orchestration

## Product rule during v1 completion

The repository owner explicitly chose to complete the bounded v1 production-hardening track before the external adoption gate is met. This exception applies only to M7-M14 and bug/security work needed to finish the already-proven Kubernetes node-drain product. It does not authorize broad feature expansion or new infrastructure adapters before adoption evidence.
