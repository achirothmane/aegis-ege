# Aegis-EGE adapter registry

The adapter registry is the dispatch boundary between the generic Aegis-EGE protocol and infrastructure-specific execution logic.

The public protocol remains:

```text
Execution Intent
→ resolve adapter by intent kind + target type
→ adapter-specific evidence/state preparation
→ Evidence Manifest
→ signed execution permit
→ verify permit
→ resolve same adapter
→ adapter-specific authorization reconstruction
→ replay protection
→ adapter execution with live revalidation
→ outcome verification
```

## First registered adapter

The registry currently contains exactly one production path:

```text
kind:        kubernetes.node_drain
target_type: kubernetes.node
engine:      StateLatch
```

This is an architectural extraction, not a surface-area expansion. No second infrastructure adapter is introduced in this change.

## Fail-closed routing

The registry is immutable after server construction.

It rejects:

- an unregistered intent kind;
- a target type that does not match the registered adapter;
- duplicate registrations for the same intent kind;
- adapters with empty kind or target metadata.

An unsupported kind never reaches an infrastructure controller.

## Adapter contract

Each execution adapter owns the infrastructure-specific parts of the control loop:

```text
prepare authoritative state/evidence
→ expose permit binding
→ reconstruct adapter authorization from verified permit claims
→ execute with adapter-specific live revalidation
→ return decision/outcome evidence
```

Cross-cutting Aegis-EGE guarantees remain outside adapters:

- public intent envelope;
- Evidence Manifest construction;
- permit signing and signature verification;
- outer intent/permit identity matching;
- replay protection;
- authentication and authorization at the API boundary;
- audit emission.

This split prevents a future adapter from bypassing the generic execution gate while allowing each infrastructure domain to retain its own state model and mutation semantics.

## Expansion gate

A second adapter should not be added merely to demonstrate extensibility.

The next adapter must be justified by evidence of a real high-consequence action where:

1. the action is already automated or being delegated to agents;
2. stale or incomplete state can make the mutation unsafe;
3. the required preconditions can be observed and bound to a permit;
4. live revalidation can detect meaningful state drift before/during mutation;
5. the result can be verified after execution.

Until that evidence exists, Kubernetes node drain remains the reference adapter and falsification target.
