# Aegis-EGE adapter registry

The adapter registry is the dispatch boundary between the generic Aegis-EGE protocol and infrastructure-specific execution logic.

Evidence preparation now lives behind a separate **Evidence Producer Registry**.

The public protocol is:

```text
Execution Intent
→ Evidence Producer Registry
→ primary evidence/state production
→ Evidence Contributors
→ composition policy
→ Evidence Manifest
→ signed execution permit
→ verify permit
→ Execution Adapter Registry
→ adapter-specific authorization reconstruction
→ replay protection
→ adapter execution with live revalidation
→ outcome verification
```

## First registered adapter

The execution registry currently contains exactly one production path:

```text
kind:        kubernetes.node_drain
target_type: kubernetes.node
engine:      StateLatch execution path
```

The matching evidence producer is also StateLatch-backed, but it is registered separately from the execution adapter.

This is an architectural extraction, not a surface-area expansion. No second infrastructure adapter is introduced.

## Fail-closed routing

The execution registry is immutable after server construction.

It rejects:

- an unregistered intent kind;
- a target type that does not match the registered adapter;
- duplicate registrations for the same intent kind;
- adapters with empty kind or target metadata.

An unsupported kind never reaches an infrastructure controller.

The evidence producer registry applies the same fail-closed kind/target routing rules independently.

## Execution adapter contract

Each execution adapter owns only the infrastructure-specific mutation side of the control loop:

```text
reconstruct adapter authorization from verified permit claims
→ execute with adapter-specific live revalidation
→ return decision/outcome evidence
```

It does **not** prepare evidence or mint permits.

Cross-cutting Aegis-EGE guarantees remain outside execution adapters:

- public intent envelope;
- evidence producer/contributor dispatch;
- evidence composition policy;
- Evidence Manifest construction;
- permit signing and signature verification;
- outer intent/permit identity matching;
- replay protection;
- authentication and authorization at the API boundary;
- audit emission.

This split prevents a future execution adapter from becoming the sole authority for both evidence generation and mutation while allowing each infrastructure domain to retain its own state and mutation semantics.

## Expansion gate

A second adapter should not be added merely to demonstrate extensibility.

The next adapter must be justified by evidence of a real high-consequence action where:

1. the action is already automated or being delegated to agents;
2. stale or incomplete state can make the mutation unsafe;
3. the required preconditions can be observed and bound to a permit;
4. live revalidation can detect meaningful state drift before/during mutation;
5. the result can be verified after execution.

Until that evidence exists, Kubernetes node drain remains the reference adapter and falsification target.
