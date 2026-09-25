# Aegis-EGE v0 — execution-intent gate

Aegis-EGE is the product/protocol layer above StateLatch.

StateLatch remains the evidence and state-assurance engine. Aegis-EGE gives agents and automation a stable execution-gate contract:

```text
agent / automation
→ execution intent
→ evidence + state verification
→ ALLOW / BLOCK / ESCALATE
→ exact action-bound authorization
→ execution
→ revalidation during execution
→ postflight verification
→ audit
```

## Why this slice exists

The first Aegis-EGE slice deliberately does **not** add AWS, GCP, SSH, databases, PLCs, a dashboard, or an LLM to the trusted execution path.

It proves one thing first:

> Can a generic execution-intent envelope sit above the already-tested StateLatch node-drain engine without weakening its fail-closed guarantees?

The only supported intent kind in v0 is:

```text
kubernetes.node_drain
```

The only supported target type is:

```text
kubernetes.node
```

All existing StateLatch evidence, plan binding, replay protection, authentication, execution locking, in-flight revalidation, checkpointing, and postflight behavior remain authoritative.

## Prepare

`POST /v1/ege/prepare`

Example:

```json
{
  "intent_id": "intent-2026-09-25-001",
  "kind": "kubernetes.node_drain",
  "target": {
    "type": "kubernetes.node",
    "name": "worker-7"
  }
}
```

A successful response uses the Aegis envelope while carrying the same StateLatch decision and exact authorization:

```json
{
  "api_version": "aegis.ege/v0alpha1",
  "intent_id": "intent-2026-09-25-001",
  "kind": "kubernetes.node_drain",
  "target": {
    "type": "kubernetes.node",
    "name": "worker-7"
  },
  "decision": "ALLOW",
  "plan_digest": "sha256:...",
  "authorization": {
    "action_id": "intent-2026-09-25-001",
    "action": "drain",
    "target": "node/worker-7",
    "resource_version": "...",
    "evidence_digest": "sha256:...",
    "plan_digest": "sha256:...",
    "valid_until": "..."
  }
}
```

## Execute

`POST /v1/ege/execute`

The caller must return the exact authorization issued by prepare together with the same intent identity, kind, and target.

A mismatch fails before the controller is called.

Real mutations remain disabled by default. Enabling execution retains the existing StateLatch requirements:

- authenticated caller;
- EXECUTE permission;
- replay guard;
- checkpoint store;
- exact action and target binding;
- fresh authorization;
- final live revalidation;
- target execution Lease;
- revalidation before subsequent mutations.

## Unsupported intent kinds

An unsupported intent kind returns:

```text
422 / UNSUPPORTED_INTENT_KIND
```

It is never forwarded to an infrastructure adapter.

That is intentional. Aegis-EGE v0 is an execution gate, not an arbitrary proxy.

## Compatibility

The existing endpoints remain available:

```text
POST /v1/node-drains/prepare
POST /v1/node-drains/execute
```

The Aegis endpoints are an additional protocol surface over the same engine.

## Next proof gate

Do not add a second infrastructure adapter until this contract is exercised end-to-end and the adapter boundary is proven by tests.

The next architectural step after that is an explicit adapter registry where each adapter must implement:

```text
normalize intent
→ observe authoritative state
→ collect/verify evidence
→ deterministic prepare
→ exact permit binding
→ execute with revalidation
→ verify outcome
```

The execution path remains deterministic. LLMs may assist outside the trusted computing base, but they do not decide ALLOW.
