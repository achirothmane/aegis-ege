# Aegis-EGE v0 — evidence-gated execution intent

Aegis-EGE is the product/protocol layer above StateLatch.

StateLatch remains the evidence and state-assurance engine. Aegis-EGE gives agents and automation a stable execution-gate contract:

```text
agent / automation
→ execution intent
→ evidence + state verification
→ evidence composition policy
→ ALLOW / BLOCK / ESCALATE
→ evidence manifest
→ signed, state-bound execution permit
→ live revalidation
→ execution
→ postflight verification
→ audit
```

## Why this slice exists

The first Aegis-EGE slice deliberately does **not** add AWS, GCP, SSH, databases, PLCs, a dashboard, ZK proofs, eBPF enforcement, or an LLM to the trusted execution path.

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

When StateLatch reaches `ALLOW`, Aegis-EGE emits two artifacts in addition to the decision:

1. an **Evidence Manifest** that identifies the evidence/state/plan the decision depended on;
2. a short-lived **Ed25519-signed execution permit** bound to the exact intent, target, state version, evidence digest, manifest digest, plan digest, and expiry.

Conceptual response:

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
  "evidence_manifest": {
    "api_version": "aegis.ege/evidence/v0alpha2",
    "intent_id": "intent-2026-09-25-001",
    "kind": "kubernetes.node_drain",
    "target": {
      "type": "kubernetes.node",
      "name": "worker-7"
    },
    "resource_version": "...",
    "evidence_digest": "sha256:...",
    "plan_digest": "sha256:...",
    "observed_at": "...",
    "evidence_classes": [
      "kubernetes.authoritative-state",
      "kubernetes.pdb-preflight",
      "kubernetes.server-dry-run"
    ],
    "sources": [
      {
        "name": "statelatch.kubernetes.node_drain",
        "trust_domain": "kubernetes-control-plane",
        "digest": "sha256:...",
        "observed_at": "...",
        "classes": [
          "kubernetes.authoritative-state",
          "kubernetes.pdb-preflight",
          "kubernetes.server-dry-run"
        ]
      }
    ]
  },
  "permit": {
    "api_version": "aegis.ege/permit/v0alpha1",
    "key_id": "ed25519:...",
    "claims": {
      "intent_id": "intent-2026-09-25-001",
      "kind": "kubernetes.node_drain",
      "target": {
        "type": "kubernetes.node",
        "name": "worker-7"
      },
      "action": "drain",
      "resource_version": "...",
      "evidence_digest": "sha256:...",
      "evidence_manifest_digest": "sha256:...",
      "plan_digest": "sha256:...",
      "valid_until": "..."
    },
    "signature": "..."
  }
}
```

The permit is domain-separated and signed over its canonical claims. Changing the plan, target, evidence binding, state version, or expiry after issuance invalidates the signature.

## Execute

`POST /v1/ege/execute`

The caller returns the signed permit together with the same outer intent identity, kind, and target.

Aegis-EGE verifies the signature before constructing the internal StateLatch authorization. It then requires the signed claims to match the outer execution intent exactly.

A forged or modified permit returns:

```text
403 / INVALID_EXECUTION_PERMIT
```

A valid permit that belongs to a different intent or target returns:

```text
400 / PERMIT_INTENT_MISMATCH
```

Only after those checks can the request reach the StateLatch mutation controller.

Real mutations remain disabled by default. Enabling execution retains the existing StateLatch requirements:

- authenticated caller;
- EXECUTE permission;
- replay guard;
- checkpoint store;
- exact action and target binding;
- fresh authorization;
- exact resource-version and plan binding;
- final live revalidation;
- target execution Lease;
- revalidation before subsequent mutations;
- postflight verification.

This means a valid signature is **necessary but not sufficient**. A permit can be authentic and still become unusable because the world changed after it was issued.

## Permit authority in v0

The server currently creates an ephemeral Ed25519 permit authority when no authority is injected.

That has a useful fail-closed property: a daemon restart invalidates outstanding permits.

It is not yet the production HA/key-custody design. Multi-replica production deployment requires a shared or externally controlled signing/verification authority with rotation and custody semantics.

The `PermitAuthority` interface exists so that the in-process signer can later be replaced without changing the protocol contract.

## Unsupported intent kinds

An unsupported intent kind returns:

```text
422 / UNSUPPORTED_INTENT_KIND
```

It is never forwarded to an infrastructure adapter.

That is intentional. Aegis-EGE v0 is an execution gate, not an arbitrary proxy.

## Compatibility

The existing StateLatch endpoints remain available during the transition:

```text
POST /v1/node-drains/prepare
POST /v1/node-drains/execute
```

The Aegis endpoints are the product-level protocol surface over the same assurance engine.

## Current proof

The KinD integration test exercises the public Aegis-EGE path end-to-end:

```text
mTLS caller
→ /v1/ege/prepare
→ real Kubernetes evidence/preflight/dry-run
→ Evidence Manifest
→ signed execution permit
→ /v1/ege/execute
→ permit verification
→ StateLatch live revalidation
→ guarded real node drain
→ verify resulting node state
→ replay same permit
→ HTTP 409
```

Unit tests also require permit tampering to fail cryptographic verification.

## Evidence composition

Permit minting now sits behind an evidence-composition policy.

The current Kubernetes production path still has one real evidence source, `statelatch.kubernetes.node_drain`, in the `kubernetes-control-plane` trust domain. The composition engine is capable of requiring multiple named sources and distinct trust domains, and those multi-source gates are exercised in unit tests.

The Evidence Manifest v0alpha2 carries the canonicalized source set. Its digest is signed indirectly through `evidence_manifest_digest` in the execution permit.

See [evidence-composition.md](evidence-composition.md).

## Next proof gate

Do not add a second infrastructure adapter or a decorative second evidence source.

The next real source must reduce a failure mode that the existing Kubernetes control-plane trust domain cannot independently detect. Independent telemetry or deterministic simulation are candidates only if concrete evidence shows that they materially improve a high-consequence decision.

The execution path remains deterministic. LLMs may assist outside the trusted computing base, but they do not decide `ALLOW`.
