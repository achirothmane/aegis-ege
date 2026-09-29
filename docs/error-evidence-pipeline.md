# Error Evidence Pipeline (EEP) v0

Status: experimental subsystem.

EEP is the runtime-evidence compilation layer inside Aegis-EGE. It is not an observability dashboard and it does not infer organizational authority from behavior.

The purpose is to turn a runtime event into a deterministic, policy-bound Evidence Packet that can be consumed by EASL, EBA conformance, approvals, permit minting, consequence gates, and the tamper-evident journal.

## Control path

```text
Runtime event
→ source/provenance binding
→ declared authority + policy binding
→ deterministic redaction
→ canonical Evidence Packet
→ packet integrity digest
→ EASL / EBA / approval / consequence gates
→ signed permit / journal
```

## Bootstrap axiom

EEP deliberately rejects zero-context setup.

Authority, policy, redaction profile, and consequence class must be supplied from declared or independently verifiable organizational sources.

```text
observed runtime behavior
≠ authority
```

The compiler therefore fails closed when `authority_ref`, `policy_ref`, `redaction_profile_ref`, or `consequence_class` is absent.

## Evidence Packet v0alpha2

The current packet binds:

- runtime source name and trust domain;
- execution `intent_id` for downstream action binding;
- event, workflow, and run identifiers;
- actor/principal and agent identity;
- action kind, tool, operation, target, and side-effect flag;
- input-event digest;
- observation and capture timestamps;
- authority, policy, redaction-profile, consequence-class, control, and approval references;
- an optional execution binding for destination/account/endpoint/adapter/expected-state context;
- redacted evidence body;
- the exact redacted JSON Pointer paths;
- a canonical SHA-256 packet digest.

Sensitive paths are expressed as RFC 6901 JSON Pointers. A declared sensitive path that cannot be found causes compilation to fail rather than silently emitting a possibly unsafe packet.

## Current guarantees

Unit tests prove that:

1. declared sensitive values are absent from the compiled packet;
2. compilation does not mutate the original runtime event;
3. missing authority context is rejected;
4. missing declared sensitive paths fail closed;
5. packet modification is detected;
6. packet digests are stable across JSON map insertion order;
7. an execution permit can be minted only when packet intent/kind/operation/target match the permit and the packet represents a side effect;
8. changing the bound `evidence_packet_digest` invalidates the permit signature;
9. the same digest can be projected into the tamper-evident journal together with a digest of the signed permit;
10. when an execution binding is present, the signed Permit must carry the exact same binding and resource version before it can consume that packet.

## Security boundary

The SHA-256 packet digest detects modification of the packet but does not by itself authenticate the runtime source.

Source authenticity still depends on the surrounding Aegis trust boundary, such as authenticated transport, a source attestation, or a signature.

For EEP-aware execution, the binding path is now explicit:

```text
Evidence Packet v0alpha2
→ verify packet integrity
→ require exact intent + kind + operation + target + side-effect binding
→ if present, require exact execution destination/account/endpoint/profile/state binding
→ evidence_packet_digest in PermitClaims
→ Ed25519-signed execution permit
→ verified permit projection
→ evidence_packet_digest + permit payload digest in hash-chained journal event
```

The journal projection refuses permits that do not carry an Evidence Packet digest. Because the packet digest is inside the signed permit claims, substituting the digest breaks permit verification; because the same digest is inside the hash-chained journal event, changing the recorded binding breaks journal verification.

Likewise, `control_refs` are references to applicable controls. Their presence is not proof that a system is compliant.

## Product boundary

EEP v0 is intentionally cross-runtime at the data-model level. Permit/journal binding primitives now exist, but the current Kubernetes prepare path does not fabricate EEP organizational context and no n8n, Make, LangGraph, MCP, or SaaS adapter is claimed yet.

The next expansion is evidence-gated:

```text
generic compiler proven
→ packet digest bound into signed permit + tamper-evident journal
→ one real workflow adapter
→ prove pre/post action evidence on a real side effect
→ external usage signal
→ only then add more adapters
```

The commercial hypothesis to test is not "another AI audit log." It is whether teams need a cross-runtime compiler that converts raw agent/workflow events into authority-bound, redacted evidence that can directly govern the next consequential action.
