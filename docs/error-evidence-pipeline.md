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

## Evidence Packet v0alpha1

The current packet binds:

- runtime source name and trust domain;
- event, workflow, and run identifiers;
- actor/principal and agent identity;
- action kind, tool, operation, target, and side-effect flag;
- input-event digest;
- observation and capture timestamps;
- authority, policy, redaction-profile, consequence-class, control, and approval references;
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
6. packet digests are stable across JSON map insertion order.

## Security boundary

The SHA-256 packet digest detects modification of the packet but does not by itself authenticate the runtime source.

Source authenticity still depends on the surrounding Aegis trust boundary, such as authenticated transport, a source attestation, or a signature. The packet digest can then be transitively bound into a signed permit or journal record.

Likewise, `control_refs` are references to applicable controls. Their presence is not proof that a system is compliant.

## Product boundary

EEP v0 is intentionally cross-runtime at the data-model level, but no n8n, Make, LangGraph, MCP, or SaaS adapter is claimed yet.

The next expansion is evidence-gated:

```text
generic compiler proven
→ one real workflow adapter
→ bind packet digest into Aegis permit/journal path
→ prove pre/post action evidence on a real side effect
→ external usage signal
→ only then add more adapters
```

The commercial hypothesis to test is not "another AI audit log." It is whether teams need a cross-runtime compiler that converts raw agent/workflow events into authority-bound, redacted evidence that can directly govern the next consequential action.
