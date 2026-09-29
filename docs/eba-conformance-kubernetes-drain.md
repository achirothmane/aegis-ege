# Evidence-before-Action conformance: Kubernetes drain

This is the first cross-project conformance scenario for the Evidence-before-Action system.

It intentionally uses a real Aegis-EGE execution shape that already exists:

```text
kubernetes.node_drain
```

The scenario does not add a new runtime primitive. It began as a harness-first
profile and is now enforced opt-in at the governed `/v1/ege/execute` boundary.

## Required artifacts

For this profile, execution conformance requires:

```text
EvidenceManifest        required
AssumptionState         required
AuthorityGrant          required
ApprovalAttestation     required
BudgetReservation       not applicable
Signed Permit           required
```

The token budget is explicitly rejected for this profile. A Kubernetes node
drain is not a token-consuming operation, so attaching a synthetic
`BudgetReservation` would weaken the meaning of `budget_ref`.

## Cross-project sources

The fixture shapes are compatible with:

- EASL / Aegis evidence semantics;
- `assumption-gate` -> `AssumptionState`;
- Agent Action Guard -> `AuthorityGrant`;
- Aegis-EGE -> signed `ApprovalAttestation` and execution `Permit`;
- Token Governance Protocol is intentionally absent for this execution profile.

## Context and issuer trust

The Kubernetes drain profile uses `eba.context/v1` with a server-owned
audience and singleton deployment namespace. The client does not authenticate
itself by choosing those strings.

AssumptionState and AuthorityGrant remain self-hashed for integrity, but that
hash is not accepted as issuer authentication. Their canonical artifact
digests, trace id, audience and namespace are bound into the signed execution
Permit. A rehashed substitute therefore fails unless the trusted permit issuer
has explicitly bound that exact artifact.

The server then still validates the artifact's semantic bindings: principal,
intent/subject, action, resource, evidence reference and profile context. The
signed parent binding and the artifact's local integrity serve different
purposes.

## Canonical representation

External AssumptionState and AuthorityGrant JSON is consumed under
`eba.canonical-json/v1` before artifact-reference or integrity checks.

The Go consumer rejects duplicate object keys, fractional/exponent-form
numbers, negative zero, integers outside the shared safe range, malformed JSON
string forms and artifacts that do not declare the current canonical profile.

Canonical hashes use deterministic key ordering and the same string escaping as
the Python reference corpus. Genesis/bootstrap canonicalization is a separate
assurance contract and is not changed here.

## What is proved

The conformance validator fails closed when:

- required assumptions are missing, invalid, expired, or tampered;
- the authority grant is missing, tampered, expired, revoked, or scoped to
  another principal/action/resource/context;
- the evidence manifest no longer matches the signed permit;
- the approval set is missing or no longer matches the signed permit;
- a token budget is attached to this non-token execution profile.

The positive test demonstrates the full profile can compose without requiring
the repositories to call each other over the network.

## Harness-first history and current execution boundary

This profile was intentionally proven in a cross-project harness before it was
enforced at a mutation boundary. The current opt-in sequence is:

```text
contract
→ cross-project conformance
→ fail-closed validation
→ governed /v1/ege/execute enforcement
```

When EBA conformance or capability fencing is configured, the legacy
`/v1/node-drains/execute` request shape cannot satisfy the stronger governed
obligations and is rejected with `409 EGE_EXECUTION_REQUIRED` before replay
claiming or controller mutation. Callers must use the EGE execution boundary.

When those EGE-only obligations are not configured, the legacy authenticated
and replay-guarded path remains available for backward compatibility.
