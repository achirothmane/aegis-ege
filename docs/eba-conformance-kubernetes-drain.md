# Evidence-before-Action conformance: Kubernetes drain

This is the first cross-project conformance scenario for the Evidence-before-Action system.

It intentionally uses a real Aegis-EGE execution shape that already exists:

```text
kubernetes.node_drain
```

The scenario does not add a new runtime primitive and does not change the public
Aegis API yet.

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

## Why this is a harness first

This PR deliberately does **not** make the external `/execute` API require
new artifacts yet.

The sequence is:

```text
contract
→ cross-project conformance
→ prove fail-closed semantics
→ then decide whether to enforce the bundle at the public execution boundary
```

That keeps architecture behind evidence and avoids a breaking API change before
the contract itself has survived an integration test.
