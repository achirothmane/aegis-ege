# Signed approval attestations

Aegis-EGE now distinguishes three different facts:

1. an action is otherwise eligible to execute;
2. an approval boundary was observed in a runtime trace;
3. a specific approver actually approved the exact action/plan.

These are not equivalent.

Runtime Witness can prove that a path crossed a named boundary such as
`approval:P`, but a boundary label alone does not authenticate the approver.

## ApprovalAttestation

A signed approval binds:

- `approval_id`
- `intent_id`
- `approver_id`
- action kind
- target
- action
- resource version
- plan digest
- expiration

The attestation is signed with the same `PermitAuthority` interface used by
Aegis execution permits. The current concrete implementation uses Ed25519.

## Binding to execution permits

`SignPermitWithApprovals` verifies every approval against the exact
`PermitClaims`, computes stable SHA-256 approval references, stores them in
`PermitClaims.approval_refs`, and signs the resulting permit.

`VerifyPermitWithApprovals` then requires:

- a valid execution permit signature;
- valid approval signatures;
- approvals not expired;
- exact intent/kind/target/action/resource-version/plan binding;
- the exact approval reference set carried by the permit.

This gives `approval_refs` real cryptographic semantics instead of treating a
log line or UI event as proof of approval.

## Runtime Witness relationship

Runtime Witness remains useful for a different question:

> Did the execution path actually pass through the required approval boundary?

A future integration can include the signed approval reference in the runtime
boundary event. That would join **approval authenticity** with **boundary
observability** without conflating the two.
