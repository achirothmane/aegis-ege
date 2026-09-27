# Opt-in EBA enforcement at the Aegis execution boundary

Aegis-EGE can now enforce the proven `eba.integration/v0.1` Kubernetes-drain
profile directly at `POST /v1/ege/execute`.

The mode is **off by default**.

## Server configuration

Embedded server users enable it with:

```go
server.Config{
    RequireEBAConformance: true,
    EBAApprovalAuthority:  approvalAuthority,
    EBAExecutionPrincipal: "aegis-ege",
}
```

When enforcement is enabled, `EBAApprovalAuthority` is mandatory. Aegis will
not silently reuse an unrelated key or generate an ephemeral approval identity.

The standalone daemon does not expose a CLI flag yet because it does not have a
real approval-key loading path. Adding a flag without durable/verifiable key
configuration would create a mode that cannot be operated correctly.

## Execution request

The existing request remains valid while enforcement is disabled.

With enforcement enabled, the request also carries:

```json
{
  "eba": {
    "evidence_manifest": {},
    "assumption_artifacts": [],
    "authority_artifact": {},
    "approvals": []
  }
}
```

For `kubernetes.node_drain`, `budget_artifact` remains absent because the
operation is not token-consuming.

## Ordering

The enforcement order is intentionally:

```text
authenticate caller
→ verify signed permit
→ match permit to outer intent
→ validate full EBA conformance bundle
→ derive execution authorization
→ claim replay guard
→ execute mutation
```

This matters: an invalid EBA bundle does not consume the replay claim and never
reaches the mutation controller.

## Failure behavior

- missing bundle -> `403 EBA_CONFORMANCE_REQUIRED`
- invalid/tampered bundle -> `403 EBA_CONFORMANCE_BLOCKED`
- controller is not called
- replay guard is not claimed before EBA validation

## Backward compatibility

When `RequireEBAConformance == false`, the existing `/v1/ege/execute`
contract behaves as before. The new `eba` object is optional.

This gives us a migration path:

```text
conformance harness
→ opt-in execution enforcement
→ production key configuration
→ measured adoption
→ only then consider stronger defaults
```
