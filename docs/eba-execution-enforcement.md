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

The standalone daemon can load a durable Ed25519 approval **public key** and
enable the same enforcement mode without holding the approval private key.

```text
--enable-mutations
--require-eba-conformance
--eba-approval-public-key-file=/etc/aegis/approval-public-key.pem
--eba-execution-principal=aegis-ege
```

The public key must be PKIX PEM with a `PUBLIC KEY` block containing an
Ed25519 key. Aegis derives the approval `key_id` from the public key using
the same SHA-256 fingerprint scheme as the signer.

The daemon refuses to start when:

- `--require-eba-conformance` is used without `--enable-mutations`;
- the approval public-key path is missing;
- the file is unreadable;
- the PEM is malformed, contains trailing non-whitespace data, is not a
  `PUBLIC KEY` block, or does not contain an Ed25519 key.

The daemon receives verification material only. Approval signing remains
outside the execution service, preserving separation between approval issuance
and mutation execution.

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
→ evaluate consequence admissibility
→ derive execution authorization
→ claim replay guard
→ execute mutation
```

This matters: an invalid EBA bundle does not consume the replay claim and never
reaches the mutation controller.

## Complete mediation across node-drain execution routes

The legacy endpoint `POST /v1/node-drains/execute` cannot carry the EBA
execution bundle, consequence-admission inputs, or capability-fence claims used
by the governed EGE boundary.

Therefore, when either of these execution obligations is configured:

- `RequireEBAConformance == true`; or
- `RequireCapabilityFencing == true`;

Aegis rejects the legacy execute route **before** it claims replay/capability
state or calls the mutation controller:

```text
409 EGE_EXECUTION_REQUIRED
```

The caller must migrate the mutation to `POST /v1/ege/execute`, where the
configured obligations are enforced at the actual execution boundary. Route
choice is not allowed to select weaker governance.

This restriction is scoped to configured governed execution. When neither
EBA conformance nor capability fencing is required, the legacy route remains
available for its existing authenticated/replay-guarded compatibility path.

## Failure behavior

- missing bundle -> `403 EBA_CONFORMANCE_REQUIRED`
- invalid/tampered bundle -> `403 EBA_CONFORMANCE_BLOCKED`
- consequence policy rejection -> `403 CONSEQUENCE_ADMISSIBILITY_BLOCKED`
- controller is not called
- replay guard is not claimed before EBA validation or consequence admission

## Backward compatibility

When `RequireEBAConformance == false`, the existing `/v1/ege/execute`
contract behaves as before and the `eba` object is optional.

The legacy `/v1/node-drains/execute` route remains available only while no
EGE-only execution obligation is configured. Enabling EBA conformance or
capability fencing intentionally makes that legacy mutation shape incompatible
and returns `409 EGE_EXECUTION_REQUIRED` instead of silently omitting the
stronger checks.

This gives us a migration path:

```text
conformance harness
→ opt-in execution enforcement
→ production key configuration
→ measured adoption
→ only then consider stronger defaults
```


## Key generation and custody

A compatible durable Ed25519 key pair can be generated with OpenSSL:

```bash
openssl genpkey -algorithm ED25519 -out approval-private-key.pem
openssl pkey -in approval-private-key.pem -pubout -out approval-public-key.pem
```

The private file is PKCS#8 and can be loaded by approval-issuer code with:

```go
signer, err := ege.NewEd25519AuthorityPKCS8PEM(privatePEM)
```

The execution daemon receives only `approval-public-key.pem`.

Do **not** deploy `approval-private-key.pem` with the Aegis execution daemon.
The security boundary is deliberate:

```text
approval issuer
  holds private key
  → signs ApprovalAttestation

Aegis daemon
  holds public key only
  → verifies ApprovalAttestation
  → cannot mint approvals
```

The derived `key_id` is stable across process restarts because it is based on
the Ed25519 public-key SHA-256 fingerprint.


## Consequence boundary

After EBA validates evidence, assumptions, authority, and approvals, Aegis performs a separate deterministic consequence-admission check before claiming replay state or entering the mutation controller.

The first profile classifies Kubernetes node drain as an `operational_state_change` and binds the decision to a versioned policy, policy hash, evaluation time, and exact action-scope digest.

See [Consequence admissibility](consequence-admissibility.md).
