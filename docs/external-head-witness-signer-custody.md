# External-head witness signer custody boundary

Status: executable process/custody separation proof.

## Objective

The live external-head witness service must not own the private key that signs:

- governed head observations;
- governed head advances;
- quorum-policy observations;
- quorum-policy transitions.

The witness runtime owns state/policy enforcement. A separate custody process owns signing authority.

```text
External-head signer custody
  owns private signing key
  has no Kubernetes service-account token
        |
        | HTTPS scoped signing API
        v
External-head witness runtime
  owns governed witness state access
  owns no signing private key
  verifies signer public identity
  canonicalizes exact protocol statements
        |
        v
RemoteHeadStore clients
  verify every response using pinned public key
```

## Allowed signing surface

The signer contract accepts only exact protocol statements for:

```text
HEAD:
  load
  advance
  rotation-observe

POLICY:
  policy-current
  policy-transition
```

The signer parses the exact statement before signing and requires:

- the external-witness protocol version;
- the exact requested operation;
- the pinned witness key ID;
- a non-empty freshness nonce;
- valid head identity/CAS generation for head statements;
- a valid quorum policy state for policy statements.

Arbitrary JSON, operation substitution, kind substitution, or malformed protocol statements are denied.

## Runtime boundary

`cmd/aegis-external-head-witness` receives only:

- signer public key;
- signer HTTPS endpoint;
- signer TLS CA;
- signer TLS server name;
- governed witness policy;
- witness runtime TLS material.

It does not read the external-head signing private key.

The custody deployment has:

```text
automountServiceAccountToken = false
```

and therefore has no Kubernetes API credential by default.

## Activation sequence

```text
generate signer custody material
        ↓
install custody signer service
        ↓
delete local signing private key
delete local signer TLS private key
        ↓
Aegis activation receives public material only
        ↓
external-head witness runtime starts
        ↓
runtime requests scoped signatures over HTTPS
        ↓
client verifies returned signatures
```

## Falsification

The proof corpus includes:

- valid head statement signing;
- valid quorum-policy statement signing;
- operation/payload mismatch rejection;
- arbitrary payload rejection;
- signing-kind substitution rejection;
- remote signer response under the wrong key rejection;
- custody signer outage causes the governed witness handler to return service unavailable rather than emit a signed response;
- CI source gate rejects any raw external-head signer private-key path in the witness runtime or Aegis activation;
- local copies of signer private material are removed before activation;
- live KinD capability-root proof continues through the remote signer path after provisioning authority removal.

## Claim boundary

This proves:

```text
external-head witness runtime
  !=
external-head signing-key custodian
```

and that signing is restricted to the governed external-witness protocol.

It does not yet prove:

- non-exportable HSM/KMS key material;
- a different cloud account or organization for signer custody;
- independently governed custody administrators;
- multi-region signer availability;
- threshold signing for the witness key itself.

Those are later custody/deployment boundaries.
