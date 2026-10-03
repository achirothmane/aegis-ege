# External recovery witness signer custody boundary

Status: executable process/custody separation proof.

## Objective

Remove the B recovery-witness signing private key from both:

- Aegis prepare/activation;
- the B witness runtime process.

The B signing authority is represented only by the public key and key ID already pinned by the Recovery Trust Manifest and the signed external witness profile.

## Custody topology

```text
B Signer Custody
  owns raw B private key
  exposes HTTPS signing endpoint
  signs only approved domain-separated payloads
        |
        v
B Witness Runtime
  owns no B private key
  verifies authority + policy
  canonicalizes exact payload
  requests external signature
  verifies returned signature locally
  emits Joint / Receipt / Response only if verification succeeds
        |
        v
A
  verifies B signature using Genesis/Recovery-Trust-pinned public key
```

The permitted signing domains are exactly:

```text
aegis-ege/taint-recovery-joint/v1
aegis-ege/witness-recovery-receipt/v1
aegis-ege/taint-recovery-witness-response/v1
```

Unscoped arbitrary payloads are denied by the signer service.

## Prepare / activate boundary

The custody side creates:

- B private signing key;
- B public key;
- signer TLS certificate/private key;
- signer endpoint and TLS server name.

Only public B/signer material crosses into Aegis prepare:

```text
B public key
signer HTTPS endpoint
signer TLS CA certificate
signer TLS server name
```

The local copies of:

```text
B private signing key
signer TLS private key
```

are deleted after the custody signer service is installed and before Aegis prepare or activate runs.

The prepared activation bundle contains no B private signing key field or value.

## B runtime

`cmd/aegis-taint-recovery-witness` no longer reads `WITNESS_PRIVATE_KEY_PATH`.

It builds a `RemoteRecoveryWitnessSigner` from:

- Recovery Trust-pinned B public key;
- Recovery Trust-pinned B key ID;
- HTTPS signer endpoint;
- signer CA;
- signer TLS server name.

For every signature returned by custody, B verifies the signature locally against the pinned B public key before proceeding.

A bad, unavailable, wrong-key, or malformed signer therefore yields fail-closed behavior and no valid signed effect evidence.

## Executable falsification

The proof corpus includes:

- remote signer succeeds for each of the three approved signing domains;
- arbitrary unscoped signing payload is denied;
- a signer response carrying a signature under a different key is rejected;
- a signer implementation that returns an invalid signature causes the B witness handler to return service unavailable instead of emitting a recovery result;
- prepared activation bundle excludes the B private signing key;
- production B runtime and Aegis activation source contain no raw B-key path/reference.

## CI live proof

CI simulates custody as a separate process/deployment:

```text
generate B custody material
        ↓
install signer service with B private key
        ↓
delete local B private key + signer TLS private key
        ↓
Aegis prepare(public material only)
        ↓
external profile P signs exact profile
        ↓
delete P private key
        ↓
Aegis activate
        ↓
B runtime starts without B private key
        ↓
B requests all signatures from custody signer
        ↓
remove Kubernetes admin credentials
        ↓
cross-cluster recovery proof
        ↓
signed receipt verified by A
```

## Claim boundary

This PR proves:

```text
Aegis prepare does not generate or possess B private signing key
Aegis activation does not possess B private signing key
B witness runtime does not possess B private signing key
external signer failure or signature mismatch fails closed
B verifies every external signature before emitting it
```

This PR does not yet prove:

```text
B private key is non-exportable hardware material
custody is in a different cloud account or organization
Aegis administrators cannot administer the custody service
KMS/HSM authorization policy is independently governed
```

The next real boundary is therefore replacing the CI custody service with a true non-exportable KMS/HSM-backed signer while keeping the same B-side signer contract.
