# TPM-backed non-exportable recovery witness signer

Status: production TPM signing path plus executable TPM-command proof.

## Objective

Move the B recovery-witness signing authority from a software private key into a TPM 2.0 signing object.

The production signer uses an ECC P-256 primary signing key created by the TPM with:

```text
Sign
FixedTPM
FixedParent
SensitiveDataOrigin
UserWithAuth
```

The TPM creates the sensitive key material internally. Aegis receives only the public key and signatures.

## Algorithm transition

Historical recovery trust manifests remain byte-compatible and default to Ed25519 when no witness signature algorithm is present.

A witness may now explicitly declare:

```text
witness_signature_algorithm = ecdsa-p256-sha256
```

Only the B witness side is algorithm-agile. Recovery authority A and the trust-manifest signer remain Ed25519 in this proof.

ECDSA public identity is encoded as PKIX SubjectPublicKeyInfo and receives a distinct key ID namespace:

```text
ecdsa-p256:<truncated SHA-256 of SPKI>
```

## TPM signer

`TPMRecoveryWitnessSigner`:

1. opens an existing TPM transport;
2. creates an unrestricted ECC-P256 Primary signing object under the Owner hierarchy;
3. never imports caller-provided private signing material;
4. hashes the exact domain-separated recovery payload with SHA-256;
5. executes TPM2_Sign with ECDSA/SHA-256;
6. converts the TPM R/S signature to ASN.1 DER;
7. verifies the returned signature locally against the pinned public key before returning it.

The same signing-domain allowlist remains in force:

```text
aegis-ege/taint-recovery-joint/v1
aegis-ege/witness-recovery-receipt/v1
aegis-ege/taint-recovery-witness-response/v1
```

## Production command

`cmd/aegis-tpm-recovery-witness-signer` defaults to:

```text
/dev/tpmrm0
```

and has two modes.

`identity` emits only:

- signature algorithm;
- public key;
- key ID.

`serve` recreates the same TPM Primary identity and refuses startup when its live key ID differs from the expected pinned key ID.

Optional TPM Owner-hierarchy and signing-object authorization are read from files and are never emitted as public identity material.

## Executable proof

The TPM simulator proof uses the exact production signer implementation and proves:

```text
TPM seed A
   ↓
CreatePrimary(template)
   ↓
B identity K1
   ↓
Joint + Receipt + Response signed through TPM
   ↓
all signatures verified by A

restart TPM seed A
   ↓
same template
   ↓
same B identity K1

TPM seed B
   ↓
same template
   ↓
different B identity K2
   ↓
existing Recovery Trust rejects K2
```

The proof is required to run without SKIP in CI.

## Compatibility

The existing Ed25519 custody path remains active in KinD CI. This demonstrates that adding TPM ECDSA support does not weaken or silently migrate existing recovery trust.

## Claim boundary

This PR proves:

```text
the production signer can keep B private signing material inside a TPM command boundary
TPM ECDSA signatures can drive the existing Joint / Receipt / Response protocol
same TPM hierarchy identity is stable across signer restart
different TPM identity cannot substitute for the trusted B signer
old Ed25519 trust manifests remain compatible
```

The CI proof uses the go-tpm simulator. It therefore does not prove that GitHub-hosted CI is backed by a physical TPM or that an external administrator cannot inspect simulator state.

A physical-device deployment must still execute the same production command against a real `/dev/tpmrm0` and bind device custody/administration independently before claiming physical hardware custody.
