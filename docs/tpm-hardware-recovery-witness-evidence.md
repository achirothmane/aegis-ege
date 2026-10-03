# TPM hardware recovery-witness evidence

Status: **hardware proof harness; hardware execution not yet claimed**

## Objective

Extend the TPM-backed B signer proof beyond simulator semantics without allowing a simulator or ordinary file to silently satisfy the hardware gate.

The hardware proof path is deliberately separate from normal CI.

## Preconditions

The proof command requires:

```text
TPM_DEVICE_PATH=/dev/tpmrm0
```

and the path must be a Linux character device.

It also requires two identities commissioned in advance:

```text
EXPECTED_TPM_EK_SHA256_PATH
EXPECTED_WITNESS_KEY_ID_PATH
```

The first pins the TPM endorsement-key SPKI identity. The second pins the deterministic TPM-backed B signer identity.

A different TPM, cleared hierarchy seed, or substituted B key must fail before a new hardware receipt is issued.

## Evidence receipt

`WITNESS_TPM_SIGNER_MODE=hardware-proof` captures:

- kernel TPM device path and mode;
- TPM manufacturer and vendor info;
- firmware major/minor;
- EK SPKI SHA-256;
- EK certificate SHA-256 when available;
- B witness algorithm and KeyID;
- the live TPM public area for B;
- SHA-256 of that public area;
- TPM Name of B;
- a fresh 256-bit challenge;
- capture time;
- TPM-produced ECDSA signature;
- receipt digest.

The signer public area is not trusted merely because the receipt says it has safe attributes.

Verification reconstructs the expected TPM public area from the pinned B SPKI and the fixed signer contract:

```text
ECC P-256
SHA-256 NameAlg
ECDSA/SHA-256
Sign
FixedTPM
FixedParent
SensitiveDataOrigin
UserWithAuth
not Decrypt
```

The reconstructed public-area digest and TPM Name must match the live values read with `TPM2_ReadPublic`.

## No simulator fallback

`CaptureTPMHardwareIdentityEvidence` rejects any path that is not a character device before opening it as a TPM.

CI contains an explicit falsification case using a regular file named like a fallback source. It must be rejected.

This test proves the gate semantics only. It does not turn GitHub-hosted CI into a hardware TPM environment.

## Hardware workflow

`.github/workflows/tpm-hardware-recovery-witness-proof.yml` is `workflow_dispatch` only and requires runner labels:

```text
self-hosted
linux
aegis-tpm-hardware
```

There is no GitHub-hosted fallback.

The runner must already contain the pinned EK digest and B KeyID under the configured machine-local paths.

A successful run produces:

```text
tpm-recovery-witness-hardware-receipt.json
tpm-recovery-witness-hardware-receipt.json.sha256
```

as a retained workflow artifact.

## Claim boundary

Merging the harness proves:

```text
hardware-only gate exists
ordinary file/socket fallback is denied
receipt binds EK + firmware + B public area + fresh challenge
B signature is verified against the pinned ECDSA P-256 key
substituted receipt fields fail verification
```

It does **not** prove that a physical TPM was used.

The stronger statement becomes admissible only after the hardware-only workflow executes successfully on an independently identified real machine. A Linux TPM character device can also represent a virtual TPM, so physical-device provenance must ultimately be corroborated by machine inventory / custody evidence outside the TPM command stream itself.
