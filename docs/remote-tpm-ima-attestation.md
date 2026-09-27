# Remote TPM + IMA Attestation v1

This layer upgrades the BPF bootstrap chain from local cryptographic attestation to a remotely verifiable hardware-rooted attestation protocol.

The governing invariant is:

> A remote verifier must not authorize a protected workload from a local bootstrap receipt alone. It must verify a fresh TPM quote from an enrolled TPM identity, replay the measured boot evidence when required, replay the IMA SHA-256 measurement log into PCR 10, and verify that the signed BPF artifact was measured by IMA when policy requires it.

## Trust chain

```text
Trusted EK identity
      |
      v
Credential activation
proves AK + EK coexist in TPM
      |
      v
Enrolled AK
      |
remote fresh challenge
      |
      v
TPM Quote
  |      |
  |      +-- SHA-256 PCR bank
  |
  +-- quote nonce binds:
        challenge
        SignedBootstrapReceipt
        IMA SHA-256 log
        TCG platform event log
      |
      v
Remote verifier
  |
  +-- AK quote signature + PCR coverage
  +-- platform event-log replay
  +-- IMA PCR10 replay
  +-- BPF artifact present in IMA log
  +-- enrolled bootstrap-attestor signature
      |
      v
Signed ALLOW / BLOCK decision
```

## Phase 1 — TPM enrollment

Enrollment is deliberately separate from normal attestation.

The host creates or loads a persistent TPM Attestation Key (AK) and sends:

```text
device_id
AK creation parameters
EK public key
optional EK certificate
bootstrap attestor public key
TPM manufacturer / firmware metadata
```

The verifier accepts the EK only through an explicit trust source:

- exact EK SPKI SHA-256 inventory allowlist; or
- an EK certificate chaining to verifier-configured roots.

The verifier then generates a TPM credential-activation challenge.

The host can recover the activation secret only when the AK and selected EK are present on the same TPM. The verifier stores the successfully activated AK as the enrolled hardware identity.

The bootstrap-attestor public key is enrolled at the same time, so a future bootstrap receipt cannot silently substitute a new host signing key.

## Phase 2 — Fresh remote challenge

The verifier creates a short-lived challenge containing:

```text
challenge_id
device_id
random nonce
PCR bank = SHA-256
PCR selection = 0..23
issued_at
expires_at
```

The random challenge is not copied directly into TPM extraData.

Instead Aegis derives the quote nonce from:

```text
domain_separator
+ canonical challenge
+ SignedBootstrapReceipt digest
+ IMA SHA-256 measurement-log digest
+ TCG platform-event-log digest
```

The resulting SHA-256 value is truncated to 20 bytes for broad TPM compatibility.

Changing the receipt or either measurement log therefore changes the TPM quote nonce.

## Phase 3 — Host collection

The host:

1. loads the enrolled AK from its TPM;
2. reads `ascii_runtime_measurements_sha256`;
3. replays PCR 10 locally;
4. reads the TCG platform event log;
5. reads the SHA-256 PCR bank;
6. verifies that the current PCR 10 equals the local IMA replay;
7. derives the bound quote nonce;
8. requests a TPM quote over the requested PCRs;
9. locally verifies the quote before emitting evidence.

If IMA changes while the snapshot is being collected, the collector retries rather than emitting a mixed-time snapshot.

Default IMA path:

```text
/sys/kernel/security/integrity/ima/ascii_runtime_measurements_sha256
```

## IMA PCR 10 replay

For each PCR-10 record in the SHA-256 IMA measurement list:

```text
PCR_next = SHA256(PCR_previous || template_digest)
```

with a 32-byte zero initial PCR value.

The verifier compares the replayed value to the TPM-quoted SHA-256 PCR 10.

A malformed log, missing PCR-10 records, or replay mismatch fails closed.

## BPF artifact measurement requirement

Remote policy may require the exact signed BPF artifact digest from the bootstrap receipt to appear in the verified IMA measurement log.

That check is separate from the bootstrap manifest signature:

```text
release signer says:
  "this BPF artifact is authorized"

IMA + TPM say:
  "this artifact digest was measured on this boot"
```

Both can be required before ALLOW.

This requires an IMA policy that actually measures the BPF object before it is loaded.

## Platform event log

When enabled, the verifier parses the TCG platform event log and replays it against the quoted PCR values.

This verifies that the supplied event log is consistent with the TPM quote rather than trusting an arbitrary userspace log blob.

## Bootstrap receipt binding

The remote verifier also verifies the local `SignedBootstrapReceipt` using the bootstrap-attestor public key stored during TPM enrollment.

This prevents a valid TPM quote from laundering an unsigned or attacker-substituted local bootstrap receipt.

The quote nonce then binds that verified receipt to the same fresh TPM attestation transaction.

## Signed remote decision

The verifier emits a signed decision:

```text
version
decision_id
challenge_id
device_id
ALLOW | BLOCK
reason_codes
bootstrap_digest
AK_public_digest
PCR10_digest
IMA_replay_digest
verified_at
verifier_id
```

The verifier signs the decision with its own Ed25519 authority key.

Deployment should consume this signed decision, not infer trust from the mere existence of attestation files.

## File-protocol workflow

The v1 implementation deliberately uses durable JSON protocol messages so the security semantics are independent of transport.

### 1. Host: create TPM enrollment request

```bash
go run ./cmd/aegis-tpm-enroll-request \
  -device node-01 \
  -ak /var/lib/aegis/attestation.ak \
  -bootstrap-attestor-pub host-attestation.pub \
  -out tpm-enrollment-request.json
```

### 2. Verifier: begin credential activation

```bash
go run ./cmd/aegis-tpm-enroll-begin \
  -request tpm-enrollment-request.json \
  -allow-ek-spki sha256:<inventory-fingerprint> \
  -challenge-out tpm-enrollment-challenge.json \
  -pending-out tpm-enrollment-pending.json
```

The pending file contains the activation secret and is verifier-private.

### 3. Host: activate challenge in TPM

```bash
go run ./cmd/aegis-tpm-enroll-activate \
  -ak /var/lib/aegis/attestation.ak \
  -challenge tpm-enrollment-challenge.json \
  -out tpm-enrollment-proof.json
```

### 4. Verifier: complete enrollment

```bash
go run ./cmd/aegis-tpm-enroll-complete \
  -pending tpm-enrollment-pending.json \
  -proof tpm-enrollment-proof.json \
  -out enrolled-tpm-identity.json
```

### 5. Verifier: issue fresh attestation challenge

```bash
go run ./cmd/aegis-attest-challenge \
  -device node-01 \
  -out remote-attestation-challenge.json
```

### 6. Host: collect hardware evidence

```bash
sudo go run ./cmd/aegis-attest-collect \
  -ak /var/lib/aegis/attestation.ak \
  -challenge remote-attestation-challenge.json \
  -bootstrap-receipt aegis-bpf-bootstrap.receipt.json \
  -out remote-attestation-evidence.json
```

### 7. Verifier: decide

```bash
go run ./cmd/aegis-attest-verify \
  -identity enrolled-tpm-identity.json \
  -challenge remote-attestation-challenge.json \
  -evidence remote-attestation-evidence.json \
  -verifier-key remote-verifier.key \
  -verifier-id prod-attestation-authority \
  -out remote-attestation-decision.json
```

Default verifier policy requires:

```text
kernel lockdown = integrity or confidentiality
TCG platform event-log replay
IMA PCR10 replay
BPF artifact digest present in IMA log
```

## TPM simulator test

CI includes a Microsoft TPM2 simulator path that exercises real TPM commands rather than mocking quote signatures.

The test performs:

```text
create AK
obtain EK
credential activation
enrollment completion
extend SHA-256 PCR10
construct matching IMA record
fresh challenge
real TPM quote
local quote verification
remote verifier quote verification
IMA PCR10 replay
BPF artifact measurement check
ALLOW
```

This gives the protocol an executable hardware-model test even when GitHub runners do not expose a physical TPM.

## Current trust boundary

Implemented:

```text
EK trust policy
AK credential activation
fresh challenge / replay protection
TPM SHA-256 PCR quote
TCG platform event-log replay
IMA SHA-256 PCR10 replay
BPF artifact measurement requirement
bootstrap-attestor key enrollment
signed remote ALLOW/BLOCK decision
TPM2 simulator verification
```

Not yet implemented:

```text
automatic TPM manufacturer EK root distribution
OCSP / CRL checking for EK certificate chains
network HTTP/gRPC transport
durable verifier database for enrollment/challenge state
one-time challenge consumption store
remote decision integration into workload admission
confidential-computing TEE attestation
runtime memory integrity
IMA policy installation / enforcement automation
kexec measurement-log continuity automation
```

## Security limitations

TPM + IMA attest measured state; they do not prove that arbitrary runtime memory remains uncompromised after measurement.

IMA coverage is only as strong as the active IMA policy. Requiring the BPF artifact in the log fails closed when that policy does not measure it.

The file protocol is intended to stabilize cryptographic semantics first. Production deployment should place the same messages behind authenticated transport and durable verifier-side state with one-time challenge consumption.

## Governing invariant

> A remote ALLOW requires a fresh quote from the enrolled TPM AK, a bootstrap receipt signed by the bootstrap-attestor key enrolled with that TPM identity, consistent quoted PCRs, required event-log replay, required IMA PCR10 replay, and all configured policy gates.
