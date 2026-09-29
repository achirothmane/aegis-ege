# Production Genesis Bootstrap v2

Mutation-capable Aegis-EGE startup is fail-closed behind the Level -1 Genesis gate.

The production path is:

```text
Level -2 DoctrineManifest
  |
  +-- independent Doctrine Authority signature
  +-- doctrine epoch rollback fence
  |
  v
GenesisManifest
  |
  +-- exact doctrine ID / epoch / manifest-hash binding
  +-- RFC8785/JCS + Ed25519 authenticity
  +-- running executable SHA-256
  +-- relying-context manifest/device/challenge pin
  +-- signed TPM/IMA remote ALLOW
  +-- current-boot-bound signed BPF bootstrap receipt
  +-- signed revocation list / epoch floors
  +-- signed semantic build provenance
  +-- typed proof verification records
  +-- spec, threat, policy, materials and SBOM digests
  |
  v
easl.Bootstrap
  |
  +-- GENESIS_LOCKED  -> no EASL Runtime -> mutation daemon startup fails
  |
  '-- BOOTSTRAP_READY -> EASL Runtime -> Aegis-EGE may expose mutation paths
```

## Daemon requirements

When `-enable-mutations` is set, `state-latchd` also requires:

```text
-genesis-manifest <path>
-genesis-verification-bundle <path>
-genesis-minimum-epoch <n>              # default 1
-genesis-minimum-doctrine-epoch <n>      # default 1
-genesis-required-conformance <C0..C4>  # default C3
```

Read-only startup does not require Genesis.

The implementation digest is not supplied by a flag. Aegis hashes the running
executable returned by `os.Executable()` and requires that digest to equal
`implementation.implementation_digest` in the manifest.

The Linux production path also reads the current boot identity from
`/proc/sys/kernel/random/boot_id` and requires the remotely bound bootstrap
receipt to refer to that exact boot.

Bundle v2 additionally carries a relying-context pin for the exact Genesis
manifest payload, enrolled device identity, and current attestation challenge.

## Verification bundle

Relative paths are resolved relative to the bundle JSON.

```json
{
  "version": "aegis.ege/genesis-verification-bundle/v2",
  "assurance_profile": "aegis.ege/genesis-assurance/v2",
  "relying_context": {
    "expected_manifest_payload_hash": "sha256:<manifest-payload>",
    "expected_device_id": "node-01",
    "expected_challenge_id": "<current-challenge-id>"
  },
  "doctrine_manifest": "doctrine/assumption-decay-doctrine.md",
  "signed_doctrine_authority_statement": "doctrine/authority-statement.json",
  "doctrine_authority_public_key": "keys/doctrine-authority.pub",
  "manifest_signer_public_key": "keys/genesis-manifest.pub",
  "remote_attestation_decision": "attestation/decision.json",
  "remote_attestation_verifier_public_key": "keys/remote-verifier.pub",
  "bootstrap_receipt": "bootstrap/receipt.json",
  "bootstrap_attestor_public_key": "keys/bootstrap-attestor.pub",
  "signed_revocation_list": "trust/revocations.json",
  "revocation_authority_public_key": "keys/revocation-authority.pub",
  "max_attestation_age_seconds": 120,
  "artifacts": {
    "specification": "genesis/spec.tla",
    "invariant_set": "genesis/invariants.json",
    "assumption_set": "genesis/assumptions.json",
    "forbidden_state_set": "genesis/forbidden-states.json",
    "tau_bounds": "genesis/tau-bounds.json",
    "proof_scope": "genesis/proof-scope.json",
    "threat_model": "genesis/threat-model.json",
    "capability_envelope": "genesis/capability-envelope.json",
    "attestation_policy": "genesis/attestation-policy.json",
    "nonce_policy": "genesis/nonce-policy.json",
    "enforcement_policy": "genesis/enforcement-policy.json",
    "refinement_mapping": "genesis/refinement-mapping.json",
    "executable_contract": "genesis/executable-contract.json",
    "build_provenance": "supply-chain/signed-provenance.json",
    "materials": "supply-chain/materials.json",
    "sbom": "supply-chain/sbom.json",
    "approval_policy": "genesis/approval-policy.json"
  },
  "proof_artifact_paths": [
    "proofs/genesis-proof-verification-record.json"
  ]
}
```

The production profile requires `supply_chain.build_provenance_ref` and every
entry in `verification.proof_artifacts` to be `sha256:<hex>` digests.

Those digests are no longer credited as semantic assurance by themselves.
Build provenance must be a signed `aegis.ege/build-provenance/v1` statement
whose builder, source revision, subject binary, materials, SBOM and build time
match the manifest and current executable. Each proof artifact must be a typed
`aegis.ege/proof-verification-record/v1` record whose PASS result, spec,
proof scope, verification mode, toolchain and model bounds match the manifest.

The proof record is a bound tool-result record. It does not independently
re-run TLC/TLAPS or establish formal implementation refinement. C4 is therefore
unsupported by this production profile and is rejected fail-closed.


## Level -2 doctrine authority

Genesis does not self-certify the doctrine from which its authority originates.

The production bundle therefore carries three independent inputs:

```text
DoctrineManifest
SignedDoctrineAuthorityStatement
DoctrineAuthorityPublicKey
```

The authority statement binds:

```text
doctrine_id
doctrine_epoch
doctrine_manifest_hash
issued_at
expires_at
```

and is signed with a dedicated Ed25519 doctrine-authority key. The production
verifier hashes the actual doctrine file, verifies the authority signature and
validity window, and requires the Genesis `doctrine` object to match the
statement exactly.

`state-latchd` also applies a minimum doctrine epoch. The signed revocation
list may raise that floor through `minimum_accepted_doctrine_epoch`; the
effective floor is the maximum of the operator/persisted floor and the signed
revocation floor.

This enforces:

```text
NO_GENESIS_WITHOUT_VALID_DOCTRINE
NO_BOOTSTRAP_WITHOUT_VALID_GENESIS
```

## Authenticity

The manifest signature uses:

```text
canonicalization = RFC8785
signature_scope  = MANIFEST_EXCLUDING_AUTHENTICITY
signature        = Ed25519(canonical manifest payload)
signed_payload_hash = SHA256(canonical manifest payload)
```

The trusted manifest-signing public key comes from the verification bundle.

RFC8785 canonicalization is implemented with the JCS library and the production
profile rejects Genesis integer fields above the exact JSON integer range.

## Trust root and attestation

For v1, `trust_root_ref` is the key id of the configured remote-attestation
verifier public key.

A production ALLOW must:

- have a valid remote-verifier Ed25519 signature;
- name the exact relying-context device and challenge;
- be fresh within `max_attestation_age_seconds`;
- bind the supplied signed BPF bootstrap receipt;
- bind a bootstrap receipt from the current live Linux boot;
- use a bootstrap receipt that is itself fresh within the configured age bound;
- carry the signed assurance results:
  - `TPM_QUOTE_VERIFIED`
  - `PLATFORM_EVENT_LOG_VERIFIED`
  - `BPF_ARTIFACT_IMA_MEASURED`
  - `IMA_PCR10_REPLAY_VERIFIED`

The bootstrap receipt must itself verify against the configured enrolled
bootstrap-attestor public key.

## Revocation

The manifest `revocation_ref` is the SHA-256 digest of the canonical signed
revocation-list artifact.

A revocation list can raise:

```text
minimum_accepted_genesis_epoch
minimum_trust_root_epoch
```

and revoke:

```text
manifest revocation ids
manifest signer key ids
trust root refs
```

A manifest revocation id deliberately excludes `revocation_ref` from its
identity before hashing. This avoids the circular dependency that would occur
if a revocation list contained a hash of a manifest which itself hashes that
same revocation list.

## Default-deny evidence

The v1 external check requires the remotely bound bootstrap receipt to attest:

```text
aegis_connect4
aegis_connect6
aegis_capsules
aegis_fences
kernel lockdown = integrity | confidentiality
```

This is bootstrap-time evidence of the enforcement substrate. It is not a claim
that TPM/IMA proves arbitrary future runtime memory integrity. Runtime Trust
Lease / continuous revalidation remains responsible for detecting and fencing
post-bootstrap trust loss.

## Assurance claim boundary

The complete current obligation matrix is
[Genesis Assurance Profile v2](genesis-assurance-v2.md).

Important boundaries:

- a matching file digest establishes artifact identity, not semantic proof;
- the signed provenance statement validates declared builder/source/binary
  relations but does not reproduce the build;
- proof verification records validate the recorded tool-result relation but do
  not prove implementation refinement;
- the current-boot check prevents a prior-boot bootstrap receipt from satisfying
  the current process, but it is not persistent rollback protection;
- open Genesis lineage/TPM-NV work (#64/#65) is not merged or credited here;
- ordinary unit/CI fixtures do not imply that a physical TPM deployment was
  exercised.

Bundle v1 is not accepted for mutation-capable v2 bootstrap. Operators must
provision a v2 bundle with the exact current relying context.

## Fail-closed rule

No missing field or missing artifact is treated as optional in mutation mode.

```text
any Genesis verification failure
    -> GENESIS_LOCKED
    -> no EASL Runtime
    -> state-latchd mutation startup aborts
```
