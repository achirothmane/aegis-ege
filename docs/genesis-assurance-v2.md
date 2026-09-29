# Genesis Assurance Profile v2 — Obligation Matrix

Profile: `aegis.ege/genesis-assurance/v2`  
Bundle: `aegis.ege/genesis-verification-bundle/v2`

This matrix is the claim boundary for mutation-capable Aegis bootstrap.

A green bootstrap means only the obligations marked **verified** below were
established by the current relying path. It does not upgrade identity checks
into semantic proof and does not imply hardware deployment that was not
exercised.

| Obligation | Current evidence | Verification | Claim boundary |
|---|---|---|---|
| Exact Genesis manifest | manifest Ed25519 signature + relying-context payload-hash pin | **Verified** | A different validly signed manifest is rejected unless the relying context is deliberately reprovisioned. |
| Doctrine identity/current epoch | signed doctrine authority statement + file digest + epoch floors | **Verified** | Does not make doctrine self-authorizing. |
| Running executable subject | SHA-256 of `os.Executable()` | **Verified** | Exact running executable only. |
| Build provenance issuer | signed provenance statement using the already trusted manifest authority | **Verified** | No new provenance trust root is introduced. |
| Builder/source/binary/material/SBOM provenance semantics | typed signed provenance fields compared with manifest and running executable | **Verified** | Validates the declared relation; it does not reproduce the build. |
| Remote verifier identity | configured Ed25519 verifier key | **Verified** | Trust anchor remains deployment-configured. |
| Relying device | signed remote decision device id vs bundle relying context | **Verified** | Device label is the enrolled remote-attestation identity, not a universal physical-host identity claim. |
| Relying challenge | signed remote decision challenge id vs bundle relying context | **Verified** | The Genesis consumer checks the exact expected challenge id; TPM quote semantics remain owned by the remote verifier. |
| Current boot | signed bootstrap receipt boot hash vs live `/proc/sys/kernel/random/boot_id` hash | **Verified on Linux production path** | Prevents a prior-boot receipt from satisfying the current process. It is not a persistent anti-rollback counter. |
| Attestation freshness | remote decision and bootstrap-receipt age windows | **Verified** | Bounded by `max_attestation_age_seconds`; not continuous runtime trust. |
| Revocation freshness/floors | signed revocation list validity + epoch/trust floors + revoked IDs | **Verified** | Persistent rollback continuity beyond those supplied floors remains separate L14 work. |
| Bootstrap default-deny evidence | signed receipt programs/maps + lockdown mode | **Verified as bootstrap evidence** | Does not prove arbitrary future runtime memory integrity. |
| Proof artifact identity | manifest-bound SHA-256 of each proof verification record | **Verified** | Identity only. |
| Proof record semantics | typed record requires PASS, exact spec/proof-scope/mode/toolchain/model-bounds, non-future checked time | **Verified as a recorded tool-result relation** | Does not re-run TLC/TLAPS and is not a proof that the implementation refines the model. |
| Refinement mapping/executable-contract identity | exact file digests | **Verified** | Artifact binding only. |
| Formal implementation refinement / verified compilation | none in this profile | **Unsupported / denied** | C4 is rejected fail-closed. |
| Physical TPM deployment | not established by ordinary unit/CI fixture tests | **Not claimed** | The separate TPM simulator path exercises TPM protocol mechanics; a real physical deployment requires its own evidence. |
| Persistent Genesis lineage / TPM NV continuity | open work #64/#65, not merged into this profile | **Not credited** | C08 does not merge or claim L14 continuity. |

## Relying context

Bundle v2 contains:

```text
expected_manifest_payload_hash
expected_device_id
expected_challenge_id
```

At startup the Linux production path also hashes the current boot ID directly
from `/proc/sys/kernel/random/boot_id`.

These values are not inferred from the manifest being verified. They are
relying-deployment inputs. Replacing the manifest, host report, device, or
challenge without reprovisioning the relying context therefore fails closed.

## Provenance statement

The build-provenance artifact is no longer accepted as an arbitrary file whose
only property is a matching digest. It is a signed
`aegis.ege/build-provenance/v1` statement binding:

```text
builder_identity
source_revision
subject_implementation_digest
materials_hash
sbom_hash
built_at
issued_at
expires_at
```

The statement is signed by the already trusted Genesis manifest authority. Its
subject digest must match both the Genesis implementation digest and the
currently running executable.

## Proof verification record

Each current proof artifact is a typed
`aegis.ege/proof-verification-record/v1` record. The verifier checks the
recorded result and its exact relation to the manifest.

This is intentionally weaker than independently replaying a theorem prover,
model checker, verified compiler, or full implementation-refinement proof.
Accordingly, the production profile rejects C4.

## Migration

Bundle v1 is not silently promoted to v2. A mutation-capable deployment must
regenerate its bundle with the v2 assurance profile and current relying context.

Historical v1 manifests/bundles may remain as audit evidence. They do not carry
the C08 current-subject or semantic-provenance guarantee.

## Hypothesis disposition

The earlier cross-host/prior-host reuse concern was a **hypothesis**, not a
previously reproduced exploit. C08 adds a full-path negative test in which a
valid signed report from one boot is presented to a different current boot.
The v2 relying path rejects it.

That test demonstrates the new v2 property; it does not retroactively assert
that a real production host was exploited.
