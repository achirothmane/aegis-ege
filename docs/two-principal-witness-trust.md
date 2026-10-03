# Two-Principal Witness Trust Model

Status: executable trust-binding proof.

This model formalizes the case where the workload/Aegis operator and the external witness owner are different principals.

## Principals

```text
Principal A: workload owner/operator
  controls workload runtime
  controls workload credentials
  may control the workload repository and CI

Principal B: witness owner/operator
  controls witness administration
  controls witness-owner signing key
  controls witness runtime signing authority
```

Aegis must not accept a new witness endpoint or runtime signing key based on either principal acting alone.

## Trust manifest

`WitnessTrustManifest` binds:

```text
version
trust_epoch
workload_principal
witness_principal
witness HTTPS endpoint
witness runtime key id
witness runtime public key
```

The payload is canonicalized with RFC8785/JCS and signed by both roots:

```text
Principal A signature
        +
Principal B signature
        ↓
verified WitnessTrustManifest
        ↓
RemoteHeadStore
```

The trust epoch is bounded to the exact JSON integer profile and checked against a minimum accepted epoch so a previously valid trust manifest cannot be silently rolled back below the relying-context floor.

## Security consequence

A workload-side principal that controls Aegis configuration can propose a replacement witness, but cannot produce Principal B's signature over the new endpoint/key.

A witness-side principal can rotate its service/runtime key, but cannot make Aegis accept that new trust target without Principal A's signature.

Therefore:

```text
A alone -> cannot rotate B
B alone -> cannot rotate B as trusted by A
A + B  -> explicit trust transition
```

This is intentionally stronger than a single pinned public key stored in mutable runtime configuration.

## Executable falsification

The tests cover:

1. Jointly signed manifest is accepted.
2. Principal A changes the witness endpoint and re-signs only its side -> rejected.
3. Principal B changes the witness runtime key and re-signs only its side -> rejected.
4. Trust epoch below the relying-context floor -> rejected.
5. Runtime key substitution after signing -> rejected.
6. A verified manifest constructs a `RemoteHeadStore` bound to exactly the signed endpoint/key.

The existing External Witness Protocol tests separately prove signed head responses, nonce freshness, stale-CAS rejection, and forged-response rejection.

## Relation to Genesis

This manifest is not a new existential trust root.

Production should bind the Principal A root, Principal B root, and minimum accepted witness trust epoch into the existing Genesis / relying-context / anti-rollback machinery. The two-principal manifest defines the executable authorization relation for witness identity changes.

## Claim boundary

The repository can prove that **one cryptographic principal alone is insufficient** to authorize witness replacement.

The repository cannot prove that two private keys are operated by two independent humans or organizations when both keys are generated and exercised by the same CI test harness.

The stronger organizational claim requires deployment where Principal B's signing key and witness administration are actually outside Principal A's account, repository, CI, and credential domain.
