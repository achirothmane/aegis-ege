# Pinned trust root for live taint recovery principals

Status: executable trust-binding proof.

PR #169 established that live source-continuity recovery requires two distinct signatures. That is necessary but not sufficient if the caller may choose both public keys for each request.

This layer fixes the identities of the two recovery principals before any live recovery authorization is evaluated.

## Trust manifest

`TaintRecoveryTrustManifest` binds:

```text
version
trust_epoch
authority principal
authority key id
authority public key
witness principal
witness key id
witness public key
```

The manifest is normalized, canonicalized with RFC8785/JCS, and signed by a trusted recovery-trust signer.

Construction of `TaintRecoveryTrustRoot` requires:

```text
signed trust manifest
        +
trusted signer public key
        +
minimum accepted trust epoch
        ↓
verified pinned recovery principals
```

The two principals must have different names and different derived Ed25519 key identities. Public-key bytes must match the declared key IDs.

The trust epoch is constrained to the exact JSON integer profile and cannot fall below the relying-context floor supplied by the caller.

## Live recovery boundary

`TaintRecoveryRequest` no longer accepts:

```text
RecoveryAuthorityKey
RecoveryWitnessKey
```

as request-scoped trust inputs.

It accepts a verified:

```text
RecoveryTrust *TaintRecoveryTrustRoot
```

The live recovery order is now:

```text
verified recovery trust root
        ↓
joint authorization key IDs must equal pinned A/B identities
        ↓
verify both signatures with pinned public keys
        ↓
validate plan / cgroup / boot binding
        ↓
kernel source re-observation
        ↓
exact joint commitment
        ↓
epoch advance
        ↓
CLEAN advance last
```

A caller cannot make an otherwise valid two-signature authorization trusted merely by supplying two new public keys alongside it.

## Executable falsification

Unit tests prove:

1. the pinned A + B pair is accepted;
2. a valid authorization signed by A' + pinned B is rejected;
3. a valid authorization signed by pinned A + B' is rejected;
4. a trust-manifest epoch below the minimum floor is rejected;
5. a post-signature manifest modification is rejected;
6. a manifest signed by an unrelated trust signer is rejected;
7. one key cannot occupy both recovery-principal roles.

The privileged BPF-LSM recovery schedule adds the stronger live case:

```text
DIRTY > CLEAN
        +
authorization signed correctly by A' + B'
        +
verified trust root pins A + B
        ↓
DENY
        ↓
DIRTY unchanged
CLEAN unchanged
epoch unchanged
source enrollment unchanged
protected egress remains DENY
```

The same schedule then uses the pinned A + B authorization and continues through the existing pre-CLEAN crash/resume and post-CLEAN lost-reply reconciliation proofs.

The crash helper reconstructs the recovery trust root from the signed trust manifest, trusted signer public key, and minimum trust epoch. It no longer receives request-scoped recovery public keys.

## Relation to Genesis

This manifest is not intended to become an independent existential root.

Production should bind the recovery-trust signer public key and minimum accepted recovery trust epoch into the existing Genesis / relying-context trust configuration, or derive them from an equivalently protected higher-level root.

The repository proof establishes the recovery-side verification contract. Wiring the trust signer and epoch floor into a production Genesis bundle is a separate integration step.

## Claim boundary

This proves that live recovery is bound to pre-authorized cryptographic principal identities rather than two arbitrary keys chosen by the caller.

It does not prove that the two private keys are held by independent people, organizations, machines, accounts, or administrative domains. It also does not yet prove that the witness private key is absent from the Aegis runtime process.

Those are the next deployment/custody obligations. The next executable step is a remote recovery-witness service that holds B's private key outside the recovery controller and signs only authorizations admitted by witness-side policy.
