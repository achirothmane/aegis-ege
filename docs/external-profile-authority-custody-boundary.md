# External profile authority custody boundary

Status: executable two-phase provisioning proof.

## Objective

Remove the external recovery witness Profile Authority private key from the Aegis activation path.

Before this proof, CI generated the Profile Authority key inside the same provisioning process that created B and deployed the runtime. Genesis pinned the correct public identity, but the provisioning process still possessed the private signing key during activation.

The new contract is:

```text
PREPARE
  Aegis sees P public key only
  creates B identity, TLS material, policy, recovery trust
  emits exact unsigned ExternalRecoveryWitnessProfile
  emits prepared activation bundle
        |
        v
EXTERNAL PROFILE AUTHORITY P
  possesses P private key
  signs exact prepared profile
  emits SignedExternalRecoveryWitnessProfile
        |
        v
ACTIVATE
  no P private key
  verifies Genesis binding
  verifies P signature
  verifies exact prepared-profile equality
  verifies TLS / policy / B-key continuity
  only then performs Kubernetes writes
```

## Activation preflight

The activation command performs the complete cryptographic preflight before creating namespaces, service accounts, ConfigMaps, Secrets, Deployments, or Services.

Preflight requires:

```text
prepared bundle valid
        ↓
external SignedProfile present
        ↓
Genesis envelope exact-byte hash valid
        ↓
Profile signer == Genesis-pinned P
        ↓
Profile == exact prepared activation request
        ↓
required B identity matches
        ↓
profile/policy epochs satisfy Genesis floors
        ↓
TLS certificate + Genesis ServerName valid
        ↓
policy epoch/hash match
        ↓
B private key matches recovery trust manifest
        ↓
VERIFIED ACTIVATION PACKAGE
        ↓
Kubernetes mutation may begin
```

No external signature means no verified activation package.

## Offline authority tool

`cmd/aegis-profile-authority` is custody-side tooling.

It supports:

- `PROFILE_AUTHORITY_MODE=generate`: create P key material;
- `PROFILE_AUTHORITY_MODE=sign`: sign an externally prepared witness profile.

The runtime provisioner does not call this command and contains no call to `SignExternalRecoveryWitnessProfile`.

Possession and execution location of this tool do not themselves establish administrative independence. The security boundary is where the P private key is stored and who is authorized to use it.

## CI falsification

CI simulates the custody boundary in separate steps:

```text
create P custody material
        ↓
prepare with P public key only
        ↓
sign in separate authority step
        ↓
delete P private key
        ↓
assert P private key absent
        ↓
assert activation source contains no profile signing call
        ↓
activate
        ↓
remove Kubernetes admin credentials
        ↓
run live cross-control-plane recovery proof
```

The unit corpus also proves:

- prepared activation bundle does not contain P private key;
- missing SignedProfile is rejected;
- a profile signed by a non-Genesis authority is rejected;
- even a valid P signature cannot retarget the prepared activation to another endpoint;
- the correct external signature produces a verified activation package.

## Claim boundary

This PR proves:

```text
Aegis activation does not possess P private key
Aegis activation cannot self-sign ExternalRecoveryWitnessProfile
No external P signature => no Kubernetes provisioning mutation
SignedProfile cannot silently change the prepared activation request
```

This PR does not yet prove:

```text
P is held in a separate cloud account / organization
Aegis administrators cannot invoke P remotely
B private signing key is externally custodied
B signs through KMS/HSM instead of mounted private material
```

The next boundary after this proof is B custody: replace the mounted B private key with an external signing primitive whose key material cannot be exported into the Aegis runtime.
