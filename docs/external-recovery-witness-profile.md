# External recovery witness profile and signed receipts

Status: executable witness identity and policy-continuity proof.

The remote recovery witness path already proves that Witness B can run in a separate process and Kubernetes control plane, with a private key unavailable to the recovery-controller runtime.

That is not sufficient if configuration can silently replace the witness endpoint, TLS identity, policy, or policy version while continuing to use an otherwise valid witness signing key.

This layer pins those coordinates explicitly.

## ExternalRecoveryWitnessProfile

A signed profile binds:

```text
profile version
profile epoch
witness_id
witness_key_id
endpoint
TLS trust-anchor SHA-256
policy epoch
policy hash
```

The profile is signed by the recovery trust signer and verified against the existing `TaintRecoveryTrustRoot`.

The witness key ID inside the profile must equal the B identity already pinned by the recovery trust root.

Verification also takes caller-supplied minimum profile and policy epochs:

```text
profile_epoch < minimum_profile_epoch
        => DENY

policy_epoch < minimum_policy_epoch
        => DENY
```

Those minimums are the anti-rollback relying-context inputs that production should bind into Genesis or an equivalently protected higher-level state.

## TLS binding

The profile pins a SHA-256 digest of the exact PEM trust anchor distributed to the controller.

The profiled client requires:

```text
requested endpoint == signed profile endpoint
TLS trust-anchor hash == signed profile TLS hash
```

and the HTTP client performs normal TLS verification using that same trust anchor.

The witness process independently hashes its mounted TLS certificate at startup and refuses to run if it differs from the signed profile.

Thus a configuration-only endpoint or certificate substitution cannot silently inherit B's recovery authority.

## Policy binding

The profiled witness policy must expose:

```text
RecoveryWitnessPolicyEpoch()
RecoveryWitnessPolicyHash()
```

The handler refuses to start unless both values equal the signed external profile.

The CI static policy computes its hash from canonical RFC8785/JCS JSON including its policy epoch and recovery coordinates.

Therefore this state is invalid:

```text
signed profile says:
  policy epoch = N
  policy hash  = X

loaded policy says:
  epoch = N+1 or hash = Y
        |
        v
signer startup DENY
```

## WitnessRecoveryReceipt

For every admitted recovery request in profiled mode, B returns a signed receipt binding:

```text
witness_id
witness_key_id
profile_epoch
endpoint
TLS trust-anchor hash
policy_epoch
policy_hash
authorization_id
exact joint commitment hash
fresh request nonce
evaluated_at
```

The receipt is signed by B's pinned witness key.

The controller verifies the receipt against the already verified external profile and rejects any mismatch before treating the remote co-signature as admissible external evidence.

A valid B signature alone is therefore insufficient when it belongs to a different profile or policy continuity.

## Runtime chain

The strengthened path is:

```text
Genesis / relying-context epoch floors
        ↓
signed RecoveryTrustManifest
        ↓
pinned A + B key identities
        ↓
signed ExternalRecoveryWitnessProfile
        ↓
pinned endpoint + TLS + policy epoch/hash
        ↓
A-signed recovery authorization
        ↓
remote B policy evaluation
        ↓
B joint co-signature
        +
B WitnessRecoveryReceipt
        ↓
receipt/profile continuity verification
        ↓
RecoveryTrustRoot verification
        ↓
kernel source revalidation
        ↓
exact joint commitment
        ↓
epoch advance
        ↓
CLEAN last
```

## Executable falsification

Unit proofs reject:

- profile epoch rollback;
- policy epoch rollback;
- post-signature endpoint modification;
- a profile naming a witness key not pinned by the recovery trust root;
- handler startup with a policy epoch different from the profile;
- handler startup with a policy hash different from the profile;
- client construction with a substituted endpoint;
- client construction with a substituted TLS trust anchor;
- a cryptographically valid B-signed receipt produced under different profile/policy continuity;
- a receipt evaluated outside the recovery authorization validity window.

A live TLS test also proves that a profiled witness produces a receipt that verifies under the pinned profile.

The KinD control-plane proof is upgraded to consume the signed profile and require `CoSignWithReceipt`, not only the joint authorization.

## Claim boundary

This proves witness identity and policy continuity under a trusted profile signer and caller-supplied anti-rollback epoch floors.

It does **not** yet prove that the profile signer or the epoch-floor authority is administratively independent from the Aegis repository owner.

In the current CI topology, one provisioning principal still creates:

- the recovery trust signer;
- A and B identities;
- the external witness profile;
- the initial policy;
- the controller bundle.

Therefore the next genuine trust boundary is external profile administration:

```text
Aegis repository/workload administration
        |
        +-- cannot sign a new ExternalRecoveryWitnessProfile
        +-- cannot lower accepted profile/policy epochs
        +-- cannot rotate B
        +-- cannot replace B TLS identity
        +-- cannot replace B policy
        |
        v
independent profile/key administration
```

That property requires deployment evidence outside the single repository-controlled CI provisioning path. Adding another mock or another KinD cluster under the same provisioning principal would not establish it.
