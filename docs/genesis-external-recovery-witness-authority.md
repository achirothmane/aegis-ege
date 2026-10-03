# Genesis-bound external recovery witness authority

Status: executable trust-root and consumer-path proof.

This layer follows the external witness profile and signed receipt work by removing two remaining runtime configuration choices from the production trust path:

- which key may authorize a new external witness profile;
- how low the accepted profile and policy epochs may be.

Those choices are now derived from a capability envelope whose exact byte hash must already be authenticated by Genesis.

## Genesis policy

The capability envelope carries:

```json
{
  "external_recovery_witness": {
    "protocol": "aegis.ege/external-recovery-witness-genesis/v1",
    "profile_authority_key_id": "...",
    "profile_authority_public_key": "...",
    "required_witness_id": "witness/control-plane-b",
    "tls_server_name": "aegis-witness.local",
    "minimum_profile_epoch": 1,
    "minimum_policy_epoch": 1
  }
}
```

`ParseGenesisExternalRecoveryWitnessBinding` accepts the policy only when the exact capability-envelope bytes hash to the already verified Genesis capability-envelope hash.

Changing any of these fields therefore requires a different Genesis-governed envelope hash.

## Three separated cryptographic roles

Genesis-bound verification rejects a profile-authority key that reuses any of:

```text
A recovery authority key
B recovery witness key
recovery trust-manifest signer key
```

The intended topology is therefore:

```text
A
  signs recovery intent

B
  evaluates witness policy
  co-signs admitted recovery
  emits WitnessRecoveryReceipt

Profile Authority P
  signs ExternalRecoveryWitnessProfile
  cannot act as A or B

Genesis
  pins P public identity
  pins required B identity
  pins TLS ServerName
  pins minimum profile/policy epochs
```

This is role separation by cryptographic identity. Administrative independence still depends on who controls P and B in deployment.

## Genesis-bound consumer

The stronger controller constructor does not accept an arbitrary HTTP client or endpoint.

It:

1. verifies the signed profile using the Genesis-bound profile-authority key;
2. enforces the Genesis profile and policy epoch floors;
3. enforces the Genesis-required witness ID;
4. takes the endpoint only from the verified profile;
5. verifies the TLS trust-anchor bytes against the profile hash;
6. creates its own TLS client;
7. sets TLS ServerName only from Genesis;
8. refuses non-positive network timeouts.

This removes caller-controlled `InsecureSkipVerify`, endpoint substitution, signer substitution, and epoch-floor substitution from the production constructor.

## Witness-side startup

The witness process consumes:

```text
signed RecoveryTrustManifest
signed ExternalRecoveryWitnessProfile
Genesis capability envelope
Genesis capability-envelope hash
mounted witness policy
mounted TLS certificate/private key
B private signing key
```

It does not receive the profile-authority private key.

Before becoming ready it proves:

```text
Genesis envelope hash matches
        ↓
Profile Authority P is Genesis-pinned
        ↓
Profile signature valid under P
        ↓
required witness_id matches
        ↓
profile/policy epochs satisfy Genesis floors
        ↓
loaded policy epoch/hash matches profile
        ↓
mounted TLS certificate hash matches profile
        ↓
mounted TLS certificate satisfies Genesis TLS ServerName
        ↓
READY
```

Any mismatch fails startup closed.

## Executable falsification

The proof corpus rejects:

- a profile signed by a key other than the Genesis-pinned profile authority;
- a profile naming a witness ID not admitted by Genesis;
- profile epoch below the Genesis floor;
- policy epoch below the Genesis floor;
- lowering either floor without changing the Genesis capability-envelope hash;
- profile-authority key ID/public-key mismatch;
- unknown fields inside the strict Genesis witness policy;
- using A as profile authority;
- using B as profile authority;
- using the recovery trust-manifest signer as profile authority;
- substituting Genesis TLS ServerName while keeping the same B, profile, endpoint, and certificate.

The TLS falsification performs a real HTTPS co-sign. With the correct Genesis ServerName the request succeeds; with a substituted Genesis ServerName the mounted certificate check fails and the remote TLS connection cannot complete.

## CI topology

CI still creates a simulated profile-authority key only to execute the proof.

The private key exists only in provisioning process memory long enough to sign the test profile. It is not written to:

- the controller bundle;
- the B Secret;
- the B ConfigMap;
- either runtime kubeconfig.

The controller bundle carries only the signed profile and Genesis/public verification material.

After provisioning, admin kubeconfigs are removed and the existing KinD recovery proof executes with narrow runtime credentials.

## Claim boundary

This PR proves:

```text
runtime A cannot choose profile authority
runtime A cannot choose epoch floors
runtime A cannot choose TLS ServerName
runtime A does not receive profile-authority private material
B cannot redefine its own admitted identity
profile authority cannot collapse into A or B keys
```

It does not prove that the CI-created profile-authority key is owned by another organization or cloud account.

The next real deployment boundary is therefore external custody:

```text
Aegis account
   cannot create P
   cannot rotate P
   cannot use P to sign a profile
   cannot administer B signing key
        |
        v
external KMS/HSM/account holds P and B custody
```

Once that deployment exists, the repository already has the consumer-side contract needed to verify it without importing those private authorities back into Aegis.
