# Genesis-Bound Witness Quorum Membership

Status: executable trust-binding proof.

Quorum consensus is not secure if the workload operator can replace the quorum membership list or reduce the threshold after boot.

This layer binds the exact witness quorum configuration to the same cryptographic authority that signs the Genesis manifest.

## Bound fields

The signed membership policy binds:

```text
Genesis manifest payload hash
Genesis epoch
membership epoch
threshold
member IDs
member HTTPS endpoints
member witness key IDs
member witness public-key hashes
```

Each member identity is therefore stronger than a display name.

```text
witness-a
  !=
any service configured under the string "witness-a"
```

The runtime member must match the exact endpoint and pinned witness key identity authorized by the Genesis-bound policy.

## Authority

The quorum membership policy must be signed by the same trusted Ed25519 authority whose key ID signs the Genesis manifest.

Verification requires:

```text
policy signer key id
        ==
trusted Genesis manifest signer key id
        ==
Genesis manifest authenticity.signer_key_id
```

A workload configuration change therefore cannot authorize a new quorum unless it also possesses the Genesis signing authority.

## Exact Genesis binding

The policy contains the exact Genesis manifest payload hash and Genesis epoch.

A valid policy for Genesis G1 cannot be replayed under Genesis G2 even if the same signer key remains trusted.

```text
Genesis G1 + Policy P1 -> valid

Genesis G2 + old Policy P1
          ↓
manifest payload hash mismatch
          ↓
DENY
```

## Membership anti-rollback

The policy carries a `membership_epoch`.

The relying context supplies a minimum accepted membership epoch.

```text
policy epoch < minimum accepted epoch
        ↓
DENY
```

This prevents an old, correctly signed quorum configuration from being restored after a newer governed membership transition has been accepted.

## Structural invariant

The verifier itself enforces strict-majority quorum.

For N witnesses:

```text
threshold > N / 2
```

Therefore even the Genesis signing authority cannot produce an accepted configuration such as 1-of-3 or 2-of-4 through this policy format.

This is a structural safety invariant rather than an operator convention.

## Runtime construction

`BuildGenesisBoundQuorumHeadStore` accepts only the exact runtime set authorized by the signed policy.

It rejects:

- missing configured witnesses;
- unexpected extra runtime witnesses;
- replacement endpoint under an existing member ID;
- replacement witness signing key under an existing member ID;
- a membership policy signed by a different authority;
- a policy replayed against another Genesis manifest;
- membership epoch rollback;
- non-majority thresholds.

Only after these checks does it construct `journal.QuorumHeadStore`.

## Resulting trust chain

```text
Genesis Manifest
  |
  | same signing authority
  v
Signed Witness Quorum Membership Policy
  |
  +-- exact Genesis payload hash
  +-- Genesis epoch
  +-- membership epoch
  +-- strict-majority threshold
  +-- witness A endpoint + key
  +-- witness B endpoint + key
  +-- witness C endpoint + key
  |
  v
Genesis-bound QuorumHeadStore
  |
  v
Capability Root
```

A workload operator can no longer replace A/B/C or lower the quorum threshold through mutable runtime configuration alone.

## Claim boundary

This proof binds configuration to the Genesis cryptographic authority.

It does not make the Genesis signing authority infallible or unavailable to compromise. A party that controls the trusted Genesis private key remains able to authorize a new valid membership policy, subject to the structural strict-majority invariant.

The next stronger boundary is governance of quorum membership rotation itself: require an authorized transition from the previous membership epoch, potentially with approval from both the Genesis authority and the currently accepted witness quorum.
