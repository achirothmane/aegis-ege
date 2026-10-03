# External Witness Protocol v1

Status: executable client contract.

This protocol is the deployment boundary for moving the Aegis capability-root witness outside the workload repository, workload cluster, and workload operator's administrative domain.

It does not make an in-repository test environment organizationally independent. It makes the kernel-side contract explicit so an externally administered witness can be substituted without changing the capability-root semantics.

## Goal

Aegis must be able to ask an independently administered service:

> What exact capability-root head is current, and atomically advance it only if the caller's expected head is still current?

The protected state is:

```text
(root_id, sequence, exact_commitment, protocol_key_id, opaque_CAS_version)
```

The witness must never authorize a transition from a stale expected state.

## Client trust contract

`journal.RemoteHeadStore` implements the existing `ExternalHeadStore` interface.

Construction requires:

- an HTTPS endpoint;
- a pinned witness key ID;
- a pinned Ed25519 public key;
- an HTTP client supplied by deployment code.

The HTTP client carries runtime authentication such as mTLS or a narrow bearer capability. Aegis does not own or provision the witness administrator credential.

Every successful witness response is signed by the pinned witness identity.

The signature binds:

```text
protocol
operation
fresh request nonce
witness key id
journal/root id
sequence
exact head commitment
protocol key id
opaque CAS store version
```

The CAS version is signed because substituting it could otherwise redirect a later compare-and-advance operation onto a different witness state.

## Freshness

A valid signature alone is insufficient.

An old T1 response can remain cryptographically valid forever. If both local state and the local ledger are restored to T1, replaying that old signed response must not make T1 appear current.

Each `Load` and `CompareAndAdvance` request therefore carries a fresh 256-bit nonce in:

```text
X-Aegis-Witness-Nonce
```

The witness must echo that nonce inside the signed response. A response signed for any previous request is rejected before its head state is consumed.

This closes the recorded-response replay boundary while the witness signing key remains trusted.

## API

### Load

```http
GET /v1/heads/{root_id}
X-Aegis-Witness-Nonce: <fresh nonce>
```

`404` means the root has not yet been initialized.

A successful response contains the signed current head.

### Compare and advance

```http
POST /v1/heads/{root_id}/advance
X-Aegis-Witness-Nonce: <fresh nonce>
Content-Type: application/json
```

Request:

```json
{
  "protocol": "aegis-ege/external-witness/v1",
  "expected": {
    "journal_id": "capability-root",
    "sequence": 12,
    "head_hash": "<sha256>",
    "key_id": "aegis-ege/capability-root-head/v1",
    "store_version": "<opaque signed CAS token>"
  },
  "next": {
    "journal_id": "capability-root",
    "sequence": 13,
    "head_hash": "<sha256>",
    "key_id": "aegis-ege/capability-root-head/v1",
    "store_version": ""
  }
}
```

The witness performs one atomic operation:

```text
if current == expected:
    persist next
    return signed next
else:
    return CONFLICT
```

`409 Conflict` or `412 Precondition Failed` maps to `ErrExternalHeadConflict`.

## Required witness properties

A production witness satisfying the stronger organizational boundary must provide all of the following independently of the workload control plane:

1. Linearizable compare-and-advance for each root ID.
2. Durable monotonic persistence of sequence and exact commitment.
3. No administrative path available to the workload runtime that can delete, rewrite, or reset witness history.
4. A witness signing private key unavailable to the workload runtime.
5. A pinned public identity distributed to Aegis through a governance path distinct from runtime mutation authority.
6. Runtime caller authentication narrower than witness administration.
7. Recovery behavior that never silently resets an absent/corrupt root to an older state.

Suitable substrates may include a separately administered service backed by a transactional database with immutable audit history, a quorum service, or a hardware-backed authority that protects both sequence and commitment.

## Executable falsification coverage

The client tests prove:

- valid signed load/advance succeeds over TLS;
- stale CAS state is rejected as conflict;
- a response signed by the wrong private key is rejected;
- an old correctly signed response with an old nonce is rejected;
- HTTP endpoints are rejected;
- missing pinned witness identity is rejected.

These tests prove the client protocol and replay/forgery boundary. They do not prove that a test server in this repository is independently administered.

## Remaining organizational proof

The final claim requires deployment of this protocol against a witness whose administrator is outside the authority that can modify the Aegis workload repository or workload credentials.

Only after that deployment is exercised can Aegis claim:

```text
workload/repository authority compromised
        |
        +-- cannot rewrite witness state
        +-- cannot obtain witness signing key
        +-- cannot replace witness identity
        |
        v
old capability root cannot be resurrected
```

Until then, the repository proves protocol readiness, not independent organizational ownership.
