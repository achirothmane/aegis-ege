# Remote taint recovery witness v1

Status: executable protocol and custody-boundary proof.

The pinned recovery trust root fixes which Authority A and Witness B identities may authorize live source-continuity recovery. This protocol moves B's signing operation behind an HTTPS service so the recovery controller does not require B's private key.

## Roles

```text
Recovery controller
  has:
    A private key
    verified recovery trust root
    B public key through the trust root

Remote recovery witness
  has:
    B private key
    verified recovery trust root
    A public key through the trust root
    witness-side admission policy
```

Neither side needs the other principal's private key.

## Authority request

The controller calls:

```text
RecoveryTrustRoot.SignAuthorityRequest(auth, A_private)
```

The resulting request binds:

```text
joint protocol version
exact TaintRecoveryAuthorization
pinned A key id
A signature over the joint recovery payload
pinned B key id
```

The trust root refuses to create the request if the supplied A private key is not the pinned recovery-authority identity.

## Witness protocol

The client accepts only an HTTPS endpoint and derives B's pinned key ID/public key from the already verified recovery trust root.

Each co-sign request uses a fresh 256-bit nonce:

```http
POST /v1/recovery/cosign
X-Aegis-Recovery-Witness-Nonce: <fresh nonce>
Content-Type: application/json
```

The witness service performs this order:

```text
protocol check
    ↓
pinned A/B identity check
    ↓
verify A signature
    ↓
authorization validity window
    ↓
witness-side policy
    ↓
B co-signature over exact recovery payload
    ↓
joint commitment digest
    ↓
fresh response signature over nonce + commitment
```

A cryptographically valid request from A is therefore not sufficient by itself. Witness policy remains an independent admission step.

## Fresh response

The witness returns the completed joint authorization plus a response signature binding:

```text
protocol
fresh nonce
witness key id
authorization id
exact joint commitment hash
```

The controller rejects:

- an old response with a different nonce;
- a response signed by an unpinned witness key;
- a modified authorization payload;
- replacement of A's signature;
- replacement of the witness identity;
- an invalid B co-signature;
- an invalid freshness-response signature.

The completed joint authorization is still verified by the existing `TaintRecoveryTrustRoot` before live recovery changes kernel state.

## Witness policy is mandatory

`NewTaintRecoveryWitnessHandler` refuses construction without a policy.

This is intentional. A service that automatically signs every valid A request would move the key without creating an independent authorization decision.

Witness policy may bind deployment-specific facts such as:

- allowed recovery plans or plan digests;
- expected DIRTY generation;
- incident/change authorization;
- host or boot identity;
- approved recovery epoch;
- external operator approval;
- a separate evidence or quorum decision.

Those semantics remain outside the generic recovery kernel.

## Executable falsification

Tests prove:

1. A signs locally and B remotely co-signs; the completed authorization verifies under the pinned trust root.
2. A signature from an unpinned private key is rejected before witness policy executes.
3. Witness policy can deny an otherwise valid pinned-A request.
4. A replayed correctly structured response with an old nonce is rejected.
5. A forged freshness-response signature is rejected.
6. HTTP endpoints are rejected.
7. A witness service cannot start with a B private key that is not pinned by the trust root.
8. A witness service cannot start without independent policy.

## Relation to live recovery

The protocol does not change the `RecoverTaintSourceContinuity` contract introduced by the pinned trust-root proof.

It produces the same `JointSignedTaintRecoveryAuthorization` that live recovery already requires:

```text
A local signature
        ↓
remote B policy + co-signature
        ↓
pinned trust-root verification
        ↓
kernel source revalidation
        ↓
exact joint commitment
        ↓
epoch
        ↓
CLEAN last
```

This avoids putting transport or HTTP semantics into the kernel-facing recovery primitive.

## Claim boundary

The repository now proves a protocol shape in which the recovery-controller client does not require B's private key and B can independently refuse a valid A request.

The in-repository test server is not evidence that A and B are operated by separate organizations or failure domains. The test harness can still create both sides.

A stronger deployment claim requires running the witness service under credentials, secret storage, administration, and infrastructure unavailable to the workload/recovery-controller domain. A later cross-control-plane proof can demonstrate that separation operationally, while organizational ownership remains deployment evidence rather than a property inferred from source code.
