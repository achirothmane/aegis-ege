# Live quorum authority from verified Genesis

The independent-control-plane live quorum no longer treats a provisioning bundle or
self-hashed capability envelope as sufficient authority.

## Authority path

The deployment path is now deliberately two-phase:

```text
prepare
  |
  |-- generate witness identities, trust manifests and exact quorum envelope
  |-- persist sensitive prepared bundle (0600)
  v
external Genesis authority
  |
  |-- bind the exact capability-envelope hash
  |-- sign/verify the Genesis artifact set
  v
activate
  |
  |-- production Genesis verification -> BOOTSTRAP_READY
  |-- emit opaque VerifiedGenesisPin
  |-- pin.ParseQuorumBinding(exact envelope)
  |-- derive active quorum policy
  v
provision A / B / C
```

The activation process cannot construct the quorum binding through
`journal.ParseGenesisQuorumBinding` directly. It must possess an in-process
`VerifiedGenesisPin` emitted by the production Genesis verifier.

## Fail-closed properties

The executable proof requires:

```text
prepared bundle only
        -> DENY

zero / unavailable VerifiedGenesisPin
        -> DENY

Genesis capability hash != prepared envelope hash
        -> DENY

tampered envelope after Genesis verification
        -> DENY

BOOTSTRAP_READY + exact pin + exact envelope
        -> quorum activation
```

The prepared bundle contains transient provisioning secrets and is deleted after
successful activation. The final client bundle contains public trust material and
the exact Genesis epoch/capability-envelope coordinates, but it is not itself an
authority token.

## Runtime reconstruction

The independent-control-plane runtime proof also changed. Each test process
re-enters the production Genesis verification path for the exact live quorum
envelope, obtains its own opaque pin, and constructs the governed quorum through
that pin. Direct parsing of the client bundle is no longer the proof path.

That distinction is important: a serialized client bundle can describe the
witnesses, but cannot manufacture the authority to trust them.

## Failure-domain proof

After Genesis-gated activation, the existing live proof still establishes:

```text
A + B + C -> T1

C unavailable
A + B -> T2

C restored stale at T1
A + B remain authoritative at T2

A and B unavailable
C alone -> FAIL CLOSED
```

The three witnesses remain on independent Kubernetes control planes with
availability-only credentials that cannot read governed witness state.

## Claim boundary

This closes the deployment bridge for the **independent-control-plane live quorum**
from verified Level -1 Genesis into quorum construction.

The test fixture used in CI is an integration-only synthetic authority that drives
the real production Genesis verifier; it is not a substitute for a production
organizational signing authority.

The legacy single-control-plane live quorum provisioning path remains a separate
migration boundary and is not covered by this claim.
