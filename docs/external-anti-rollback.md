# M10 — external anti-rollback anchor and key custody

M10 closes the strongest known M6 rollback gap without putting signing authority into the authorization path.

## The M6 gap

M6 could detect:

- modified entries;
- reordered entries;
- middle deletion;
- tail truncation against the current local signed anchor.

But this pair could be restored together:

journal snapshot at sequence 2
+
matching valid local anchor at sequence 2

and local verification would accept it.

## External latest-head reference

M10 adds ExternalHeadStore.

The independently retained head contains:

- journal ID;
- latest sequence;
- latest head hash;
- signing KeyID.

Verification now requires:

local hash chain
+
local signed anchor
+
external latest head
→ exact agreement

If the local journal and local signed anchor are both rolled back from sequence 3 to a valid sequence-2 snapshot while the external store remains at sequence 3:

local verification → valid
external-head verification → invalid

This is the anti-rollback property M6 did not have.

## Kubernetes external head backend

M10 includes a Kubernetes ConfigMap-backed ExternalHeadStore.

It is external to the journal files and uses resourceVersion compare-and-set semantics.

This protects against:

- Pod/container filesystem rollback;
- restored local volumes;
- replacement daemon instances receiving stale local journal files;
- stale writers attempting to regress the retained head through the normal StateLatch API.

It does not claim to defeat a Kubernetes administrator who can arbitrarily rewrite both application state and the external-head ConfigMap.

The ExternalHeadStore interface exists so deployments with a stronger threat model can use:

- WORM/object-lock storage;
- transparency logs;
- dedicated append-only services;
- independently administered databases;
- hardware-backed monotonic services.

## Signer / verifier separation

FileJournal no longer needs a raw private key.

M10 defines:

- AnchorSigner
- AnchorVerifier
- Ed25519Signer for local/testing use
- Ed25519Keyring for historical verification
- RemoteSigner for external key custody

The remote signer sends only the anchor signing payload to an HTTPS signing service.

The StateLatch process never receives the private key.

A KMS/HSM can therefore sit behind that signing service without coupling StateLatch to AWS, GCP, Azure, or a specific HSM SDK.

RemoteSigner fails closed when:

- endpoint is not HTTPS;
- request fails;
- signer returns non-200;
- returned KeyID differs from the configured KeyID;
- signature is empty or malformed.

The HTTP client is caller-supplied so production deployments can use mTLS and a separately administered trust boundary.

## Key rotation

Every signed anchor records KeyID.

A verifier keyring can retain old public keys while a new signer becomes active.

Rotation flow:

old signer + old public key
→ existing anchor verifies

add new public key to verifier keyring
→ reopen journal with new signer
→ append next entry
→ new anchor uses new KeyID

old historical anchor → still verifies
new current anchor → verifies

Removing a historical verification key before old anchors are retired fails closed.

## Live proof

The KinD M10 test uses:

- local journal + local signed anchor;
- Kubernetes-backed external head.

It writes through sequence 3, then restores both local files to the valid sequence-2 snapshot.

Expected result:

local-only verification = VALID
M10 external verification = INVALID / external journal head mismatch

This directly proves detection of the full-local-snapshot rollback that M6 documented as undetectable.

## Authority boundary

M10 remains audit infrastructure only.

The signer, verifier, and head store do not mint execution permits or change ALLOW/BLOCK/ESCALATE.

## Crash behavior

Journal entry, local anchor, and external head are separate durable writes.

A crash between them can leave components temporarily inconsistent.

Verification fails closed on inconsistency.

Automatic crash repair is intentionally not guessed by M10; recovery requires an operator or a later recovery protocol to establish which durable head is authoritative.

## Production threat-model boundary

The Kubernetes head backend is sufficient for the v1 single-cluster threat model where journal storage and Kubernetes control-plane state are distinct failure domains.

For protection against a malicious cluster administrator or coordinated rollback of every StateLatch-controlled store, configure an ExternalHeadStore implementation under an independently administered trust domain.
