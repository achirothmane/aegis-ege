# governedaction (D04 experimental extraction)

A small standalone Go module for three executable relations in the frozen
governed-action v1 contract:

| API | Relation | What the adapter must establish |
| --- | --- | --- |
| `CheckBinding` | K01 exact revision, target and trusted profile binding | Native canonicalization, resolved destination/account scope, profile selection and evidence authenticity |
| `CheckValidity` | K03 finite authority at each effect boundary | Trusted boundary clock, current witnesses and invalidation semantics |
| `PrepareEffect` / `Dispatch` | K02 custody before a possible surviving effect; K03 revalidation after the write | Durable native custody for the same effect/attempt, accountable ownership, cardinality and native transaction/CAS/fencing |

Import: `github.com/achirothmane/aegis-ege/governedaction`.
The repository currently uses local `replace` directives. `v0.0.0` is a local
development dependency, not a published version or certification claim.

```go
result, err := governedaction.Dispatch(ctx,
    checkCurrentNativeBoundary,
    persistSameNativeAttempt,
    executeConditionalNativeMutation,
)
```

The callback contracts are part of the API. A custody callback must acknowledge
the durable native write, not schedule it asynchronously. A boundary check must
establish current domain facts, not merely trust caller assertions. Neither
callback may dispatch the governed effect. The library calls each effect
callback at most once per invocation; durable native storage must prevent unsafe
second invocations. There is no automatic retry.

`CustodyRecorded` and `BoundaryEntered` describe only facts this invocation can
know. A failing effect callback can have committed. Process death yields no
return value at all. Recover the original native records and observe; do not
create a replacement effect. These structs are neither permits nor dispatch
receipts, and they do not establish accepted or verified outcomes.

Native transaction locking/CAS/fencing is still needed between a check and a
remote mutation. A boundary expiry check does not bound the time at which a
remote commit completes. A post-write check failure leaves recorded custody
intact; the adapter retains conservative native uncertainty.

Current consumers are CRM conditional HTTP mutation, the PostgreSQL gosmig
transaction wrapper, and the existing decision authorization validator used by
Kubernetes. Typed closure profiles, postconditions, observers, replay claims and
recovery authority remain in their adapters. This module is not a universal
lifecycle, scheduler, policy engine, identity service or credential.

## Experimental execution-origin hardening

`CheckOrigin` is an additive, non-normative hardening relation. It does **not**
change the frozen K01-K05 oracle.

It binds an admitted execution origin to the current origin by exact:

```text
origin_id
origin_type
source_digest
trust_domain
trust_epoch
```

and rejects any silent capability expansion. A strict capability subset is
allowed; a new capability requires fresh admission.

The adapter/profile must derive origin provenance from a trusted mechanism.
Caller-provided labels, self-reported digests or a matching artifact hash alone
are not authority.

The machine-readable Muse-class adversarial corpus lives at
`testdata/muse-class/corpus-v0.json`. Only M00/M04/M05 are newly executable
through this origin check; planned cases are deliberately not credited as
implemented controls.

See
[ Muse-class adversarial hardening v0 ](../docs/governed-action/muse-class-adversarial-v0.md).

Run `go test -race -count=1 ./...` from this directory. Repository CI also runs
the unchanged frozen oracle, CRM/D02 tests, native PostgreSQL crash schedules and
KinD integration tests. See [D04 scope and evidence](../docs/governed-action/d04-shared-library.md).
