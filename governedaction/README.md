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

`CheckOrigin`, `CheckApprovalUse`, `CheckCredentialUse`, and `CheckTaintEgress` are additive, non-normative hardening relations. They do **not**
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
`testdata/muse-class/corpus-v0.json`. M00/M04/M05 are executable through
`CheckOrigin`; M06/M07 through `CheckApprovalUse`; M08/M09 through
`CheckCredentialUse` plus broker tests; M01/M02/M03 through `CheckTaintEgress`
and the synthetic `taintflow` propagation model. M10-M15 retain existing/partial
classifications and are not relabeled by this work.

`CheckApprovalUse` consumes an already-authenticated approval reference and
binds it to exact action revision, effect identity, target, scope, nonce, effect
limit and expiry. Replay protection is only as strong as the adapter's durable
use accounting and native transaction/CAS/fencing; this package does not create
a universal approval store.

`CheckCredentialUse` binds an opaque credential handle to exact action revision,
effect identity, audience, destination, scope, trust epoch and expiry. Raw
credential bytes are deliberately absent. The synthetic HTTP broker experiment
lives in `internal/secretbroker`: it resolves the handle in trusted bootstrap
state, checks the binding, injects a bearer credential at the outbound boundary,
rejects caller credential headers, and refuses to follow redirects with the
injected credential. This proves interface behavior, not cross-process secret
isolation.

`CheckTaintEgress` requires every observed taint label to be explicitly admitted
for the same subject and trusted monitor epoch. The `taintflow` subpackage is a
synthetic monotonic model used by M01-M03: fork copies parent taint, and
file/IPC-style write/read unions labels into the receiving process. It is not a
BPF-LSM implementation or proof of hostile-process complete mediation.

See
[ Muse-class adversarial hardening v0 ](../docs/governed-action/muse-class-adversarial-v0.md).

Run `go test -race -count=1 ./...` from this directory. Repository CI also runs
the unchanged frozen oracle, CRM/D02 tests, native PostgreSQL crash schedules and
KinD integration tests. See [D04 scope and evidence](../docs/governed-action/d04-shared-library.md).

## Synthetic model retirement

The historical `governedaction/taintflow` simulation package described above is
now a test-only fixture in `taint_fixture_test.go`. Its complete propagation
algorithm, three original tracker tests and all M00-M15 corpus cases are retained;
only the test namespace, constructor name and three gofmt columns change. Normal
module builds no
longer compile or expose the simulation package. `CheckTaintEgress` and every
execution/recovery API remain unchanged. This retires an experimental simulation
import path; it does not remove a trusted production monitor or prove complete
mediation. See [kernel shrink cycle 2](../docs/governed-action/kernel-shrink/cycle-2.md).
