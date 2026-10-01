# D04: executable common relations (owner-authorized development)

Status: **PROVISIONAL_EXTRACTION**, not an independently validated generalized
kernel release. Base: `37d9e403c367077990dffb335ddfeabdefa4f991` (merged PR #99).

On 2026-10-01 the owner authorized progressing to D04 on the explicit development
assumption that D03 was complete. This assumption does not change the factual
D03 readiness record, the frozen v1 contract, the independent-review claim or
the pending upstream recruitment requests. Actual independent D03 evidence may
still require shrinking or revising this API. No external maintainer identity or
acceptance is asserted.

## Extracted boundary

The standalone `governedaction` module extracts exact opaque binding equality,
exclusive finite expiry, and ordered native custody before effect entry with a
fresh check after the custody write. These relations recur in the tested
domains; their native meanings do not belong in the shared code.

| Consumer | Shared code now executed | Native semantics retained |
| --- | --- | --- |
| CRM EEP executor | Exact plan/destination/account/profile matching, finite authority, custody then revalidation then one PATCH callback | Signed evidence/permit validation; durable file claim/transition and journal; If-Match; stable field postconditions; observation-only recovery; UNKNOWN and residual custody |
| gosmig PostgreSQL wrapper | Exact SQL revision/database/schema/profile matching, database-clock expiry, custody then boundary revalidation | Actual unmodified pinned gosmig; authority row lock, owner/fence/epoch/native-version checks; independent autocommit custody INSERT; transactional SQL whitelist; read-only native observer |
| decision authorization (Kubernetes consumer) | Shared finite boundary validity, including unknown-time rejection | EASL state bindings, action/target/plan validation, execution locks, Kubernetes API CAS, exact Pod UID observation and native checkpoints |

This extraction is deliberately a subset of K01–K03. K04 closure remains native
and typed. CI retry-gate Python code is not linked to this Go module and is not
claimed as an extracted runtime consumer. The library does not copy the
test-only boolean K07 evaluator into production.

## Concrete behavior corrected

CRM previously checked start-permit expiry only before its precondition read.
If that read or a durable custody write consumed the validity window, the
subsequent PATCH could start with expired authority. Both operations now precede
a new boundary check. A changed plan during the custody write also cannot cross
the boundary. Existing destination If-Match still protects the atomic state
precondition; repeating a local check does not replace destination enforcement.

A check failure after successful custody persistence retains the conservative
`POSSIBLE_EFFECT` native record even when this invocation did not enter PATCH.
Restart cannot blindly replay it. Existing read-only reconciliation remains
available after start-permit expiry and does not dispatch a second mutation.

The decision validator also refuses a missing boundary clock even when optional
state bindings are absent. Domain reason codes remain domain-owned.

## Validation and provenance

The additive registration at `testdata/governed-action/d04/registration-v1.json`
fixes the extraction scope and new negative schedules before CI. Existing gosmig
registration, 13 native cases and 11 K07 mappings stay unchanged. All seven
normative artifacts, original frozen tests and `evaluateK07` remain byte-identical.

Validation includes standalone library admission/custody failure and useful
execution tests; five real CRM HTTP/file-store boundary faults plus the existing
successful, replay, lost-response and D02 recovery cases; a four-vector bridge
for the extracted revision/custody relations; all 28 original K07 vectors; all
13 PostgreSQL schedules and 11 existing mappings; and the repository's full
unit/KinD CI. The supplemental bridge is not evidence for unextracted semantics.

`d04-shared-library` workflow artifacts retain test event logs, source hashes and
the source SHA checked out. PostgreSQL artifacts separately retain real native
observations. Final immutable runs reject formatting or dependency-file drift.
Evidence closeout is additive; no frozen expected results are edited to pass.

The immutable dependency check also records Go's already-selected indirect
versions for `go-spew`, `go-difflib` and `pflag` in the root module. Their checksums
were already present in the baseline `go.sum`. Go's resolved checksum file is
committed in its canonical order with required transitive module metadata, so
validation cannot silently change dependency files. The standalone shared
module itself uses only the Go standard library.

## Limits and rollback

The library cannot prove that an adapter's clock, durable-write acknowledgement,
profile selection or mediation boundary is trustworthy. Cooperative adapters
must uphold the documented callback contracts and native atomic enforcement.
It does not make arbitrary code, nontransactional migrations, hostile bypass or
production trust-root deployment conformant. No new recovery mutation authority,
substitution rule, universal EffectIdentity or universal outcome enum is created.

Rollback removes local module dependencies and returns the adapter boundary
ordering to its previous implementation. Native custody/evidence records keep
their existing schemas and remain readable; no data migration is introduced.
Reverting the CRM rechecks also reintroduces the documented expiry gap.
