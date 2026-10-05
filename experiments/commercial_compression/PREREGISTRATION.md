# Commercial compression experiment — frozen before implementation

Registered: 2026-10-05. Repository: achirothmane/aegis-ege.
Pinned main: `04434db12fa0c85d3497faf6ebb40df937092c5d`.
PR #246: open draft, unmerged, head
`75d253c4e2b60b44baaba211d2e7ce6edf335ceb`.
N1 / R4 / P1 and W1 remain the starting state.

## One workflow and its boundary

Change the image of a named container in a Kubernetes Deployment, using a
retained JSON Patch with UID, resourceVersion and destination-local authority
generation/active preconditions. Operation 1 releases a new image; operation 2
rolls back that same container to its prior image. The second operation is a new
authorized logical effect, never a recovery retry with a new identity.

The effect is the committed Deployment desired-spec mutation. CLOSED does not
mean Pods are healthy, traffic has moved, the release is commercially successful,
or all external/global authorization services have synchronously revoked access.
Current truth is the fresh desired image of the independently selected UID and
container. Native API audit RequestResponse records supply authenticated request
identity and the winning mutation; an independent read supplies current truth.
The destination-local grant is protected by admission policy, and the unchanged
retained resourceVersion precondition orders revocation against commit.

Buyer hypothesis: platform/SRE teams repeatedly maintaining reliable release
automation. Commercial spend on delivery tools establishes a relevant category,
not willingness to buy this library. There are no customer or payment claims.

## Fairness and implementation freeze

Use a real disposable KinD Kubernetes API server, not an in-memory fake or SQL
replacement. Both variants use the same service accounts/RBAC, admission policy,
native CAS, retained request, SQLite FULL-synchronous issued/result and successor
CAS journal, raw audit events, independent observer, Ed25519 root, freshness
challenge, trust assumptions and failure schedules. The journal is a small real
durable equivalent for this issued/completed single-step contract, not Temporal
conformance. No vendor workflow engine is rebuilt.

A is a purpose-specific respectable ordinary checker, written to the same exact
question and evidence/trust contract. It may reuse its own code for operation 2.
B uses the unchanged main `evidenceverify.Verify` consumer through the existing
CLI; no new production checker, runtime, hosted component or feature is allowed.
Use the smallest contract that works: ordinary PKI, no Genesis/quorum default.
If its fixed PostgreSQL wire profile requires a compatibility projection, mark
it SIMULATION, count all mapping/binding glue, and never call it native Kubernetes
support. If a raw API supplies a fact, both variants receive it. No closures are
credited from renamed labels or executor success reports.

Before implementation, commit this document separately. Retain its Git commit,
content hash and parent. Any methodological change is an explicitly reported
amendment, not a silent redefinition. No optimization driven by a favorable
classification is permitted. Fix correctness defects exposed by tests; retain
their cost. Stop after this workflow; do not try another domain to obtain a win.

## Measurements

1. **Custom integration LOC**: physical nonblank, non-comment Python source
   lines, excluding standalone docstrings; format both variants identically with
   Black 24.8.0, line length 88, before counting. Count all hand-written reachable
   workflow-specific evidence mapping, question/trust/freshness binding,
   reconciliation, recovery/continuation and independent verification glue.
   Include common glue in both totals. Include B's compatibility/CLI glue.
   Exclude vendor/library code, generated artifacts, corpus/test/measurement
   drivers, native mutation transport and the shared durable executor itself.
   Publish the source manifest, exclusions and both gross integration totals;
   also show common native/executor plumbing so it cannot hide cost shifting.
   LOC is a maintenance proxy, not measured human authoring hours.
2. **Configuration**: list/count named required input fields, manual deployment
   settings, question fields, trust/policy bindings and recovery options. Show
   mechanically generated wire fields separately; defaults do not erase schema
   coupling. A role label reusing one root is not an extra trusted signer.
3. **Engineer setup steps**: enumerate each documented human decision/command
   from checkout to first independently justified governed effect. Automation may
   execute commands, but do not claim commands were eliminated by packaging.
4. **Recovery steps**: count destination/audit observation, validation, judgment
   and continuation actions. Report operator actions and programmatic stages
   separately, plus actual destination reads/writes/CLI invocations. A single
   wrapper around identical work earns no step reduction.
5. **First-effect time**: clean fresh CI workspaces, fresh journals, fresh
   namespace, no imported author state. Record setup/build/provisioning and the
   end-to-end interval to verified first effect. Prerequisites already installed
   by CI are declared; cached base images/tool installations are not a customer
   onboarding study. Use two paired runs with A/B order reversed. A fresh
   documentation-only runner must follow the same commands and record problems.
   This simulates a clean integrator, not an independent human/team.
6. **Recovery time**: monotonic failure marker to justified result for each
   schedule. For unavailable evidence report time to justified UNKNOWN and,
   separately, delay-until-available plus time to resolution. Never turn
   injected delay or unbounded UNKNOWN into a speed win. Record raw samples and
   verification/collection components; subprocess costs are disclosed.
7. **Custom test burden**: count destination-specific test cases/controls the
   integrator still needs, and B-only compatibility controls. Existing Aegis
   generic tests are reusable assets, not automatic removal of native tests.
8. **Trust/privilege**: credentials, mutation/read grants, observers, signers,
   roots and installation operators. A compression win is invalid if a material
   new privilege/trust assumption appears or is hidden by normalization.
9. **Diagnostics**: score six explicit answers (actual outcome, exact winner,
   authority at commit, current truth, retry permission and reason) against the
   same retained facts. Preserve richer known-negative answers from A; UNKNOWN
   is not a diagnostic defect when evidence is unavailable.
10. **Reuse**: operation 2 gets the full ordinary implementation's reuse too.
    Count marginal production-glue LOC, required changed data fields, new tests,
    setup steps and elapsed execution. Zero new code on both sides is a tie.

For each cost dimension use `(A - B) / A * 100`. When A is zero, report equal-zero
as a tie and a positive B as added cost; do not divide by zero. Do not average
unrelated metrics. Report increases as negative reductions. No p95 or population
onboarding claims from this small sample. Byte/LOC ratios are not labor hours.

## Identical correctness corpus

Run both on independent copies of the same retained evidence for: crash before
effect; commit/lost ACK; executor death after commit; successor recovery;
duplicate delivery; two recovery owners racing; destination-local authority
revoked before effect; historical commit followed by image drift; matching image
caused by another authorized attempt; unavailable evidence; later-available
evidence; authentic stale signed observation; executor falsely claiming success.
Use real process exit after the API commits for death/lost-ACK schedules.
Add controls for altered signature, wrong independent question and UID replacement.

Required invariants: zero false CLOSED, zero unsafe retry/rebase/new operation
key used as recovery, zero duplicate logical mutation attributable to recovery,
zero unauthorized governed image change in the declared admitted/CAS profile.
Freshness challenge and question/UID binding come from the relying party. Native
audit logs may be delayed or unavailable; their absence does not prove no commit.
The same frozen CAS may be safely redelivered only under the declared profile;
an arbitrary new desired-state command is not equivalent.

## Decision rule

C4 is unavailable without independent external paid/reuse evidence. C3 requires
at least one major reconciliation/recovery engineering-cost dimension >=50%
reduction, preserved correctness, materially lower second-operation marginal
work and no offsetting trust/privilege burden. No favorable timing-only result,
generic test inventory or averaged score substitutes for that gate.
C2 requires substantial demonstrated recurring reuse/compression but lacks
customer evidence. C1 records modest compression with useful internal reuse.
C0 applies when recurring engineering work is not materially reduced: preserve
research/code as portfolio IP, stop this commercial asset track, and do not add
features or select another narrative. Borderline evidence is classified down.

The report must answer all 27 requested fields, show raw measurements and state
exactly what changed (or did not change) relative to the proposed 50% gate.
