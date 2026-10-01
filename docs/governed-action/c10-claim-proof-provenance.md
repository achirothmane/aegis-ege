# C10 — Claim / proof / release provenance closeout

Status: **IN PROGRESS**

This record implements the C10 correctness closeout from the Reconciled Master
Engineering Queue. It does not add platform architecture, runtime authority,
repository settings, or distribution claims.

Machine-readable evidence:
`testdata/governed-action/c10/claim-proof-matrix.json`

## What is already supported by merged evidence

The repaired C01–C09/C02 claims are pinned to merged PRs and immutable merge
commits. Current `main` heads were compared against the earliest repair commit
for every participating repository; each audited head is ahead with
`behind_by=0`.

| Card | Merged evidence |
|---|---|
| C01 | Aegis #68 → `a4fb223caea1e03eea1939a2e0ad4974850653f3` |
| C02 | ModFactory #26 → `35db43094299fe722979f154d701d0841267be2d`; #27 → `48310eaa8ccae31da4a32e38c1f75172c0f76733` |
| C03 | Aegis #69; WFL #110; EASL #13; AAG #11; assumption-gate #2; TGP #3 |
| C04 | Aegis #70; WFL #111; AAG #12; assumption-gate #3 |
| C05 | Aegis #71; WFL #112; AAG #13; assumption-gate #4; TGP #4 |
| C06 | Aegis #72 |
| C07 | Aegis #73 |
| C08 | Aegis #74; EASL #14 |
| C09 | Aegis #75 |

The JSON record contains every exact merge commit.

## Claim corrections discovered in C10 preflight

Three material documentation/provenance defects require correction before C10
can be marked complete.

### ai-deployer

Current `main` contains a placeholder AI image, hard-coded example credentials,
a legacy installer snippet, no release, and no CI-backed deployment/security/
recovery proof. The existing README claim `Production-ready` is unsupported.

Correction PR: `achirothmane/ai-deployer#2`  
Head: `39ba3c934ffe4bd7ffe14789a36ea370071b035d`  
State in this record: **OPEN — NOT COUNTED AS MAIN**

The corrected claim is: legacy non-production placeholder; do not deploy as-is.

### Runner Fleet Doctor

The implementation exists and is a read-only GitHub Action. The repository name
is not being changed. The preflight found two provenance defects: stale
`othy19904-eng` identity/reference text and wording that did not distinguish
the movable `v1` branch from an immutable/protected release channel.

Correction PR: `achirothmane/atlassian-revenue-integrity#1`  
Head: `4265c955a8d08982a61c3e4d22c953af664d2e7a`  
State in this record: **OPEN — NOT COUNTED AS MAIN**

No external adoption, Marketplace listing, production fleet deployment, or paid
usage is inferred from the repository.

### CI Retry Gate release provenance

WFL has real immutable releases, including `v1.2.0` at
`f9bc919f3dfd8c1f705fb7bf2f4c064c37962abb`. Its movable `v1`
branch currently points at that same commit.

Correction PR: `achirothmane/workflow-failure-lab#123`  
Head: `605b14689514ac319821e11c9a6f1de75e9a6401`  
State in this record: **OPEN — NOT COUNTED AS MAIN**

The correction separates the documented maintainer release process from actual
GitHub-enforced branch controls.

## Branch/ruleset audit

The audit used GitHub branch objects plus the repository rulesets endpoint.
The current GitHub App connection cannot read the branch-protection detail
endpoint, so no claim is based on that unavailable endpoint.

For every audited repository/branch, the branch object reports
`protected=false`, and the repository rulesets endpoint returned an empty
list. This includes:

- Aegis `main`;
- WFL `main` and `v1`;
- ModFactory `main`;
- EASL `main`;
- AAG `main`;
- assumption-gate `main`;
- TGP `main`;
- ai-deployer `main`;
- Runner Fleet Doctor `main` and `v1`.

Therefore no C10 claim may describe those controls as GitHub-enforced
**mandatory branch protection**. Workflow success, release discipline and
branch protection remain distinct facts.

## Credential and recovery boundaries

C10 preserves the narrower claims already established by the repaired systems:

- **Aegis-EGE:** D02 proves the bounded Kubernetes Lease/ConfigMap path and
  truthful UNKNOWN custody under the tested experiment. It does not prove
  external CRM CAS or production failover.
- **CI Retry Gate:** read/report paths are read-only; rerun mutation requires
  explicit `actions: write`; UNKNOWN does not grant rerun authority.
- **ModFactory:** local verification only; project-code execution is explicit
  opt-in; `deployment_admissible=false`; PASS is not deployment permission.
- **AAG / assumption-gate:** `trusted_in_process` self-hashes provide
  integrity, not external issuer authentication.
- **TGP:** the reference evaluator is not an atomic distributed production
  control plane.
- **EASL:** it neither executes actions nor decides policy; unsupported external
  assurance obligations must fail closed.

## Open PRs are not main capabilities

The matrix explicitly excludes open work from main capability claims. In
particular Aegis #64/#65/#91 and WFL #63/#108/#109/#116 remain outside the
merged evidence set. The three C10 correction PRs above are also excluded until
merged.

## Completion rule

C10 becomes **COMPLETE** only after:

1. the three correction PRs pass their repository-appropriate checks and merge;
2. this record is updated from PR heads to exact merge commits;
3. the claim matrix reports
   `all_material_claims_supported_or_corrected=true`.

Until then this file is a truthful **IN PROGRESS** evidence record.

Normative change: **NO**  
Runtime change: **NO**
