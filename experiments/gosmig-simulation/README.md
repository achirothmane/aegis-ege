# Native gosmig owner simulation

This is an isolated nested Go module. The root module's dependencies and frozen
contract remain unchanged. The unmodified upstream dependency is pinned to
`padurean/gosmig@f2cc69c685d654990d01582cb68b2c5b097cb36d`.

Read `../../docs/governed-action/gosmig-owner-simulation.md` for the preregistered
criteria, mediation boundary and limitations. This is same-owner supplemental
evidence, not upstream maintainer participation or an independent D03 pass.

The dedicated workflow supplies a disposable PostgreSQL 16.6 service and runs
the actual gosmig runner in subprocesses. `TestHelperProcess` is the subprocess
entry point. `os.Exit(93)` cuts the worker immediately after native commit;
`os.Exit(94)` cuts it immediately before commit. Barrier files order takeover
and expiry interleavings; SQL snapshots and a separate SELECT-only role verify
the outcome without reissuing the migration.

To reproduce, provide `GOSMIG_SIM_ADMIN_DSN` for a **new disposable database**,
set `GS_SOURCE_HEAD` to the tested commit, and run
`go test -mod=readonly -count=1 -v ./...` in this directory. The harness creates fixture
roles with the public test password `fixture-only` and thirteen isolated schemas.
It deliberately fails without PostgreSQL. Use the generated JSON with the root
`TestGosmigNativeEvidenceUsesUnchangedK07Evaluator` test to verify the supplemental
dispositions with the existing evaluator.

`evidence/` preserves the native JSON and unchanged K07 result from the first
fully successful run, the earlier failed native report, and their provenance.
The workflow now verifies committed formatting and lockfiles without rewriting
source or dependency selection before testing.

The fixture key and roles provide cooperative test authorization. They do not
model hostile code, malicious database administrators, production key custody,
or nontransactional migrations. UNKNOWN/OPEN is retained when an exact native
postcondition cannot be verified. A failed worker exit is never interpreted as
proof of a failed effect.
