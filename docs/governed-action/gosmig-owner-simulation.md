# gosmig / PostgreSQL owner simulation

This experiment is authorized by the owner as a hypothetical maintainer exercise.
It uses the actual pinned gosmig library and disposable PostgreSQL, without
contacting or representing the upstream maintainer. It is supplemental
falsification evidence. D03 remains BLOCKED_UNSTARTED, and D04 remains blocked.

## Registration

The expectations in
`testdata/governed-action/gosmig-simulation/registration-v1.json` are committed
before the first native execution. Keep that registration commit and its exact
blob hash in the result. Fix implementation defects without changing expected
outcomes. A contradictory valid trace is a failure to investigate, never an
opportunity to relax the oracle.

The positive comparator matters: gosmig's transaction and version table already
provide atomic migration rollback and version bookkeeping. This experiment tests
the additional value of a state-bound, finite permit, durable pre-commit custody,
read-only reconciliation, and destination fencing. Native transactions and row
locks remain the mechanisms that make these checks effective.

## Boundary and limits

Only one fixed transactional migration is supported. Its exact SQL, parameter
identities, database, schema, expected native version, and profile are bound into
ActionRef. The adapter mediates its SQL calls and commit request. The gosmig
metadata table is pre-provisioned; its normal create-if-absent call is a no-op
within the fixture. Nontransactional migrations, arbitrary callbacks, external
effects, production credentials, adversarial adapter bypass, and platform-wide
kernel enforcement are outside this profile.

A PostgreSQL row lock serializes authority/state/fence checks with the migration
transaction. Expiry is checked using the database clock at transaction entry and
immediately before the commit request; this does not claim a hard deadline on
the wall-clock instant at which commit durability completes. A short-lived
permit cannot be used to authorize recovery after expiry: the new observer has
separate read-only authority.

Custody is committed on a separate connection before migration SQL. It retains
the signed original permit and effect/attempt identities even if the migration
transaction rolls back. A missing target marker is therefore UNKNOWN/OPEN,
not proof that dispatch never happened. Observation uses a separate PostgreSQL
role with SELECT privileges and a consistent read-only transaction. It verifies
the exact marker, table shape, migration version, target identity and custody,
and retains a null dispatch receipt after injected lost replies or process loss.

## Cases and evidence

Two native controls and eleven governed schedules are fixed in the registration:
normal success, state drift, expired permit, revision mismatch, lost commit
reply, exit after commit, exit before commit, fenced takeover, expiry before
commit, unrelated postcondition, and refused blind replay. Process-loss cases
exit a real subprocess; they are not exception-only simulations.

The native workflow will publish per-case database snapshots, worker exits,
boundary events, read-only observations, dependency lockfiles, source pins,
registration hash, and the frozen K07 bridge result. These artifacts support
owner review; they do not establish independent domain adoption.

## Native result

Run [36798979674](https://github.com/achirothmane/aegis-ege/actions/runs/36798979674)
passed all thirteen fixed schedules on PostgreSQL 16.6 using source commit
`9a8256ed5484e87e3ff2025543865c849e14a170`. All eleven governed supplemental
traces passed the existing unchanged K07 evaluator. The two native controls
remain controls; they are not represented as governed acceptance.

| Case | Worker exits | Committed target rows | Custody rows | Observation |
| --- | --- | ---: | ---: | --- |
| N01 | 0 | 1 | 0 | NOT_RUN |
| N02 | 0 | 1 | 0 | NOT_RUN |
| G01 | 0 | 1 | 1 | VERIFIED/CLOSED |
| G02 | 5 | 0 | 0 | NOT_RUN |
| G03 | 5 | 0 | 0 | NOT_RUN |
| G04 | 2 | 0 | 0 | NOT_RUN |
| G05 | 5 | 1 | 1 | VERIFIED/CLOSED |
| G06 | 93 | 1 | 1 | VERIFIED/CLOSED |
| G07 | 94 | 0 | 1 | UNKNOWN/OPEN |
| G08 | 5, 0 | 1 | 1 | VERIFIED/CLOSED |
| G09 | 5 | 0 | 1 | UNKNOWN/OPEN |
| G10 | 0 | 1 | 1 | UNKNOWN/OPEN |
| G11 | 5, 2 | 1 | 1 | VERIFIED/CLOSED |

N02 commits under changed policy/state epochs while G02 rejects the same
interleaving. This is the bounded incremental value over native transactional
version tracking, not a claim that the adapter replaces PostgreSQL locks.
G06 observes after the original permit expires. G08 blocks the stale worker
while native version is still zero and only then runs the fresh worker. G09
proves a competing authority UPDATE waits behind the held destination row lock.
G07, G09 and G10 remain UNKNOWN/OPEN; a missing or unrelated postcondition does
not become success. G11 preserves the original custody and rejects a fresh
permit that would blindly replay the possible effect.

Raw observations, K07 output, source checksums and the earlier failed native
report are preserved in `experiments/gosmig-simulation/evidence/`. The successful
artifact zip SHA-256 is
`d5045bff8aa7f5d04fad0ea07b52daccbf855fea9679df8399ff06779d3a7789`.
The registration blob stayed byte-identical through the implementation fixes.
The workflow now checks committed formatting and dependencies before rerunning
the native cases; it does not rewrite them to obtain a pass.

D03 remains BLOCKED_UNSTARTED: no independent maintainer, scope grant,
cohort or independent result is supplied by this owner simulation. D04 is not
extracted. This evidence establishes a useful native execution experiment, not
a full platform kernel.
