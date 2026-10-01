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
