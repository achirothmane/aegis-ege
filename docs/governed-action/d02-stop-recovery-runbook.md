# D02 stop and recovery runbook

This runbook applies only to the isolated D02 KinD cluster and synthetic CRM
fixture.

## Stop conditions

Immediately stop the affected mutation class when any required item is
unavailable or contradictory:

- durable attempt/checkpoint store;
- pre-effect journal append;
- current authority required for a new effect;
- Kubernetes execution Lease;
- destination CAS / resourceVersion enforcement;
- exact destination/account/profile binding;
- required closure journal;
- observation authority for reconciliation.

Stopping means **no additional consequential effect**. It does not erase a
possible/accepted earlier effect.

## EEP CRM recovery

1. Preserve the attempt file and journal.
2. Do not delete/re-key the attempt to regain availability.
3. Do not issue another PATCH for an unresolved `POSSIBLE_EFFECT` or
   `ACCEPTED` attempt.
4. Restore observation access.
5. Run observation-only `ReconcileAttempt` against the same signed
   action/permit/plan/destination identity.
6. If stable intended-postcondition evidence closes the attempt, persist
   `COMPLETED`.
7. If the agreed synthetic observation horizon is exhausted, an authorized
   operator may invoke `RetireAttemptUnknown`.
8. `RETIRED_UNKNOWN` keeps the durable record and observation handle. It is
   not proof that the provider did nothing and is not replay authority.

## Kubernetes recovery / takeover

1. Preserve the shared checkpoint ConfigMap and destination state.
2. Inspect live Node/Pod state and reconcile exact Pod UIDs already absent.
3. If another owner holds the Kubernetes Lease, the stale executor stops.
4. A takeover owner does not reuse the old plan as mutation authority.
5. Obtain a fresh authorization for the current remaining Pod set.
6. Resume only the remaining exact effects.
7. Treat a checkpoint `resourceVersion` conflict as a stale-owner failure;
   reload/reassess instead of overwriting.
8. Do not reset the checkpoint to make recovery pass.

## Cleanup

After evidence is retained:

- delete only the isolated test namespace/synthetic node resources created by
  the KinD test cleanup;
- close the local HTTP server;
- retain redacted test logs, run IDs, commit hashes and fault-schedule identity;
- never claim cleanup compensated every external consequence.
