# Checkpointed Kubernetes effects use the shared library

The checkpointed node-drain adapter now calls the unchanged public `governedaction.Dispatch` before a native cordon and before each native Pod eviction. It checks current authorization, plan/remaining UID scope and native lease ownership, acknowledges retention of the original checkpoint, then checks again. A lease renewal or API read can consume the authority window; the final clock check runs after those calls.

Preparation errors retain their native decision/reasons and do not become destination rejection receipts. An error after the native call still means a possible effect. Existing native recovery inspects the original node/Pod UIDs, reconciles an accepted eviction and requires fresh authorization for the exact remaining scope. The library adds no retries, native lifecycle, credential service or new authorization issuer.

The legacy API without a checkpoint keeps its existing behavior and is not claimed as a durable-custody library consumer. Native node resourceVersion and Pod UID preconditions remain adapter-owned. A cooperative Kubernetes lease is not target-enforced generation fencing; hostile credential bypass and universal complete mediation remain outside this proof.

`testdata/governed-action/shared-boundaries/registration-v1.json` freezes the additional unit and native schedules before final immutable validation. Eight file-store boundary invalidations must produce zero effects at the invalidated boundary and retain original scope after reopening. Two native KinD schedules expire authority while a ConfigMap checkpoint is being retained. Existing useful drains, lost-reply recovery, takeover and native checkpoint CAS schedules must continue to pass, alongside the unchanged K07 and PostgreSQL suites.

The separate owner-controlled CI experiment in `achirothmane/ci-retry-gate-consumer-e2e/experiments/shared-kernel-ci` imports public module version `v0.0.0-20261001022909-a902f1dddf8f` without replacement. Its legacy Python D01 consumer remains separate. This is a provisional cross-domain implementation experiment, not an official D05 registration or independent D03 PASS.
