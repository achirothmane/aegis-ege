# One-workflow commercial compression benchmark

The frozen measurement contract is [PREREGISTRATION.md](PREREGISTRATION.md).
The public benchmark changes Deployment desired image and then rolls it back.
It does **not** prove running-pod readiness or production adoption savings.
Effects execute against a real disposable Kubernetes API. The Aegis consumer is
unchanged main; its fixed wire projection is explicitly SIMULATION grade.

## Setup from a clean checkout

These are the actual commands consumed by the fresh CI runner. All paths below
are caller-selected, documented state. No local developer cache, credentials,
private fixture seed, existing journal or previous evidence is required.

1. Provision Linux with Docker, Python 3.12+, kubectl, Git and KinD v0.33.0.
   B additionally needs Go 1.25.x. The hosted-runner study starts with these
   tools installed; their installation time is not customer onboarding evidence.
2. Checkout this experiment branch and, for B, checkout upstream main at
   `04434db12fa0c85d3497faf6ebb40df937092c5d` in a separate `baseline` directory.
3. Install common observer crypto; Black is only needed for source accounting:
   `python -m pip install cryptography==46.0.0 black==24.8.0`.
4. B only: build the existing consumer from pinned source:
   `(cd baseline && go build -mod=readonly -trimpath -o ../aegis-evidence-inspect ./cmd/aegis-evidence-inspect)`.
5. Create the disposable audited control plane and install the shared admission
   fence: `python experiments/commercial_compression/provision.py --state "$PWD/compression-state"`.
   This requires a cluster installer/operator. It changes only the new KinD
   cluster. The native observer needs read access to this cluster's audit archive.
6. Select namespace, target/container, desired image, local grant epoch/generation,
   and a persistent journal path. The setup runner creates bounded writer and
   read-only observer service accounts in fresh `compression-*` namespaces and
   issues temporary credentials. Those credentials remain outside public output.
7. Establish the observer signing root through the relying party's independent
   channel; retain the complete question and a fresh challenge. These are common
   trust requirements. The study generates a new root in each fresh workspace.
8. Execute the integration and independently check the effect. For the documented
   clean simulation (A1, B1, B2, A2), run:

   ```bash
   python experiments/commercial_compression/clean_setup.py \
     --base "$PWD/baseline" \
     --admin "$PWD/compression-state/admin-kubeconfig.yaml" \
     --audit "$PWD/compression-state/audit/audit.log" \
     --out "$PWD/compression-evidence/clean"
   ```

   The runner copies the source into four fresh directories, creates four new
   virtual environments, installs crypto without pip cache, uses fresh Go build
   caches for B, provisions fresh namespaces, executes release then rollback,
   and records every measured phase. Go module downloads may reuse the hosted
   runner's shared cache; this is disclosed. It executes the same commands without
   consulting an author. This is not an independent person or customer study.

9. Run rollback with the same adapter and checker, changing only desired image
   and operation label. New logical ID, attempt, before-image and resourceVersion
   are derived and retained under fresh authorization. Do not use rollback as a
   recovery retry. No new root, role, configuration schema or reconciliation code
   is added. Both ordinary and Aegis implementations reuse equally.

There are seven numbered first-effect setup stages for A and eight for B
(step 4 is B-only). B also performs the additional pinned-source checkout within
stage 2; count that command separately when comparing executable commands.
Step 9 is the marginal second operation, not first-effect setup. Commands wrapped
by the runner are still counted. The initial infrastructure provisioning interval
is recorded separately and must be added to either variant's clean setup interval
if starting without an existing audited cluster.

## Failure corpus

```bash
python -B experiments/commercial_compression/run.py \
  --admin "$PWD/compression-state/admin-kubeconfig.yaml" \
  --audit "$PWD/compression-state/audit/audit.log" \
  --private "$PWD/compression-private" \
  --binary "$PWD/aegis-evidence-inspect" \
  --out "$PWD/compression-evidence/corpus"
python experiments/commercial_compression/measure.py > "$PWD/compression-evidence/loc.json"
```

Use only the newly created disposable cluster. This harness never selects an
existing production kubeconfig. Its writer uses namespace RBAC; its observer has
Deployment GET permission. A shared installer manages local authority and the
audit archive. Admin drift/UID replacement schedules are explicitly outside the
governed writer profile. The declared authority is destination-local, not a
synchronously coupled global IAM revocation service.

The durable store retains an exact JSON Patch. Native UID/resourceVersion/image
and local-authority tests make its repeated delivery safe; never regenerate its
preconditions during recovery. An absent audit record does not prove no effect.
UNKNOWN never grants an arbitrary retry; `REPLAY_FROZEN_CAS` permits only that
unchanged guarded request when its additional native preconditions support it.

Process-death schedules exit after the API call commits but before any result is
retained or returned to the workflow. They model a lost workflow acknowledgement,
not packet-level TLS failure. Successful API audit events and fresh reads must
be retained; old signed observations fail a new relying-party challenge.

Public output contains signed evidence, public roots, questions, result reports,
timings and source counts. Never upload `compression-state` kubeconfig files,
`compression-private` credentials, or the clean workspace `private` directories.
Cleanup: `kind delete cluster --name compression-test`.

The corpus includes three shared evidence controls and five B-only mapping/wire
controls. The frozen registration remains unchanged; all corrections and the
seven timing-only source exclusions are listed in [AMENDMENTS.md](AMENDMENTS.md).
