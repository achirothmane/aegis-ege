# Attested Workload Admission v1

Remote attestation is not useful as an execution control if an `ALLOW` decision is merely written to disk and workload activation can ignore it.

This layer turns the signed TPM + IMA decision into a one-shot workload activation capability.

## Control chain

```text
TPM + IMA evidence
      |
      v
SignedRemoteAttestationDecision(ALLOW)
      |
      v
WorkloadAdmissionRequest
      |
      v
Admission Authority
      |
      v
SignedWorkloadAdmissionGrant
      |
      v
host verifies exact bindings
      |
      v
atomic one-shot grant consumption
      |
      v
CLONE_INTO_CGROUP
      |
      v
workload starts inside protected cgroup
      |
      v
SignedWorkloadActivationReceipt
```

## Why the remote decision is not used directly

A remote attestation decision proves a host state for a short time window. It does not itself specify which workload may start.

The admission grant adds exact execution bindings:

```text
device_id
workload_id
workload_spec_digest
target_cgroup
target_cgroup_id
bootstrap_digest
remote_decision_id
remote_decision_digest
issuer_id
not_before
expires_at
```

A valid attestation for one device, one bootstrap, or one workload cannot be replayed for another target without causing a signature or binding failure.

## Workload specification

The workload launch specification binds:

```text
absolute executable path
arguments
working directory
complete environment supplied to the child
Linux privilege-isolation profile
```

The environment is normalized by variable name before hashing so map/order differences do not alter the digest.

The workload process receives exactly the environment listed in the spec. It does not silently inherit the parent environment.

For the production-style Linux launcher, the signed spec must also include:

```text
linux_isolation.mode = user-namespace-v1
linux_isolation.host_uid = non-root host uid
linux_isolation.host_gid = non-root host gid
```

This isolation object is part of `WorkloadLaunchSpecDigest`. Removing it or
changing the host UID/GID after admission therefore invalidates the signed
workload binding.

## Freshness

The admission authority verifies the signed remote attestation decision before minting a grant.

The decision must:

- have a valid verifier signature;
- be `ALLOW`;
- bind the same `device_id`;
- bind the same signed bootstrap digest;
- not be too old;
- not be unreasonably in the future.

The grant expiry is capped by the remaining attestation freshness window:

```text
grant_expires_at =
  min(now + grant_ttl,
      remote_verified_at + max_attestation_age)
```

A grant can never extend trust beyond the accepted remote-attestation age.

## Exact cgroup identity

A cgroup path alone is not sufficient because a path can be replaced or redirected.

The admission request therefore records both:

```text
target_cgroup
target_cgroup_id
```

On Linux, `target_cgroup_id` is the inode identity of the cgroup v2 directory.

At activation time Aegis:

1. verifies that the path is on cgroup v2;
2. opens the target cgroup directory;
3. obtains the inode from the opened file descriptor;
4. compares it to the signed grant;
5. keeps that file descriptor open through process creation.

This prevents a path/symlink substitution from silently redirecting the workload after grant issuance.

## Atomic process placement

The launcher uses Go/Linux `SysProcAttr.UseCgroupFD` and `CgroupFD`.

That path uses Linux clone-into-cgroup semantics, so the child is created inside the authorized cgroup rather than:

```text
start process
then
move PID into cgroup
```

There is no intentional pre-enforcement execution window.

## Host privilege separation

When `linux_isolation.mode` is `user-namespace-v1`, the launcher creates a
fresh Linux user namespace and mount namespace while cloning directly into the
authorized cgroup. UID/GID 0 inside the workload namespace map to the explicit
non-root host UID/GID signed into the workload specification.

The result is deliberate authority separation:

```text
governed workload namespace root
        !=
host initial-user-namespace root
        !=
BPF / cgroup / host-mount enforcement authority
```

The privileged native M15 harness exercises the actual
`StartAttestedWorkload` path and verifies that the isolated hostile process
cannot remove pinned enforcement links, mutate protected-cgroup state, escape
the protected cgroup, or join the host mount namespace. Host-side activation
remains present after the hostile workload exits.

`aegis-attested-run` fails closed when `linux_isolation` is absent. The
lower-level library retains an unisolated path for compatibility/internal
experiments, but that path does not earn the M15 privilege-separation claim.

This does not claim containment after compromise of host root or the initial
user namespace itself.

## One-shot grant consumption

After every non-mutating validation succeeds, the host consumes the grant with an atomic `O_EXCL` durable claim.

Exactly one concurrent activation attempt can win.

Consumption is terminal.

If process creation fails after the grant was consumed, the grant is **not reopened**. Recovery requires a fresh admission grant. This mirrors the execution-capability rule used elsewhere in Aegis: ambiguity does not recreate authority.

## Activation receipt

After successful process creation, the host signs:

```text
activation_id
grant_id
grant_digest
device_id
workload_id
workload_spec_digest
target_cgroup
target_cgroup_id
process_id
started_at
```

with the host attestor key.

The resulting `SignedWorkloadActivationReceipt` provides a cryptographic handoff from admission authorization to actual workload start.

## Key separation

Three authority roles remain separate:

```text
remote attestation verifier
  -> signs host-state ALLOW/BLOCK

workload admission issuer
  -> signs workload-specific grant

host attestor
  -> signs activation receipt
```

A remote verifier is therefore not automatically granted the ability to choose arbitrary workloads, and a host cannot self-issue workload admission.

## Commands

### 1. Define the workload spec

Example:

```json
{
  "executable": "/usr/local/bin/my-worker",
  "args": ["--serve"],
  "working_dir": "/var/lib/my-worker",
  "environment": [
    {"name": "MODE", "value": "production"}
  ],
  "linux_isolation": {
    "mode": "user-namespace-v1",
    "host_uid": 65534,
    "host_gid": 65534
  }
}
```

### 2. Host: create admission request

Use the bootstrap digest already present in the remote attestation decision:

```bash
go run ./cmd/aegis-admission-request \
  -device node-01 \
  -workload payments-worker \
  -spec workload-spec.json \
  -cgroup /sys/fs/cgroup/aegis/payments-worker \
  -bootstrap-digest sha256:<bootstrap-receipt-digest> \
  -out workload-admission-request.json
```

The command reads the live cgroup inode and binds it into the request.

### 3. Admission authority: issue one-shot grant

```bash
go run ./cmd/aegis-admission-issue \
  -request workload-admission-request.json \
  -remote-decision remote-attestation-decision.json \
  -remote-verifier-pub remote-verifier.pub \
  -issuer-key admission-authority.key \
  -issuer-id prod-workload-admission \
  -out workload-admission-grant.json
```

### 4. Host: start the workload

```bash
sudo go run ./cmd/aegis-attested-run \
  -grant workload-admission-grant.json \
  -issuer-pub admission-authority.pub \
  -spec workload-spec.json \
  -consumption-dir /var/lib/aegis/consumed-workload-grants \
  -device node-01 \
  -host-attestor-key host-attestation.key \
  -receipt workload-activation-receipt.json
```

The command waits for the child and propagates its exit code. The signed activation receipt is written immediately after a successful start.

## Failure semantics

The following fail before grant consumption:

```text
invalid grant signature
expired grant
wrong device
workload spec mismatch
wrong target cgroup path
wrong target cgroup inode
non-cgroup-v2 target
invalid executable
invalid working directory
missing linux_isolation in aegis-attested-run
invalid/root host uid or gid in linux_isolation
```

The following happen after terminal consumption:

```text
kernel process-creation failure
receipt signing failure after process creation
```

If receipt signing fails after start, Aegis kills the newly started child rather than leave an admitted workload without an activation artifact.

If the CLI cannot persist the signed receipt, it also kills the child.

## Current boundary

Implemented:

```text
remote decision verification
freshness cap
workload-specific signed grant
bootstrap/device binding
workload spec digest
exact cgroup path + inode binding
one-shot durable grant claim
atomic clone-into-cgroup start
signed user-namespace privilege isolation
non-root host UID/GID mapping bound into workload spec digest
production-style CLI fails closed without linux_isolation
signed activation receipt
concurrent replay rejection
```

Not yet implemented:

```text
Kubernetes scheduler/admission-controller integration
distributed/linearizable grant-consumption backend
container image digest / OCI manifest specialization
systemd unit specialization
host-root / initial-user-namespace compromise containment

```

## Lifecycle continuation

Workload exits are now governed by a separate lifecycle layer. Every governed run emits a signed exit receipt and moves a durable ledger from RUNNING to EXITED. Any later activation requires an explicit signed restart decision and a newly issued one-shot admission grant.

See [workload-lifecycle-governance.md](workload-lifecycle-governance.md).

## Governing invariant

> No protected workload activation is authorized merely because a host once passed remote attestation. Activation requires a fresh, verifier-backed, workload-specific, one-shot grant bound to the exact cgroup identity and exact launch specification.
