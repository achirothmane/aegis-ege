# StateLatch daemon API

M7 introduces the first long-running StateLatch HTTP daemon.

The production goal is to separate callers/agents from direct Kubernetes mutation credentials and give them a narrow API surface.

## M7 safety boundary

The `state-latchd` binary is **read/prepare only** in M7.

It exposes:

```text
GET  /healthz
POST /v1/node-drains/prepare
POST /v1/node-drains/execute
```

but the executable configures:

```text
mutations_enabled = false
```

so `/execute` returns:

```text
503 MUTATIONS_DISABLED
```

and cannot invoke the mutation controller.

Authenticated mutation enablement is deferred to M8 so the first network daemon cannot accidentally expose unauthenticated cluster mutations.

## Prepare request

```json
{
  "action_id": "drain-2026-09-23-001",
  "node_name": "worker-7"
}
```

The caller does **not** submit policy knobs.

Drain policy is owned by the daemon. This prevents a caller from weakening controls such as:

- blast-radius limit;
- evidence age;
- DaemonSet handling;
- unmanaged Pod handling;
- emptyDir deletion;
- authorization TTL;
- execution lock settings.

Unknown request fields are rejected.

## Prepare response

The response is an explicit API DTO containing:

- decision;
- reason codes;
- snapshot;
- deterministic execution plan;
- plan digest;
- short-lived state-bound authorization when ALLOW is reached.

The API does not expose Go implementation structs as its JSON contract.

## Execute request

The execute endpoint accepts:

```json
{
  "node_name": "worker-7",
  "authorization": {
    "action_id": "...",
    "action": "drain",
    "target": "node/worker-7",
    "resource_version": "...",
    "evidence_digest": "...",
    "plan_digest": "...",
    "valid_until": "..."
  }
}
```

Before it can call the controller, the API checks that the authorization is for the requested node drain.

The controller still performs the authoritative live revalidation.

## Request hardening

M7 includes:

- strict JSON decoding;
- unknown-field rejection;
- maximum request body size;
- request timeout;
- HTTP read/write/header/idle timeouts;
- graceful SIGINT/SIGTERM shutdown.

## Running

Inside Kubernetes:

```bash
go run ./cmd/state-latchd
```

Outside Kubernetes:

```bash
go run ./cmd/state-latchd --kubeconfig ~/.kube/config
```

Then:

```bash
curl http://127.0.0.1:8080/healthz
```

M7 is not yet the production mutation API. M8 must add caller authentication and authorization before the daemon binary is allowed to enable mutations.
