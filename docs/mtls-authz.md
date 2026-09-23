# M8 — mTLS caller identity and API authorization

M8 turns the M7 daemon from a read-only network surface into an authenticated mutation boundary.

## Identity

Production mode requires mutual TLS.

Caller identity is taken only from a verified client-certificate URI SAN.

Example:

spiffe://company.example/agents/remediator

Common Name is not used as identity.

A certificate with zero or multiple URI SAN identities is rejected.

## Authorization

Authorization is default deny and separates two permissions:

- PREPARE
- EXECUTE

The daemon loads a JSON ACL.

Example:

{
  "principals": {
    "spiffe://company.example/agents/planner": ["PREPARE"],
    "spiffe://company.example/agents/operator": ["PREPARE", "EXECUTE"]
  }
}

A PREPARE-only caller cannot invoke EXECUTE.

## TLS requirements

Normal daemon mode requires:

- server TLS certificate;
- server TLS key;
- trusted client CA;
- authorization file.

TLS minimum version is TLS 1.3.

For local development only, --insecure-read-only allows HTTP without mTLS. It cannot be combined with --enable-mutations.

## Mutation enablement

Real mutation mode requires all of the following:

- mTLS authentication enabled;
- an Authorizer;
- a durable checkpoint store;
- a replay guard;
- --enable-mutations explicitly set.

The daemon refuses unsafe combinations at startup.

## Replay boundary

M8 adds a durable single-daemon execution replay guard.

Before the mutation controller is called, the exact state-bound authorization is hashed over:

- ActionID;
- action;
- target;
- resourceVersion;
- evidence digest;
- plan digest;
- expiry.

The first execution atomically claims that authorization.

Any later attempt with the same authorization returns:

409 EXECUTION_REPLAY_REJECTED

The claim survives process restart because it is stored on disk.

This is intentionally fail-closed. If a request is claimed and the process crashes during execution, the same authorization is not reusable; recovery must proceed through the recovery path and fresh authorization.

M9 will replace local checkpoint/replay state with shared HA state.

## Audit identity

Authentication and authorization decisions are emitted through the security audit sink with:

- caller principal;
- requested permission;
- method/path;
- allow/deny;
- StateLatch decision when available;
- action ID;
- node name;
- reason codes.

The default daemon uses structured slog output.

M10 will bind production audit identity into the externalized tamper-evident journal/key-custody boundary.

## Live proof

The KinD integration proof:

1. creates a real mTLS client identity;
2. grants it PREPARE + EXECUTE;
3. prepares a state-bound node-drain authorization;
4. executes the authenticated drain;
5. verifies the Node becomes unschedulable;
6. replays the same authorization;
7. requires HTTP 409 EXECUTION_REPLAY_REJECTED.

This proves that network mutation is no longer reachable without the M8 identity/authorization boundary.
