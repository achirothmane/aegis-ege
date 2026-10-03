# Execution-origin admission — bounded profile experiment

Status: **DESIGN-VISIBLE, COOPERATIVE TEST EXPERIMENT**

Profile: `extension-origin-admission/experiment-v0.1`

This experiment asks whether the frozen candidate kernel contract can represent
execution-origin trust through its existing trusted Admission Profile,
ActionRevision, DecisionBasis and current-state bindings. It adds a separate
profile-specific interpretation for local extension activation/use. It does not
change the accepted/rejected meaning of any old profile or v1 oracle case.

## Motivation

An origin can supply instructions, tool declarations, hooks or executable code.
Discovery of those bytes is not an authenticated authority grant. A requester's
`trusted=true` or `may_execute_code=true` assertion cannot authorize activation.

Grok Build provides concrete examples of this boundary: its plugin trust code
blocks hooks, MCP servers and scripts for untrusted project plugins; its rewind
implementation appends a `RewindMarker` to the update log. These are engineering
inputs, not independent validation of this experiment:

- [Plugin trust](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-agent/src/plugins/trust.rs)
- [Rewind implementation](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-shell/src/session/acp_session_impl/rewind.rs)
- [Hook failure semantics](https://github.com/xai-org/grok-build/blob/main/crates/codegen/xai-grok-pager/docs/user-guide/10-hooks.md)

## Existing kernel relations used

| Origin obligation | Existing frozen relation |
| --- | --- |
| Exact origin/content/capability identity | ActionRevision + I1 |
| Owner-issued bounded grant and typed validator | DecisionBasis + AuthorityContext + I2 |
| No authority from self-declaration or discovery | I3 + trusted profile selection |
| Recheck content, policy, epoch and actor scope at activation and every use | K03 + I4 |
| Keep prior effect facts across data rewind; missing optional cost stays unknown | K04 + I6 |

The supporting rules are in `kernel-v1.md` sections 3–7, 13 and 14, and
`normative-vectors-and-change-control-v1.md` section 8. The new profile is a
different input; it is not a hidden mandatory obligation on every old profile.

## Profile-specific contract

The declaration identifies `origin_id`, `origin_type` and `source_ref`. The host
computes a SHA-256 digest of the fixture's canonical, sorted artifact snapshot.
The snapshot contains instructions, hook content, configuration and the exact
MCP server/tool descriptor. Duplicate and non-canonical artifact paths fail.

The trusted enforcing owner issues an Ed25519-signed grant binding:

- issuer, exact profile and validator version;
- actor, origin identity/reference/type and snapshot digest;
- one capability class: instructions, tools, hooks or code;
- the exact registry target and tenant namespace;
- policy hash, current revocation epoch and half-open validity interval.

The signature is verified against the boundary's owner-controlled public key.
A self-hash or repository-generated signature is not authority. Grant issuer
identity and signature alone are insufficient if another required binding is
stale, mismatched, unknown or outside the current actor's scope. Authority
expansion is not an extension capability in this profile; any additional grant
must be separately issued by the trusted owner.

Admission produces a profile-specific witness including the exact action
revision, source/grant digests, validator, policy and revocation epoch. It causes
no registry mutation. Activation checks current witnesses and records a local
registry entry. Invocation checks them again, including active registration.
Neither an old admission nor active registration bypasses revalidation.

Every mandatory failure denies new activation/use for both low and high
consequence labels. Missing optional cost telemetry remains absent; it neither
becomes zero nor disables an otherwise complete admission.

## Bounded evidence

The Go test-only harness verifies 27 fixture cases plus discriminating tests for
discovery/admission/activation separation, a fresh owner grant after source
change, dependency-snapshot identity and append-only data rewind. Decisions are
computed from signed bindings and current state, not copied from expectations.
Tests count actual fixture registry writes and invocations, including positive
useful behavior so deny-all cannot pass.

The rewind test appends a new transition referencing the earlier data snapshot.
It retains the old audit prefix, prior effect count and current authority epoch.
The restored registry data cannot make the old revoked grant authorize a use.

Run:

```sh
go test -race -count=1 -v ./internal/originadmissionexperiment
go test ./...
```

The existing K06 hash checks and K07 executions continue to protect all seven
frozen artifacts and all 28 normative traces. The experiment separately pins the
frozen oracle blob `37e2e0a0867fa78df37f9d4243a1c4107d62094b`.

## Current implementation context

The later standalone library already exposes `governedaction.CheckOrigin` for
exact provenance identity and capability-subset checks. This earlier experiment
is complementary: it exercises owner-issued signed grants, local activation/use,
and current authority after data rewind. Its harness does not call `CheckOrigin`
and is not evidence that a production loader verifies those grants. Production
integration must connect authenticated profile witnesses to the actual shared
boundary rather than use this fixture as a second runtime.

## Claim boundary and classification

Classification: **policy/profile specialization experiment**, subject to review.
No new shared kernel primitive is required to represent these bounded traces.
That is a representability result for this declared model, not proof that all
future origins or loaders can be governed by the same mechanism.

All evaluator/loader code is confined to `_test.go` files. Nothing in the runtime
imports or activates it. There is no production plugin/MCP loader, real process
execution, provider attestation, remote dependency fetch or credential grant.

The boundary is an in-memory cooperative registry protected by a local mutex.
Complete mediation, trustworthy owner configuration/clock and a complete declared
dependency snapshot are assumptions of the fixture. It does not demonstrate OS
enforcement, filesystem TOCTOU resistance, dynamically changing remote MCP
servers, distributed revocation, durable/tamper-resistant audit or independent
maintainer validation. It is not D03 evidence and does not reopen architecture
discovery or establish a platform kernel.

Production integration requires an independently justified loader boundary,
content-to-use binding, declared dependency coverage and revocation guarantees.
Any discovery that changes an old profile's valid traces or a shared core relation
must receive a separately versioned normative change record.
