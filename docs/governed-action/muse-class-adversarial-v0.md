# Muse-class adversarial hardening v0

Status: **EXPERIMENTAL — non-normative hardening work**

This work does not change the frozen governed-action v1 oracle. It adds four
experimental hardening relations—execution-origin trust, bounded approval use,
opaque credential-use binding, and taint-aware egress—plus synthetic secret-broker
and taint-propagation experiments.

The purpose is not to reproduce Meta Muse or to claim parity with its runtime.
The purpose is to use the same class of hostile assumptions against the
governed-action kernel:

> the actor may be compromised, may create or install tools, may retry, may
> survive through child processes, and may attempt to turn local execution
> capability into a real-world effect.

## 1. New experimental relation: Execution-Origin Trust

The existing kernel already binds action revision, target/profile, authority,
custody, temporal validity, effect identity, observation and truthful closure.
It did not previously expose a small executable relation for this question:

> Did the code/instruction-bearing origin at the effect boundary remain the
> same origin that was admitted, without silently gaining runtime capability?

The experimental `governedaction.CheckOrigin` relation binds:

```text
origin_id
origin_type
source_digest
trust_domain
trust_epoch
capabilities
```

and enforces:

```text
UNTRUSTED_OR_CHANGED_ORIGIN
    => NO EFFECT BOUNDARY

CURRENT_CAPABILITIES - ADMITTED_CAPABILITIES != {}
    => NO EFFECT BOUNDARY
```

A capability subset is valid. A capability expansion requires a fresh
admission.

This is intentionally not a generic code scanner, signature verifier, identity
service, plugin registry, or policy engine. The adapter/profile must derive the
binding from trusted provenance. A self-reported digest or origin label is not
evidence.

## 2. Why this belongs beside the kernel rather than inside an agent

An agent can be allowed to write code, install a tool, or spawn a child process.
Those actions do not imply that the newly introduced origin automatically
inherits the authority of the already-admitted action.

The actor must not be able to create the mechanism that authorizes the actor.

The relevant separation is:

```text
Actor / Agent
    !=
Origin trust authority
    !=
Effect-boundary enforcer
```

The current experimental check only proves the relation supplied to it. Complete
mediation remains an enforcement-substrate responsibility.

## 3. Experimental relation: bounded approval use

Aegis already has signed `ApprovalAttestation` support that authenticates an
approver and binds intent/kind/target/action/resource-version/plan/expiry. The
Muse-class gap is different: an authentic approval must not silently become a
reusable capability at later effect boundaries.

The experimental `governedaction.CheckApprovalUse` relation binds:

```text
approval_ref
action_revision
effect_id
target
scope
nonce
max_effects
valid_until
```

and evaluates a trusted durable `effects_used` count supplied by the adapter.

For a one-time approval:

```text
max_effects = 1
effects_used >= 1
    => REJECT
```

Target, action revision, effect identity, scope, nonce, approval reference,
expiry and effect limit must remain exact.

This pure relation does not create a durable approval store. The adapter must
atomically charge approval use under its declared failure model and use native
transactions/CAS/fencing where concurrent consumers could race. Two callers
that both falsely present `effects_used=0` are outside the guarantee.

## 4. Experimental relation: opaque credential use

`governedaction.CheckCredentialUse` binds an opaque credential handle to:

```text
handle_id
action_revision
effect_id
audience
destination
scope
trust_epoch
valid_until
```

Raw credential bytes are intentionally absent from this relation. A changed
effect identity is treated as replay outside the admitted effect. Audience and
destination are separate bindings so a connector cannot silently request a
credential for another logical audience while retaining the same network
endpoint.

The experimental `internal/secretbroker.HTTPBroker` exercises the next layer:

```text
untrusted caller
    ↓ opaque handle + bound request
broker
    ↓ CheckCredentialUse
    ↓ exact destination check
    ↓ JIT Authorization injection
network
```

The caller-facing request has no raw-secret field. The broker rejects caller
supplied Authorization/Proxy-Authorization headers, does not follow redirects
with the injected credential, and sanitizes the returned response request so the
injected Authorization value is not recoverable through `resp.Request`.

This proves interface/boundary behavior in a synthetic HTTP process. It does not
prove production secret isolation while actor and broker share an OS protection
domain. A production implementation still requires a separate broker
process/VM, authenticated IPC, protected bootstrap secret storage and complete
mediation.

## 5. Experimental relation: taint-aware egress

`governedaction.CheckTaintEgress` binds an egress decision to a trusted taint
monitor identity and epoch:

```text
subject_ref
monitor_ref
monitor_epoch
allowed_labels
```

The observed evidence contains only:

```text
subject_ref
monitor_ref
monitor_epoch
labels
```

No sensitive payload is carried. Every observed label must be explicitly
admitted; an empty `allowed_labels` set means clean-only egress.

The companion `governedaction/taintflow` package is deliberately a synthetic,
monotonic propagation model for the adversarial corpus:

```text
sensitive read
  -> process taint

fork
  -> child inherits full parent taint set

process writes file/IPC channel
  -> channel accumulates process taint

process reads file/IPC channel
  -> reader accumulates channel taint
```

Labels are additive. A clean writer cannot erase an already-tainted channel.

A first Linux kernel artifact now exists at `kernel/bpf/aegis_taint.bpf.c`.
It contains:

```text
lsm/file_permission
tracepoint/sched/sched_process_fork
cgroup/connect4
cgroup/connect6
```

The LSM program unions configured source-file labels and propagated file labels
into per-process taint, propagates process taint into written files, and fails
the file operation closed if the required taint-state update cannot be recorded.
The fork tracepoint copies a parent's current label set into the child map. The
cgroup connect programs deny egress for a protected cgroup when propagation
uncertainty is non-zero or when process labels exceed the admitted cgroup
allow-mask.

CI compiles this object with `clang -target bpf`, and the Go side mirrors and
decodes its fixed ABI while refusing unmapped label bits.

A signed two-phase install path now also exists:

```text
release-signed taint manifest
        ↓
verify artifact digest + exact ELF program/map surface
        ↓
load LSM / fork tracepoint / connect4 / connect6
        ↓
pin programs + maps + BPF links
        ↓
signed local bootstrap receipt
        ↓
activation plan
        ↓
verify receipt + current boot + pinned links
        ↓
install source labels / allow-mask / uncertainty counter
        ↓
write protected-cgroup flag LAST
```

The install phase intentionally leaves the target cgroup inactive. A partial
install therefore cannot become taint enforcement authority. Activation writes
the protected-cgroup flag only after all source and fail-closed state is
initialized. A crash around that final boundary can be reconciled by reading the
protected-cgroup map.

This still does **not** prove production Linux kernel mediation. The loader and
activation path compile and have pure contract tests, but no privileged native
runtime test has yet shown that a BPF-LSM-enabled target kernel accepts all four
hooks and that a hostile real process cannot evade them.

## 6. Muse-class adversarial corpus

The machine-readable corpus is:

```text
governedaction/testdata/muse-class/corpus-v0.json
```

It contains M00-M15.

Current accounting is explicit:

| Coverage | Cases | Meaning |
|---|---:|---|
| EXECUTABLE_NOW | 10 | M00/M04/M05 origin; M06/M07 approval; M08/M09 credential; M01/M02/M03 taint and propagation |
| EXISTING_COVERAGE | 4 | Existing kernel/recovery/anti-rollback work already exercises the class, but not through this new origin check |
| PARTIAL_EXISTING | 2 | Relevant machinery exists, but the full Muse-class property is not yet proved |
| PLANNED | 0 | No M00-M15 case remains documentation-only; some remain existing/partial rather than newly executable |

### Registered cases

- **M00** exact admitted origin positive control.
- **M01** prompt injection attempts private-data exfiltration.
- **M02** tainted parent forks an apparently clean child.
- **M03** tainted data launders through file or IPC.
- **M04** the agent self-installs a different tool after admission.
- **M05** the same origin silently expands connector capability.
- **M06** a one-time approval is replayed.
- **M07** an approved target is substituted.
- **M08** a surrogate credential is replayed outside its effect boundary.
- **M09** a connector requests a credential for the wrong audience.
- **M10** an approved destination changes through redirect/resolution.
- **M11** the effect commits and the process loses the reply.
- **M12** takeover inherits a stale capability.
- **M13** runtime state is rolled back.
- **M14** provider acceptance contradicts the observed postcondition.
- **M15** a compromised actor attempts to disable the guard.

## 7. Current executable claims

Only the following new claims are earned by this change:

1. exact execution-origin identity/provenance bindings can be checked without
   changing the frozen K01-K05 oracle;
2. an admitted origin may use a strict subset of its admitted capabilities;
3. source digest, trust domain, trust epoch, origin identity or type drift causes
   rejection;
4. silent capability expansion causes rejection;
5. unknown capability bits fail closed;
6. an authenticated approval reference can be additionally bound to exact
   action/effect/target/scope/nonce/expiry/cardinality at the effect boundary;
7. a one-time approval presented after one durably charged effect is rejected;
8. approval target substitution is rejected;
9. an opaque credential handle is bound to exact action/effect/audience/destination/scope/trust epoch/expiry;
10. replay of the same handle under a different EffectIdentity is rejected before network dispatch;
11. credential audience substitution is rejected before network dispatch;
12. the synthetic HTTP broker injects a bearer credential only after the bound checks, rejects caller credential headers, does not follow redirects with the credential, and sanitizes the returned request metadata;
13. unbound taint labels fail closed at the egress relation;
14. forked children inherit the parent's complete synthetic taint set;
15. file/IPC-style channel transfer propagates taint to a previously clean reader;
16. a clean writer cannot erase channel taint;
17. M00-M09 are machine-registered and executable, while M10-M15 retain their
    existing/partial classifications;
18. the experimental Linux taint object compiles as BPF and exposes a fixed
    file/process/egress evidence ABI;
19. the kernel-side label bitset remains semantically opaque: userspace profile
    code owns bit-to-label meanings and fails closed on unmapped bits;
20. a signed loader validates the exact taint ELF surface before loading and
    exposes no unsigned taint-loader command;
21. programs, maps and links are pinned before a signed local bootstrap receipt
    is produced;
22. activation is a second phase: source labels, egress allow-mask and a zeroed
    propagation-uncertainty counter are installed before the protected-cgroup
    bit can be written.

This change does **not** yet prove:

- successful native loading/attachment of the Linux taint programs on a real BPF-LSM-enabled test kernel;
- a privileged end-to-end proof that file read -> fork/file propagation -> network denial occurs in-kernel;
- production Linux process/data taint observation and complete mediation;
- production-grade cross-process/VM secret isolation and authenticated broker IPC;
- out-of-band approval transport/authenticity beyond the existing signed-attestation machinery;
- atomic concurrent approval consumption without an adapter-native transaction/CAS/fence;
- DNS/redirect final-destination mediation;
- that a hostile process cannot bypass the effect-boundary enforcer;
- a Muse-compatible runtime;
- production-grade agent containment.

## 8. Next implementation order

Do not add all planned controls at once.

The next highest-value sequence is:

```text
Execution-Origin Trust
    ↓
Approval binding/replay corpus
    ↓
Credential-surrogate broker experiment
    ↓
Synthetic taint evidence + propagation
    ↓
Linux BPF-LSM/process/filesystem artifact + ABI
    ↓
Signed two-phase attach/pin + activation
    ↓
Privileged native hook test on BPF-LSM-enabled kernel
    ↓
Hostile-agent harness
```

Each step must add a failing attack schedule first, then an executable control,
then preserve the original positive path. A planned corpus entry must never be
counted as a passed control merely because it is documented.

## 9. Kill condition

This hardening effort is useful only if the same relation survives different
domains without embedding their business semantics.

If execution-origin enforcement requires a different core semantic model for
GitHub, Kubernetes, PostgreSQL and a fourth domain, the abstraction has failed
its complexity-dividend test and should not be promoted into the frozen kernel.
