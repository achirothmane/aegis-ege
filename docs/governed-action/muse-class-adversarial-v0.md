# Muse-class adversarial hardening v0

Status: **EXPERIMENTAL — non-normative hardening work**

This work does not change the frozen governed-action v1 oracle. It adds one
experimental execution-origin relation and registers a broader adversarial
corpus for agent-runtime failure classes.

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

## 3. Muse-class adversarial corpus

The machine-readable corpus is:

```text
governedaction/testdata/muse-class/corpus-v0.json
```

It contains M00-M15.

Current accounting is explicit:

| Coverage | Cases | Meaning |
|---|---:|---|
| EXECUTABLE_NOW | 3 | M00, M04, M05 execute against `CheckOrigin` in tests |
| EXISTING_COVERAGE | 4 | Existing kernel/recovery/anti-rollback work already exercises the class, but not through this new origin check |
| PARTIAL_EXISTING | 2 | Relevant machinery exists, but the full Muse-class property is not yet proved |
| PLANNED | 7 | Registered as attack classes only; they do not count as implemented controls |

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

## 4. Current executable claims

Only the following new claims are earned by this change:

1. exact execution-origin identity/provenance bindings can be checked without
   changing the frozen K01-K05 oracle;
2. an admitted origin may use a strict subset of its admitted capabilities;
3. source digest, trust domain, trust epoch, origin identity or type drift causes
   rejection;
4. silent capability expansion causes rejection;
5. unknown capability bits fail closed;
6. M00/M04/M05 are machine-registered and executed in the standalone shared
   library test suite.

This change does **not** yet prove:

- process/data taint propagation;
- secret surrogation or just-in-time credential injection;
- credential audience isolation;
- out-of-band human approval replay protection;
- DNS/redirect final-destination mediation;
- that a hostile process cannot bypass the effect-boundary enforcer;
- a Muse-compatible runtime;
- production-grade agent containment.

## 5. Next implementation order

Do not add all planned controls at once.

The next highest-value sequence is:

```text
Execution-Origin Trust
    ↓
Approval binding/replay corpus
    ↓
Credential-surrogate broker experiment
    ↓
Taint evidence producer
    ↓
Hostile-agent harness
```

Each step must add a failing attack schedule first, then an executable control,
then preserve the original positive path. A planned corpus entry must never be
counted as a passed control merely because it is documented.

## 6. Kill condition

This hardening effort is useful only if the same relation survives different
domains without embedding their business semantics.

If execution-origin enforcement requires a different core semantic model for
GitHub, Kubernetes, PostgreSQL and a fourth domain, the abstraction has failed
its complexity-dividend test and should not be promoted into the frozen kernel.
