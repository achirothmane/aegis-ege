# Agentic Workforce Domain v9

Status: **non-normative adversarial falsification experiment**

Classification: **synthetic adversarial workload — not a public incident replay, not an independent held-out cohort, and not D03 PASS evidence**

Public motivation signal:

- Le Figaro, 2026-10-01: an entrepreneur-facing platform described as using nine specialized AI assistants across business functions.
- The signal motivates the workload; it does not make the synthetic schedules below historical incidents.

## Question

Can the current domain-agnostic reduction govern a workforce of independently
authorized AI agents that can cause real external effects without adding Sales,
Finance, Marketing, CRM, or deployment semantics to the kernel?

The workload uses four radically different actions:

```text
Sales agent      -> send_email
Finance agent    -> issue_invoice
Developer agent  -> deploy_release
Community agent  -> publish_post
```

Each action is translated into the same current reduced basis:

```text
Identity
State
Constraint
Evidence
Transition
```

A mechanical capability may still be minted after admission.

## New adversarial distinction

The workload exposes a distinction that is easy to miss in a single-agent model:

```text
authority identity != external effect identity
```

Two different agents can each possess valid authority while still attempting to
realize the **same one external effect**.

The earlier experimental `EffectIdentity` intentionally includes subject identity.
That is useful for authority-scoped attempt identity, but it cannot by itself be
used as a cross-subject deduplication key.

If two authorized agents independently execute:

```text
agent:sales-primary -> send welcome email to lead-99
agent:sales-backup  -> send welcome email to lead-99
```

then two authority-scoped identities exist even though the domain declares one
external cardinality slot.

## Reduction

v9 does not add a semantic primitive.

The domain adapter supplies an opaque state fact:

```text
effect.slot = <domain-owned cardinality slot>
```

Examples in the corpus are values such as:

```text
outbound/email/welcome/lead-99
billing/invoice/9001/issue
deployment/prod-api/release-42
```

The evaluator does not parse these values.

A shared effect identity is derived from existing State + Transition bindings:

```text
effect.slot
+ target key
+ operation
+ from version/digest
+ to version/digest
        ↓
shared EffectSlotIdentity
```

Subject identity is deliberately excluded from this derived key. Subject
authorization is still checked independently by `EvaluateReducedAdmission`.

## Effect-boundary schedule

```text
Agent A admission ─┐
                   ├─> same trusted effect.slot
Agent B admission ─┘
                         ↓
                 durable RESERVED custody
                         ↓
                 both derive CROSSING
                         ↓
                 exact CAS at boundary
                    ┌────┴────┐
                    │         │
                  A wins    B fails
                    │
              external effect
                    │
          receipt missing / crash
                    ↓
                  UNKNOWN
                    ↓
        no blind cross-agent replay
                    ↓
       final provider observation
                    ↓
                  CLOSED
```

## Executable attacks

The test suite exercises:

1. all four agent classes through the same five-primitive reduced evaluator;
2. authority revocation before effect-boundary claim;
3. stale evidence;
4. two separately authorized subjects targeting one external effect slot;
5. concurrent claims from both agents, with exactly one CAS winner;
6. crash after boundary entry followed by a different authorized agent retry;
7. UNKNOWN remaining non-replayable without final provider evidence;
8. final exact provider observation resolving UNKNOWN to CLOSED;
9. distinct effect slots remaining independent;
10. missing trusted `effect.slot` failing closed.

## Claim boundary

If CI passes, the experiment earns only this bounded claim:

> For the modeled agentic-workforce schedules, Sales/Finance/Developer/Community
> actions can be represented through the same five semantic primitives, while
> cross-agent external-effect cardinality can be enforced by a derived opaque
> effect-slot binding plus ordinary custody/CAS machinery.

It does **not** claim:

- five primitives are mathematically minimal;
- every agent framework exposes a sufficient hard effect boundary;
- a local CAS is sufficient across disconnected enforcement sites;
- provider-side exactly-once behavior exists when the provider does not supply it;
- synthetic v9 schedules are public incident evidence;
- D03 independent validation.

## Run

```bash
go test ./experiments/primitivereduction
```
