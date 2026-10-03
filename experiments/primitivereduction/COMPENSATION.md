# Compensation / Irreversibility Boundary v7

Status: **non-normative falsification experiment**

This experiment attacks the six-primitives candidate with a common distributed
failure mode:

```text
effect A -> CLOSED
effect B -> fails or becomes UNKNOWN
system wants to "roll back" A
```

The experiment rejects the fiction that a consequential effect can be erased by
rewinding local state.

## Core rule

```text
compensation != rollback
```

A compensation is a **new governed effect** with its own:

- Identity
- State
- Capability
- Constraints
- Evidence
- Transition
- effect custody
- possible UNKNOWN outcome

The original effect remains permanently part of history.

## Candidate reduction

The candidate basis remains:

```text
Identity
State
Capability
Constraint
Evidence
Transition
```

The experiment introduces only derived relations:

- **CompensationBinding** — evidence that one distinct effect is intended to
  compensate one truthfully CLOSED original effect;
- **CompensationStatus** — derived disposition:
  `NOT_JUSTIFIED | REQUIRED | UNKNOWN | CLOSED`.

Neither is a primitive.

## Safety rules

Automatic compensation is admitted only when:

1. the original effect is truthfully CLOSED;
2. the compensation is a different logical EffectIdentity;
3. the original/compensation relationship is evidence-bound;
4. the compensation itself passes ordinary admission;
5. the compensation owns its own RESERVED effect custody.

An UNKNOWN original effect is not automatically compensatable because the system
does not yet know whether the consequence actually occurred.

An UNKNOWN compensation never rewrites the original effect and never becomes
implicit replay permission.

## Executable corpus

Tests cover:

- GitHub, Kubernetes, and PostgreSQL original effects;
- compensation as a distinct logical effect;
- UNKNOWN original effect blocking compensation;
- stale compensation binding;
- foreign compensation effect substitution;
- self-compensation / same EffectIdentity rejection;
- compensation itself becoming UNKNOWN;
- closed compensation preserving original CLOSED history;
- partial multi-effect plan where only truthfully CLOSED effects may be
  compensated;
- primitive basis remaining exactly six.

## Irreversibility boundary

This round exposes another important claim boundary:

> the kernel can govern compensating actions, but it cannot make irreversible
> external history disappear.

If a destination offers no meaningful inverse/compensating action, the residual
effect remains real. "Rollback" is therefore never a kernel guarantee unless the
destination semantics themselves provide such a guarantee and the kernel has
evidence for it.

## Current bounded result

This attack does **not** force `Rollback`, `Compensation`, `Saga`,
`Inverse`, or `Irreversibility` to become fundamental primitives.

They remain derived semantics and destination-specific contracts over the same
six-primitives candidate.
