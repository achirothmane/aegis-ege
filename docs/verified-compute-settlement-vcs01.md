# VCS-01 — Contradictory Compute Evidence Reconciliation

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

This experiment asks one bounded question:

> Can the existing domain-agnostic outcome primitive reconcile a compute contract
> when provider and tenant observations disagree, without adding GPU semantics to
> the governance kernel?

It is intentionally **not** a GPU scheduler, marketplace, billing engine,
monitoring product, attestation implementation, or legal SLA adjudicator.

## Contract fixture

VCS-01 uses an opaque measurable contract fact set:

```text
capacity.available = true
hardware.identity  = valid
metering.running   = true
```

The provider observation reports all three facts as satisfied.

The tenant-side observation reports:

```text
capacity.available = false
hardware.identity  = valid
metering.running   = true
```

The economic question is therefore not whether the hardware identity is valid
or whether metering is running. The unresolved point is whether the contracted
capacity was actually available.

## Required invariant

The contradictory trace must never produce:

```text
SETTLED
CREDIT_DUE
```

It must remain:

```text
DISPUTED
```

because one source matches the contract while another source diverges from it.

A missing required observed fact must remain:

```text
UNKNOWN
```

and convergent evidence is retained as the positive control:

```text
all sources MATCH                  -> SETTLED
all sources same contract breach   -> CREDIT_DUE
```

## Kernel boundary

The implementation deliberately reuses:

```text
internal/outcome.Compare
```

for opaque expected/observed fact comparison.

The compute adapter owns only the commercial disposition mapping:

```text
MATCH + MATCH       -> SETTLED
MATCH + DIVERGED    -> DISPUTED
UNKNOWN anywhere    -> UNKNOWN
same DIVERGENCE     -> CREDIT_DUE
different divergence-> DISPUTED
```

No changes are made to:

```text
kernel/
governedaction/
internal/outcome/
```

The kernel therefore does not learn the meaning of GPU model, topology, ECC,
NVLink, NCCL, token throughput, GPU-seconds, price, credits, or SLA terms.

## Claim boundary

VCS-01 is same-owner executable falsification. It does **not** count as D03
independent maintainer validation and does not modify the frozen governed-action
contract.

The source labels in this fixture describe provider-side and tenant-side
observations. VCS-01 does not yet prove that their failure domains are
independent in a real deployment. That is the next evidence problem and must be
bound by the existing evidence-composition dependency model rather than by a
caller-supplied `independent=true` flag.

VCS-01 also does not prove:

- correctness of GPU remote attestation;
- correctness of provider metering;
- legal enforceability of a service-credit rule;
- trustworthy clock synchronization;
- completeness of hardware/performance telemetry;
- invoice correctness.

## Success criterion

VCS-01 passes only if the executable tests show that contradictory delivery
evidence cannot silently settle and incomplete evidence cannot be upgraded to a
commercial conclusion.

If this passes without kernel changes, it is evidence for the **Complexity
Dividend** hypothesis: a financially consequential hardware/telemetry domain
can reuse the existing generic outcome semantics while keeping its business
meaning in the adapter.
