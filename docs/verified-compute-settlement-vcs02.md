# VCS-02 — Independent Evidence Binding

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-01 proved that contradictory compute-delivery observations can reuse the
existing generic outcome comparison without adding GPU semantics to the kernel.

VCS-02 asks the next harder question:

> Can a settlement conclusion require evidence from materially independent
> failure domains rather than merely accepting two different source labels?

## Why VCS-02 exists

The following is not sufficient:

```text
provider-control-plane = AVAILABLE
tenant-observer        = AVAILABLE
```

if both observations ultimately depend on the same provider-controlled
metering API, credential, administrator, or observation path.

Two names are not two witnesses.

For a settlement-grade conclusion, the evidence sources must be bound to their
producer, observation path, subject, material dependencies, and assurance
class.

## Generic extraction

The independence evaluator previously lived inside the server evidence
composition path used during prepare/permit issuance.

VCS-02 exposed a second use of the same primitive after execution. Reusing the
server/prepare path with a synthetic permit would have been a false
generalization.

The experiment therefore extracts the existing logic into:

```text
internal/ege/evidence_composition.go
```

with the domain-agnostic contract:

```text
EvidenceSource[]
        +
EvidenceIndependenceRequirement
        ↓
EvidenceCompositionAssessment
```

The server prepare path delegates to this same primitive. Compute settlement
uses it directly after execution.

The extraction introduces no GPU, billing, price, SLA, NCCL, ECC, NVLink, or
topology semantics.

## VCS-02 binding rule

A settlement observation is admissible for conclusive reconciliation only when:

1. every observation maps one-to-one to an assessed evidence source;
2. source name, evidence digest, and observation time match;
3. every source declaration is bound to the required compute-execution subject;
4. the configured material dependency classes are covered;
5. the required independent-source count is established.

The initial profile requires:

```text
required independence = ASSERTED
minimum independent sources = 2
material dependency classes:
  administrative
  credential
  upstream
```

A shared physical facility is intentionally non-material in this bounded
profile. That does not claim facility independence; it means the profile is
testing control/observation independence rather than correlated hardware
failure.

## Executable cases

### VCS02-A — different labels, shared provider upstream

```text
provider-control-plane
  producer = provider
  path     = provider-metering-api
  upstream = provider-metering-api

tenant-observer
  producer = tenant
  path     = tenant-sidecar
  upstream = provider-metering-api  ← shared material dependency
```

Even if both observations say the contract was satisfied:

```text
AVAILABLE + AVAILABLE
```

the result must remain:

```text
UNKNOWN
```

because settlement-grade independence was not established.

### VCS02-B — materially separated observation paths

```text
provider:
  upstream = provider-metering-api
  admin    = provider
  credential = provider-metering

tenant:
  upstream = tenant-telemetry-store
  admin    = tenant
  credential = tenant-observer
```

With matching delivery observations:

```text
SETTLED
```

is allowed by the experiment.

### VCS02-C — independent contradiction

If the same independent sources disagree on availability:

```text
provider = AVAILABLE
tenant   = UNAVAILABLE
```

the result remains:

```text
DISPUTED
```

VCS-02 therefore does not turn independence into majority voting.

### VCS02-D — missing declaration

Different labels without a complete independence declaration remain:

```text
UNKNOWN
```

### VCS02-E — post-assessment evidence substitution

If an observation digest differs from the digest whose independence was
assessed, settlement remains:

```text
UNKNOWN
```

This prevents an independently assessed source from being replaced after the
assessment by unbound evidence.

## Kernel / platform boundary

VCS-02 does not change:

```text
kernel/
governedaction/
internal/outcome/
```

It makes one horizontal refactor: the existing evidence-independence algorithm
becomes reusable outside the prepare/permit server path.

This is a more honest Complexity Dividend result than pretending the old API
already fit settlement perfectly:

```text
VCS-01: zero kernel change
VCS-02: one generic primitive extraction
        zero compute semantics added to the primitive
```

## Claim limits

VCS-02 is same-owner executable falsification. It does not prove that a real
tenant-side observer is physically or organizationally independent from a real
GPU provider.

`ASSERTED` means the deployment profile has declared the relevant dependency
scope and the algorithm found no shared material dependency inside that scope.
It is not a universal proof of physical independence.

A future stronger experiment may require `CORROBORATED` declarations backed
by independently reviewable topology, credential, administrative, or
attestation evidence.

VCS-02 also does not establish invoice correctness, legal enforceability, clock
trust, complete hardware telemetry, or performance-delivery truth.
