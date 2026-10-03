# VCS-03 — Attested Hardware Identity + Observation Continuity

Status: **EXPERIMENTAL / HELD-OUT COMMERCIAL DOMAIN CANDIDATE**

VCS-01 proved conservative reconciliation of contradictory compute-delivery
evidence.

VCS-02 proved that matching source labels cannot manufacture settlement-grade
independence when the evidence sources share a material failure domain.

VCS-03 asks a different question:

> Can an execution receipt remain bound to the exact attested hardware identity
> and topology admitted for its compute lease, so that a stale receipt or
> observed hardware substitution cannot silently settle?

## Scope

This experiment does not implement NVIDIA Remote GPU Attestation, DCGM, NVML,
NVLink discovery, or provider APIs.

Instead it introduces a compute-adapter attestation envelope whose hardware and
topology are opaque digests:

```text
SignedHardwareIdentityAttestation
├─ subject
├─ sequence
├─ hardware_set_digest
├─ topology_digest
├─ evidence_digest
├─ verifier_id
├─ observed_at
└─ valid_until
```

The signature is verified through the existing EGE `PermitAuthority /
SignatureVerifier` interface. The compute adapter owns the meaning of the
hardware and topology digests.

## Lease binding

A compute lease binds:

```text
lease_id
subject
contract_digest
hardware_set_digest
topology_digest
admission_attestation_digest
starts_at
ends_at
```

The execution receipt then binds:

```text
receipt_id
lease_id
contract_digest
hardware_set_digest
topology_digest
admission_attestation_digest
completion_attestation_digest
started_at
finished_at
```

This creates the intended chain:

```text
Compute Contract
      ↓
admitted hardware attestation
      ↓
HardwareLeaseBinding
      ↓
execution
      ↓
completion hardware attestation
      ↓
ComputeExecutionReceipt
      ↓
independent evidence reconciliation
      ↓
SETTLED | DISPUTED | CREDIT_DUE | UNKNOWN
```

## VCS03-A — stale receipt after observed hardware substitution

Admission is bound to:

```text
hardware = A
topology = T1
```

The original receipt also binds a completion attestation for A/T1.

At settlement, fresh signed evidence reports:

```text
hardware = B
topology = T1
```

The old receipt carries the old completion-attestation digest.

Required result:

```text
UNKNOWN
```

The receipt cannot be paired with a different fresh hardware observation.

## VCS03-B — rewriting the receipt does not rewrite the lease

A stronger substitution attempt changes the receipt's completion-attestation
binding to the fresh B/T1 attestation.

The admitted lease is still bound to A/T1.

Required result:

```text
UNKNOWN
```

A new receipt cannot make substituted hardware inherit an old hardware lease.

## VCS03-C — topology substitution

The hardware-set digest remains A but the completion evidence reports:

```text
topology = T2
```

while the lease admitted T1.

Required result:

```text
UNKNOWN
```

This prevents a receipt for an admitted topology from silently settling a
different observed topology.

## VCS03-D — stable attested identity

When:

```text
admission hardware = A
completion hardware = A

admission topology = T1
completion topology = T1

receipt bindings match
attestation signatures verify
observation timing is bounded
VCS-02 evidence independence is satisfied
commercial facts match
```

the positive control may produce:

```text
SETTLED
```

## VCS03-E — observation too far from execution

A valid signed completion attestation collected long after execution completion
does not prove what hardware was present at the execution boundary.

The bounded profile therefore uses:

```text
MaxCompletionProbeLag
```

and returns:

```text
UNKNOWN
```

when the observation is outside that window.

## Reused primitives

VCS-03 reuses:

```text
EGE PermitAuthority / SignatureVerifier
VCS-02 EvidenceCompositionAssessment
VCS-02 evidence binding
VCS-01 outcome reconciliation
```

No change is made to:

```text
kernel/
governedaction/
internal/outcome/
internal/ege/
```

The entire hardware contract remains in:

```text
internal/computesettlement/
```

This is the desired Complexity Dividend shape: the domain becomes stronger by
composing existing generic trust/evidence primitives rather than by teaching the
kernel what an H100, NVLink fabric, ECC counter, or GPU topology means.

## Important claim boundary

Two endpoint attestations do **not** prove mathematically that no transient
hardware substitution happened between the observations.

VCS-03 proves a narrower property:

> A substitution that appears in the attested settlement evidence, an
> attestation/receipt binding mismatch, a topology mismatch, or an observation
> outside the configured temporal boundary cannot silently produce SETTLED.

A stronger continuity claim would require one or more of:

- continuous or periodic attestation;
- a hardware-rooted monotonic event/measurement chain;
- provider-independent telemetry continuity;
- workload-bound device identity measurements;
- cryptographically chained topology/assignment events.

Those are candidates for later falsification, not claims made by VCS-03.

## Commercial relevance

The property being tested is deliberately settlement-facing.

A buyer should not accept:

```text
"the receipt says the contracted hardware ran"
```

when the current attested execution evidence is bound to a different hardware
set or topology.

The system therefore preserves:

```text
evidence before settlement
```

rather than treating a provider-issued receipt as final truth.
