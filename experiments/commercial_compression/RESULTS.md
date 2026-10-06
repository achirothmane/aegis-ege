# Commercial compression result

Status: **C0 — stop the commercial asset track for this proposition**

Frozen registration: `PREREGISTRATION.md`  
Pinned baseline: `04434db12fa0c85d3497faf6ebb40df937092c5d`  
Qualifying workflow: `Bounded commercial compression #4` / run `37265407983`  
Evidence artifact: `commercial-compression-evidence`  
Artifact SHA-256: `98f34fa7fa01d9069d143e0e7967366e4eb80cacb5f3d2a7da3ab64f286ae81e`

This result applies only to the registered Kubernetes Deployment desired-image release/recovery workflow and the unchanged Aegis evidence consumer used by the experiment. It is not a claim that every Aegis capability lacks value.

## Decision

The pre-registered C3 gate is not met. The Aegis integration preserved correctness, but did **not** remove at least 50% of a major recurring reconciliation/recovery engineering-cost dimension. In the measured workflow it added integration work and runtime/setup overhead relative to the respectable purpose-built ordinary checker.

Under the frozen decision rule, the correct disposition is therefore **C0**:

> preserve the research/code as portfolio IP, stop this commercial asset track, and do not add features or select another narrative to obtain a win.

No customer, willingness-to-pay, adoption-cost, or paid-reuse evidence was established, so C4 was unavailable by definition.

## Correctness

Both implementations received the same destination capabilities, trust material, failure schedules and independent evidence.

Across all 13 registered schedules:

- same closure disposition: **13/13**;
- same retry disposition: **13/13**;
- same current-truth result: **13/13**;
- false CLOSED: **0**;
- unsafe retry: **0**;
- recovery-created duplicate logical effects: **0**;
- unauthorized governed image effects: **0**.

The three shared evidence controls also failed closed for altered signature, wrong independent question and UID replacement.

The Aegis-specific compatibility controls rejected a mismatched native observation, wrong root, claim downgrade, wrong retained request and altered evidence bundle.

The Aegis Kubernetes projection remains explicitly **SIMULATION grade**. This experiment does not claim a new native Kubernetes production profile.

## Engineering cost

### Custom integration source

Using the pre-registered Black-24.8.0 physical-LOC method:

| Metric | Ordinary | Aegis |
|---|---:|---:|
| Common required glue | 231 LOC | 231 LOC |
| Variant-specific checker / mapper | 52 LOC | 218 LOC |
| Total custom integration | **283 LOC** | **449 LOC** |
| Gross source total | 290 LOC | 456 LOC |

Aegis custom integration was **58.66% larger**, not smaller.

Even a hypothetical zero-cost Aegis adapter could save at most **18.37%** of this registered integration because most work is common native/evidence/recovery plumbing. That is below the 50% C3 threshold before considering real mapping cost.

### Recovery workflow

| Metric | Ordinary | Aegis |
|---|---:|---:|
| Programmatic recovery stages | 7 | 9 |
| CLI invocations per recovery | 0 | 2 |
| Operator recovery actions | 0 | 0 |

The two Aegis-specific stages were:

1. map/sign library wire evidence and policy;
2. derive library declaration fields using the existing consumer.

No operator-step reduction was demonstrated.

### Destination-specific tests

| Metric | Ordinary | Aegis |
|---|---:|---:|
| Custom cases / controls | 17 | 22 |

Aegis required five additional compatibility controls. Existing generic Aegis tests remain reusable assets, but they did not remove the native destination-specific test burden in this workflow.

### Configuration / trust

Both variants required the same 13 manual destination/evidence settings:

`admin_kubeconfig`, `worker_kubeconfig`, `observer_kubeconfig`, namespace, Deployment, container, image, audit archive, journal, observer root, relying-party challenge, grant epoch and grant generation.

Aegis additionally required the Aegis binary path plus generated wire/policy fields for schema/build/case/profile/policy/claims/keys/history. The admission/execution/destination roles reused one root, so these labels are not counted as extra independent trusted signers.

No material privilege reduction was demonstrated. Both variants relied on the same Kubernetes RBAC/admission boundary, native CAS, audit archive, independent observer root and durable journal.

## Time measurements

The clean runner used fresh workspaces, venvs, namespaces, journals, observer keys and challenges. Two paired runs reversed A/B order.

### Clean setup to first justified effect

- Ordinary: 5.496 s, 5.389 s; mean **5.442 s**
- Aegis: 10.912 s, 10.960 s; mean **10.936 s**
- reduction: **-100.95%** (Aegis took about 2.0x as long)

The infrastructure provisioning interval was common and separately measured at **40.808 s**.

### First effect execution after setup

- Ordinary mean: **1.057 s**
- Aegis mean: **1.086 s**
- reduction: **-2.78%**

### Clean recovery measurements

First recovery:

- Ordinary mean: **55.96 ms**
- Aegis mean: **65.14 ms**
- reduction: **-16.42%**

Second recovery:

- Ordinary mean: **52.77 ms**
- Aegis mean: **62.02 ms**
- reduction: **-17.52%**

Across the ten normal/non-availability-heavy registered paths, ordinary recovery averaged **49.53 ms** and Aegis **57.43 ms**. Timing is not the decision criterion, but it supplies no compression evidence.

### Second operation

Both implementations reused their existing code with:

- marginal custom LOC: **0 / 0**;
- one new destination-specific case each;
- zero new destination settings;
- only image + operation label changed.

Mean execution:

- Ordinary: **159.4 ms**
- Aegis: **169.4 ms**

This is a reuse tie, not an Aegis advantage.

## What the experiment did establish

The unchanged Aegis evidence consumer can be integrated into a real native Kubernetes release/recovery experiment while preserving conservative effect-finality judgments across the registered failure corpus. Its reusable evidence semantics are technically real.

What it did **not** establish is the economic proposition under test: that this library materially compresses the recurring engineering required by a capable team already using native destination guarantees and a purpose-built evidence/recovery checker.

For this workflow, the native substrate plus a small ordinary checker was the stronger substitution.

## Final commercial disposition

**C0.**

Do not add features to this track in an attempt to cross the threshold after seeing the result. Do not rename the same proposition and repeat the experiment in another domain merely to search for a favorable outcome.

Retain the code, corpus and evidence as research/portfolio IP. A future commercial revisit requires **new external evidence** that changes the economic premise — for example, a real buyer repeatedly paying to avoid this integration/reconciliation work — rather than another internal implementation comparison.
