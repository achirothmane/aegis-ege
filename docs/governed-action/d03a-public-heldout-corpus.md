# D03-A — Public held-out incident corpus falsification v1

Status: **ACTIVE — SUPPLEMENTAL HELD-OUT FALSIFICATION, NOT D03 PASS**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

## Purpose

D03-A removes external-maintainer response latency from the **unseen-case
generalization** work. It selects public incidents only after the K06 freeze and
maps their externally documented root causes/fixes into the already frozen K07
boundary evaluator.

It does **not** replace the independent-implementation requirement of D03.

## Evidence rule

Each corpus entry must have:

1. an external repository not owned by `achirothmane`;
2. a closed public incident with a concrete consequence;
3. public root-cause evidence;
4. a public fix, fixed release, or maintainer-confirmed corrected behavior;
5. a kernel mapping written only after freeze;
6. an expected historical disposition derived from the unchanged frozen
   relations;
7. where a fixed counterpart exists, a positive mapping showing the contract
   does not collapse into deny-all.

The public incident is ground truth for what happened. The mapping into kernel
facts is authored by us and is therefore **not** independent implementation
evidence.

## v1 corpus

The first batch contains six incidents across three structurally different
areas:

- OpenMeter: migration-baseline completeness and concurrent billing-result
  attribution;
- Hatchet: redelivery/idempotency, lost completion observation causing duplicate
  child work, and exact durable cancellation identity;
- Infisical: migration rollback state ownership.

The exact issue/fix references and merged commit identities are recorded in
`testdata/governed-action/d03a/corpus-v1.json`.

## Execution

The test harness builds a safe baseline `k07Input`, applies only the
incident-specific fact overrides, and sends the result through the same
`evaluateK07` function used by K07.

The corpus is therefore forbidden from:

- adding a D03-specific evaluator;
- changing evaluator ordering to fit an incident;
- changing the frozen oracle;
- relabeling a failed mapping after seeing the result;
- claiming that external maintainers implemented the contract.

For every historical unsafe trace the evaluator must produce the preregistered
safety disposition. For every fixed counterpart it must produce the
preregistered useful disposition.

## Falsification rule

If a well-grounded public incident exposes a material safety distinction that
the frozen relations cannot express without a new semantic rule, D03-A records
that as a **falsification failure**. The case is not repaired by editing v1.

If the incident is merely outside the contract's declared claim scope, it is
recorded as out-of-scope rather than counted as a pass.

## Relationship to D03

D03-A can support:

- unseen-case generalization evidence;
- cross-domain counterexample coverage;
- discovery of missing frozen distinctions.

D03-A cannot support:

- independent implementability;
- maintainer independence;
- the D03 PASS gate by itself;
- D04 unblocking by itself.

The existing D03 readiness state remains `BLOCKED_UNSTARTED` for the
independent-participant requirement while D03-A runs in parallel.

## v1 selection integrity

Selection occurred after K06/K07/D01/D02 and after the frozen oracle identity
was fixed. None of these incidents may be used to silently redesign
`candidate-kernel-contract-v1` before evaluation.

Normative change: **NO**  
Runtime change: **NO**
