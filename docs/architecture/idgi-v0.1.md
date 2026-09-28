# IDGI v0.1 — Intent-to-Doctrine Genesis Interface

Status: experimental specification
Layer boundary: Level -3 -> Level -2

## Purpose

IDGI is the only permitted translation boundary from external human intent and physical/external reality into a machine-governing doctrine.

It exists to prevent raw human prose, undocumented operator intent, or runtime interpretation from acquiring machine authority.

Core rule:

Intent not operationalized => intent has no machine authority.

## Boundary

Level -3 is an ontological substrate, not a runtime governance layer. It contains facts and authorities outside the machine-governed system:

- human creator intent and ethical commitments;
- physical and hardware limits;
- external legal, supply-chain, geopolitical, and macro-environmental conditions.

Level -2 begins only after those inputs have been operationalized, reviewed, ratified, and bound into a doctrine epoch.

## IDGI pipeline

Human / external input
-> constrained natural language
-> behavioral operationalization
-> ambiguity / adversarial interpretation review
-> axiom candidate set
-> formal invariant traceability
-> doctrine candidate
-> frozen visibility period
-> independent ratification
-> genesis signing ceremony
-> Doctrine Epoch 0

No stage may be skipped for an ACTIVE doctrine.

## Constrained Natural Language contract

Every operational axiom MUST define:

- axiom_id
- semantic_version
- normative_statement
- applies_when
- requires
- forbids
- failure_behavior
- permitted_exceptions
- authority_to_change
- rationale
- positive_cases
- negative_cases
- boundary_cases
- adversarial_cases
- formal_invariants

A statement that cannot produce observable positive and negative behavioral cases is not eligible to become a machine-governing axiom.

## Interpretation firewall

An axiom MUST NOT be ratified while multiple materially different operational interpretations remain unresolved.

AmbiguousAxiom => RewriteRequired

The formal engineer, AI system, runtime operator, or implementation is not allowed to choose one interpretation silently.

## Constitutional replacement

Doctrine is not modified in place.

Doctrine_n
-> proposal
-> frozen visibility
-> challenge / review
-> quorum ratification
-> activation pending
-> Doctrine_n+1

Any material change to a frozen proposal resets the visibility clock.

The constitutional kernel defining who may propose, ratify, halt, and restart cannot silently self-amend. A change to that kernel requires a new trust lineage / system identity and explicit migration.

## Emergency semantics

Protective pause and constitutional emergency halt are distinct.

Protective pause may be bounded and recoverable after fresh safety evidence.

Emergency halt is monotonic with respect to automatic recovery:

EMERGENCY_HALTED -/-> RUNNING by timeout alone.

Restart requires fresh evidence and independent restart authority.

## Historical evidence and compromised epochs

Historical evidence is never erased merely because an epoch is later compromised.

HistoricalEvidence != CurrentTrust

A decision record can remain CONFORMANT_AT_EXECUTION while the epoch is later marked COMPROMISED. Future authority from a compromised epoch is denied.

## Physical-reality input

Physical faults are modeled as threats and failure-domain assumptions, not as proofs of certainty.

Physical fault tolerance SHOULD combine:

- redundancy;
- hardware / implementation diversity where justified;
- independent failure domains;
- cross-checking;
- fail-closed behavior on unresolved divergence.

Diversity alone is not proof against common-mode failure.

## Bidirectional traceability

Every Level -1 invariant MUST trace to one or more Level -2 axiom IDs.

Every runtime decision evidence record SHOULD eventually be traceable in reverse:

runtime decision
-> formal rule
-> axiom ID
-> doctrine epoch
-> ratification / signing evidence

This permits auditors to answer which signed doctrine authorized or prohibited a concrete mutation.

## v0.1 deliberate limits

This version defines semantics and traceability only.

It does NOT yet:

- define canonical CBOR / Protobuf encoding;
- claim a completed threshold-signature ceremony;
- activate Doctrine Epoch 0;
- claim that natural-language ambiguity can be eliminated automatically;
- make TLA+ proofs claims about physical hardware correctness.

Binary canonicalization and threshold signing are downstream of validated semantics and model checking.
