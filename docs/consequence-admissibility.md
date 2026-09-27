# Consequence admissibility at the commit boundary

Aegis-EGE separates three questions that are easy to collapse into one:

```text
Access
→ can the caller reach the tool?

Authority
→ is the caller allowed to request this action?

Consequence admissibility
→ is this exact consequence allowed to become real now?
```

The third question is evaluated immediately before the replay claim and mutation path.

## Current supported profile

The first deterministic policy is intentionally narrow:

```text
kind:              kubernetes.node_drain
action:            drain
target type:       kubernetes.node
consequence class: operational_state_change
```

The policy is identified by:

```text
policy_ref
policy_version
policy_hash
```

The admission record also carries:

```text
evaluated_at
action_scope_digest
```

so the execution receipt can prove which policy admitted which exact action scope.

## Commit-boundary ordering

When EBA enforcement is enabled, the mutation path is:

```text
authenticate caller
→ verify signed permit
→ match permit to outer intent
→ validate EBA conformance bundle
→ evaluate consequence admissibility
→ derive execution authorization
→ claim replay guard
→ execute guarded mutation
→ emit execution receipt + produced evidence
```

A consequence block happens before the replay claim. It therefore cannot consume a one-shot execution token and cannot reach the mutation controller.

## What the gate revalidates

The current deterministic consequence policy checks:

- supported intent kind;
- supported action;
- supported target type;
- permit temporal validity;
- exact binding between the Evidence Manifest and permit claims;
- Evidence Manifest observation time;
- maximum evidence age when configured.

These checks are additional to EBA conformance. They make the consequence boundary independently fail closed instead of assuming that access or authority alone implies permission to commit an external effect.

## Result

A successful evaluation produces:

```json
{
  "api_version": "aegis.ege/consequence/v0alpha1",
  "decision": "ADMISSIBLE",
  "consequence_class": "operational_state_change",
  "policy_ref": "aegis-ege/policy/kubernetes-node-drain-consequence",
  "policy_version": "v1",
  "policy_hash": "sha256:...",
  "evaluated_at": "2026-09-27T19:00:00Z",
  "action_scope_digest": "sha256:..."
}
```

If any mandatory predicate fails, execution returns:

```text
403 CONSEQUENCE_ADMISSIBILITY_BLOCKED
```

and no mutation is attempted.

## Execution receipt binding

For consequence-gated executions, the ExecutionReceipt embeds the admission record. Produced execution evidence also contains a digest of that admission.

This creates the chain:

```text
Evidence + assumptions + authority
→ consequence policy
→ ConsequenceAdmission
→ guarded mutation
→ ExecutionReceipt
→ produced evidence
```

Tampering with the receipt or the admission binding invalidates receipt integrity.

## Probabilistic evaluators are advisory

An LLM or secondary model may contribute evidence such as:

```text
estimated blast radius
risk classification
likely customer impact
```

but it is not the final authority at the commit boundary.

The final admission decision is deterministic and policy-bound:

```text
probabilistic model
→ evidence contribution

deterministic consequence gate
→ ADMISSIBLE / BLOCKED
```

This prevents a second probabilistic model from becoming the sole authorization source for an irreversible or externally binding action.

## Compatibility

The existing `eba.integration/v0.1` artifacts are not rewritten by this change.

Consequence admission is an additive Aegis-EGE boundary record with its own version:

```text
aegis.ege/consequence/v0alpha1
```

Legacy execution behavior remains unchanged when EBA conformance enforcement is disabled.
