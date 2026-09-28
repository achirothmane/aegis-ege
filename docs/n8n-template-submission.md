# n8n template submission pack

This file is copy-ready material for submitting the EEP validation workflow to the n8n template library.

## Title

Evidence-gate an external customer update before mutation and verify the outcome

## Short description

Generate a structured runtime evidence envelope in n8n for a consequential customer-record update, then pass it to Aegis-EGE for evidence-bound authorization, external mutation, outcome verification, and tamper-evident journaling.

## What it demonstrates

```text
n8n runtime event
→ explicit authority/policy/redaction context
→ Evidence Packet
→ signed permit
→ external mutation
→ state reread
→ Outcome Evidence
→ journal
```

The included workflow does not infer organizational authority from observed behavior. It emits declared references that Aegis-EGE validates fail-closed.

## Intended audience

- AI/agent workflow builders
- platform and automation engineers
- teams evaluating high-consequence n8n actions
- security/governance engineers testing evidence-before-action patterns

## Setup

1. Import `examples/n8n/eep-live-validation.workflow.json`.
2. Configure Header Auth on the Webhook.
3. Publish the workflow.
4. Configure the Aegis-EGE live-validation secrets in a fork.
5. Run `EEP Live Validation`.

Full instructions: [Try EEP with n8n](try-eep-n8n.md).

## Evidence

The reference external validation completed with:

```text
PASS
APPLIED
journal_entries = 2
```

See [EEP external validation v1](eep-external-validation-v1.md).

## Suggested categories / keywords

```text
AI
DevOps
IT Ops
Security
Governance
Webhook
Evidence
Approval
Agent
Audit
```

## Boundary

This is an experimental validation workflow. It is not a production CRM integration and does not claim Salesforce or HubSpot compatibility.
