# n8n → EEP adapter v1

Status: experimental, opt-in.

The adapter gives an n8n workflow a stable HTTP contract for compiling a runtime event into an Aegis-EGE Evidence Packet.

It deliberately does not depend on n8n's internal execution database or undocumented payload shapes. An n8n HTTP Request node sends an explicit JSON envelope to Aegis.

## Enable

The adapter is disabled by default.

```text
--enable-n8n-eep-adapter
```

It requires Aegis authenticated transport. A workflow cannot self-assert its principal identity in JSON; Aegis derives the principal from the authenticated request context.

Endpoint:

```text
POST /v1/eep/n8n/compile
```

The caller needs the existing `PREPARE` permission.

## Request contract

```json
{
  "intent_id": "intent-crm-1",
  "event_id": "evt-1",
  "workflow_id": "wf-crm-sync",
  "execution_id": "exec-77",
  "agent_id": "agent-crm",
  "observed_at": "2026-09-28T03:59:58Z",
  "action": {
    "kind": "crm.customer_update",
    "tool": "salesforce",
    "operation": "update_customer",
    "target": "customer/c-17",
    "side_effect": true
  },
  "data": {
    "customer": {
      "id": "c-17",
      "email": "alice@example.com"
    },
    "ticket": "T-42"
  },
  "authority_ref": "authority://crm/customer-update/v3",
  "policy_ref": "policy://agent-actions/v8",
  "redaction_profile_ref": "redaction://crm/pii/v4",
  "consequence_class": "customer-record-write",
  "execution_binding": {
    "destination_id": "crm-primary",
    "account_id": "acct-1",
    "endpoint": "https://crm.example.test",
    "adapter_profile": "aegis.eep/crm-http-json/v1",
    "expected_resource_version": "\"rv-17\""
  },
  "control_refs": ["soc2:CC6.1"],
  "approval_refs": ["approval://ticket/T-42"],
  "sensitive_paths": ["/customer/email"]
}
```

Sensitive paths are RFC 6901 JSON Pointers and fail closed if a declared path is absent.

## Response

A successful response contains an `aegis.ege/evidence-packet/v0alpha2` packet. It binds the authenticated caller principal, n8n workflow/execution IDs, intent/action identity, declared authority/policy/redaction context, optional execution binding, redacted evidence, provenance, and a deterministic SHA-256 digest.

For the current CRM automatic-mutation profile, the execution binding is later required to match the signed Permit and the executor's configured destination/account/endpoint/profile. The compile endpoint records proposed context; it does not itself grant mutation authority.

## Identity rule

```text
workflow says "I am admin"
!=
authoritative identity
```

The adapter never accepts `principal_id` from the request body. A compromised workflow therefore cannot forge the authority provenance of its own evidence merely by changing JSON.

## n8n wiring

```text
Trigger / AI Agent
→ construct explicit EEP envelope
→ HTTP Request: POST /v1/eep/n8n/compile
→ Evidence Packet
→ evidence-bound authorization
→ side effect
→ outcome evidence
→ tamper-evident journal
```

The n8n ingestion boundary now feeds the bounded CRM side-effect profile documented in [EEP CRM execution profile v1](eep-crm-execution-profile-v1.md). Compilation remains distinct from mutation admission: the returned packet must still be bound into a signed Permit and satisfy the executor's destination/precondition/attempt-custody checks before an effect can escape.
