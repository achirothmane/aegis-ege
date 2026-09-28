# EEP live validation harness

Status: experimental validation path. This is not a production deployment recipe.

This harness turns the local n8n → EEP → permit → CRM → outcome → journal proof into a manually triggered run against external HTTPS endpoints.

It is outbound-only: GitHub Actions calls the n8n webhook and the CRM API. No tunnel or inbound access to the runner is required.

## Safety boundary

The workflow is manual and requires `confirm_live_mutation=true` before it runs.

The harness:

- reruns `go test ./...` before any external mutation;
- requires HTTPS for both external endpoints;
- refuses credentials embedded in URLs;
- reads secrets only from GitHub Actions secrets;
- never prints raw CRM state or the n8n evidence payload;
- prints only target identifiers, digests, workflow/execution IDs, outcome, and journal entry count;
- binds the exact n8n-derived Evidence Packet digest into the signed permit;
- binds the exact customer-update plan digest into the signed permit;
- journals authorization before the mutation;
- rereads the external CRM state after the mutation;
- creates verifiable outcome evidence from before/after state digests;
- requires a valid two-entry authorization + outcome journal before reporting `PASS`.

The live harness uses an ephemeral permit key and ephemeral journal key for each validation run. That is appropriate for validation only, not durable production key custody.

## Required GitHub Actions secrets

Configure these repository or environment secrets before running `.github/workflows/eep-live-validation.yml`:

| Secret | Purpose |
| --- | --- |
| `EEP_N8N_WEBHOOK_URL` | HTTPS n8n Webhook URL that returns the explicit EEP envelope |
| `EEP_N8N_AUTH_TOKEN` | Bearer token required by that n8n webhook |
| `EEP_SOURCE_PRINCIPAL` | Predeclared source identity for this validation workflow |
| `EEP_CRM_BASE_URL` | HTTPS base URL of the external CRM-style API |
| `EEP_CRM_BEARER_TOKEN` | Optional bearer token for the CRM API |
| `EEP_PATCH_JSON` | JSON object representing the one allowed customer patch |
| `EEP_N8N_TRIGGER_JSON` | Optional JSON body sent to the n8n webhook; defaults to `{}` |

`EEP_SOURCE_PRINCIPAL` is validation bootstrap context. It does not replace the mTLS identity rule of the Aegis n8n adapter for production ingress.

## n8n webhook contract

The n8n workflow may start from a Webhook Trigger and must return one JSON object shaped like:

```json
{
  "intent_id": "intent-live-1",
  "event_id": "evt-live-1",
  "workflow_id": "wf-customer-update",
  "execution_id": "exec-101",
  "agent_id": "agent-customer-ops",
  "observed_at": "2026-09-28T14:00:00Z",
  "action": {
    "kind": "crm.customer_update",
    "tool": "crm.http-json",
    "operation": "update_customer",
    "target": "customer/c-17",
    "side_effect": true
  },
  "data": {
    "ticket": "T-42",
    "customer": {
      "id": "c-17",
      "email": "alice@example.com"
    }
  },
  "authority_ref": "authority://crm/customer-update/v3",
  "policy_ref": "policy://agent-actions/v8",
  "redaction_profile_ref": "redaction://crm/pii/v4",
  "consequence_class": "customer-record-write",
  "control_refs": ["soc2:CC6.1"],
  "approval_refs": ["approval://ticket/T-42"],
  "sensitive_paths": ["/customer/email"]
}
```

Unknown JSON fields are rejected by the live harness. Missing authority, policy, redaction, consequence, or declared sensitive paths fail closed in the EEP compiler.

## CRM API contract

The external validation target is intentionally tiny:

```text
GET   {EEP_CRM_BASE_URL}/customers/{customer_id}
PATCH {EEP_CRM_BASE_URL}/customers/{customer_id}
```

`GET` must return a JSON object. `PATCH` receives exactly the JSON object stored in `EEP_PATCH_JSON` and must return a 2xx response. After PATCH, Aegis performs another GET and compares state digests.

The harness accepts an optional bearer token through `EEP_CRM_BEARER_TOKEN`. The workflow or evidence packet cannot choose the CRM base URL.

## Passing criterion

A run is evidence of external end-to-end behavior only if the command returns:

```json
{
  "status": "PASS",
  "outcome": "APPLIED",
  "journal_entries": 2
}
```

with non-empty packet, permit, and outcome digests.

A locally green CI run is not the same thing as external validation.

The first external run has now passed. See [EEP external validation v1](eep-external-validation-v1.md) for the recorded run, digests, result, and limitations.
