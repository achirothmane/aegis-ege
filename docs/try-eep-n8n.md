# Try EEP with n8n

This path exists to collect **independent usage evidence**.

It reproduces the externally validated chain with synthetic data:

```text
n8n
→ Evidence Packet
→ signed permit
→ external CRM-style mutation
→ state reread
→ Outcome Evidence
→ tamper-evident journal
```

The reference external run is recorded in [EEP external validation v1](eep-external-validation-v1.md).

## What you need

- an n8n instance (Cloud or self-hosted);
- a fork of this repository;
- an HTTPS endpoint that implements:

```text
GET   /customers/{customer_id}
PATCH /customers/{customer_id}
```

A stateful mock is enough only if it can expose destination/account identity headers and enforce ETag/If-Match conditional mutation. Use synthetic data only.

## 1. Import the n8n workflow

Import:

```text
examples/n8n/eep-live-validation.workflow.json
```

Configure the Webhook node as:

```text
method: POST
path: aegis-eep-live
authentication: Header Auth
respond: Using Respond to Webhook Node
```

Use an `Authorization` header with a bearer token and publish the workflow.

## 2. Prepare a synthetic CRM target

The default target is:

```text
customer/c-17
```

Initialize it to a synthetic state such as:

```json
{"id":"c-17","tier":"standard"}
```

The validation patch changes the tier to `gold`.

## 3. Configure GitHub Actions secrets in your fork

Required names:

```text
EEP_N8N_WEBHOOK_URL
EEP_N8N_AUTH_TOKEN
EEP_SOURCE_PRINCIPAL
EEP_CRM_BASE_URL
EEP_CRM_DESTINATION_ID
EEP_CRM_ACCOUNT_ID
EEP_CRM_EXPECTED_RESOURCE_VERSION
EEP_PATCH_JSON
EEP_N8N_TRIGGER_JSON
```

Optional:

```text
EEP_CRM_BEARER_TOKEN
```

Do not commit secret values.

Recommended non-secret values:

```text
EEP_SOURCE_PRINCIPAL             = spiffe://aegis-ege.live/n8n
EEP_CRM_DESTINATION_ID            = synthetic-crm-1
EEP_CRM_ACCOUNT_ID                = synthetic-account-1
EEP_CRM_EXPECTED_RESOURCE_VERSION = <current ETag>
EEP_PATCH_JSON                    = {"tier":"gold"}
EEP_N8N_TRIGGER_JSON              = {"requested_tier":"gold","ticket":"T-42"}
```

For `EEP_N8N_AUTH_TOKEN`, store only the raw token. The validation harness adds `Bearer ` itself.

## 4. Run

In GitHub:

```text
Actions
→ EEP Live Validation
→ Run workflow
→ confirm_live_mutation = true
```

A successful independent run should end with:

```json
{
  "status": "PASS",
  "outcome": "APPLIED",
  "journal_entries": 3
}
```

and non-empty packet, permit, and outcome digests. The current profile also requires that the mutation was conditionally guarded at the destination and that the durable attempt record prevented duplicate dispatch.

## 5. Report the result

Open an **EEP independent validation** issue in this repository.

PASS, FAIL, setup friction, or a decision not to continue are all useful evidence.

The product gate is not "more features." It is whether someone other than the author can reproduce the value without private assistance.
