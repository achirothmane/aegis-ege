# Free external validation setup

This document describes the non-secret setup for the first external EEP validation.

## n8n

Import:

```text
examples/n8n/eep-live-validation.workflow.json
```

The workflow exposes a POST webhook and returns a strict EEP envelope for the synthetic customer target `customer/c-17`.

Before publishing the workflow, configure Header Auth on the Webhook node and keep the credential outside source control.

## Stateful CRM mock

A free stateful mock service can satisfy the validation contract with two routes:

```text
GET   /customers/:customer_id
PATCH /customers/:customer_id
```

The GET route must return a JSON object representing current state. The PATCH route must persist the supplied JSON patch so that a subsequent GET returns changed state.

Initialize `customer/c-17` to a synthetic baseline such as:

```json
{"id":"c-17","tier":"standard"}
```

The validation patch should change the synthetic tier to `gold`.

## Pass condition

The manual EEP Live Validation workflow is successful only when it reports:

```json
{
  "status": "PASS",
  "outcome": "APPLIED",
  "journal_entries": 2
}
```

Use synthetic data only. Free mock endpoints may be public and are not a production security boundary.
