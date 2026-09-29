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

The GET route must return a JSON object representing current state and must also expose `ETag`, `X-Aegis-Destination-ID`, and `X-Aegis-Account-ID`.

The PATCH route must enforce `If-Match` against that ETag and reject stale writes with HTTP 412. It must also remain on the same destination; redirects are not part of the current automatic profile. The PATCH route must persist the supplied JSON patch so that a subsequent GET returns changed state.

A mock service that cannot enforce this conditional-write contract is useful for historical/read-only experimentation only; it does not satisfy the current C06 automatic mutation profile.

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
  "outcome": "VERIFIED",
  "journal_entries": 3
}
```

Use synthetic data only. Free mock endpoints may be public and are not a production security boundary.

Current C07 runs report `VERIFIED` only when the requested CRM patch fields are observed stably on the exact bound customer. Whole-state digest change and HTTP success are not sufficient.
