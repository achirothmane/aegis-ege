# EEP external validation v1

Status: **PASS**

Observed at: **2026-09-28T16:39:40Z**

GitHub Actions run:

https://github.com/achirothmane/aegis-ege/actions/runs/36451992526

## What ran

This validation crossed real external network boundaries:

```text
GitHub Actions
→ n8n Cloud production webhook
→ EEP Evidence Packet compilation
→ evidence-bound signed permit
→ external Beeceptor stateful CRM mock
→ GET before state
→ PATCH customer/c-17
→ GET after state
→ Outcome Evidence
→ tamper-evident journal
```

The customer record was synthetic. The external CRM endpoint was a stateful Beeceptor mock, not Salesforce, HubSpot, or a production customer system.

## Result

```json
{
  "status": "PASS",
  "target": "customer/c-17",
  "outcome": "APPLIED",
  "journal_entries": 2,
  "n8n_workflow_id": "r847zPYjnld62IZo",
  "n8n_execution_id": "1"
}
```

The run emitted three independently bound digests:

```text
packet_digest  = sha256:04f8cdb4546940e67d70ccf226f8e464f1c3ba1602187a2d4959e32afa358022
permit_digest  = sha256:d8daed57ac5d108ebbcd700e0a2c84562e5ca18d85d91ebfce53d7e384c72e34
outcome_digest = sha256:cd8d50798083942a2dc61dfabc443f5e261ff528ea4156cca5f34235d840e7c0
```

## What this proves

The run demonstrates that the current EEP path can operate across external services rather than only in-process test servers.

It proves one complete externally executed chain where:

- n8n produced the runtime envelope;
- EEP compiled a redacted Evidence Packet;
- the exact packet digest was bound into a signed permit;
- the exact mutation plan digest was signed before mutation;
- authorization was journaled before the external PATCH;
- the target state was reread after mutation;
- before/after state digests changed;
- Outcome Evidence verified;
- the tamper-evident journal contained exactly two entries: authorization + outcome.

## C06 migration note

This run predates `aegis.eep/crm-http-json/v1` and remains valid historical
evidence for the older external chain only. It does **not** establish the C06
guarantees for destination/account binding, ETag conditional mutation, durable
attempt claiming, redirect rejection, or ambiguous-response replay blocking.

A new external validation under the C06 profile requires a target that exposes
the required destination/account identity headers and enforces If-Match.

## What this does not prove

This is **technical validation, not business evidence**.

It does not prove:

- production readiness;
- Salesforce or HubSpot compatibility;
- durable production key custody;
- production-grade secrets management;
- production rollback semantics;
- customer demand;
- willingness to pay;
- repeat usage by an independent user.

The next product gate is therefore not another adapter. It is **independent external usage**.

## Implementation note discovered by the live run

The originally exported n8n workflow used Webhook node `typeVersion: 2.2`. The user's n8n Cloud workspace rendered that imported node as unavailable. Replacing it with the native Cloud Webhook node worked, and the importable example is now pinned to the more conservative Webhook `typeVersion: 2`.

This is an example of evidence changing the artifact rather than forcing the environment to match the artifact.
