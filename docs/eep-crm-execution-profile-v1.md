# EEP CRM execution profile v1

Profile: `aegis.eep/crm-http-json/v1`

This profile is the bounded automatic-mutation contract for the current synthetic
CRM path. It is intentionally stricter than a generic HTTP PATCH adapter.

## Signed execution binding

The Evidence Packet and signed Permit must bind the same:

- destination id;
- account id;
- base endpoint;
- adapter profile;
- expected resource version.

The executor is separately configured with the destination id, account id,
endpoint and profile. A request cannot select another endpoint or account by
changing only its plan payload.

The current profile uses the Permit's `resource_version` as the same expected
resource version bound inside `execution_binding`.

## Destination support required for automatic mutation

Before any PATCH, the executor performs:

```text
GET {base}/customers/{customer_id}
```

The response must expose:

- `ETag` — the conditional-write resource version;
- `X-Aegis-Destination-ID` — destination identity;
- `X-Aegis-Account-ID` — account identity.

The values must match the signed/configured execution binding.

PATCH is then sent to the same URL with:

- `If-Match: <expected resource version>`;
- `X-Aegis-Destination-ID`;
- `X-Aegis-Account-ID`.

HTTP redirects are not followed. A destination that cannot support the required
identity and conditional-write contract is not eligible for this automatic
profile.

A local lock is not treated as remote fencing. The conditional write must be
enforced by the destination itself.

## Durable attempt custody

Each signed Permit + customer-update plan produces one deterministic attempt id.

Before an external mutation can escape:

1. a durable local attempt claim is fsynced;
2. authorization is appended to the tamper-evident journal;
3. the destination precondition is read and validated;
4. a dispatch-intent EXECUTION journal entry is appended;
5. the attempt transitions durably to `POSSIBLE_EFFECT`;
6. only then may PATCH be sent.

Attempt states:

```text
CLAIMED
  ├─> BLOCKED
  └─> POSSIBLE_EFFECT
          ├─> BLOCKED
          ├─> ACCEPTED
          │      └─> COMPLETED
          └─> COMPLETED
```

A duplicate attempt id is rejected across process restarts. Claims are not reset
merely to recover availability.

## Ambiguous acceptance

If the request may have reached the destination but the response is lost, the
attempt remains `POSSIBLE_EFFECT`.

If a 2xx response is received but the post-mutation observation is unavailable,
the attempt remains `ACCEPTED`.

Neither case is automatically replayed.

The current C06 profile does not claim exactly-once delivery. It preserves one
attributable possible effect per signed attempt and blocks blind duplication.

## Known bounded outcomes

A destination HTTP 412 response to the If-Match write is treated as a definite
precondition rejection for this profile and transitions the attempt to
`BLOCKED`.

Other non-2xx responses are not assumed to prove that no effect happened.

## Recovery evidence

The durable attempt record contains:

- intent id;
- permit digest;
- plan digest;
- destination id;
- account id;
- endpoint;
- adapter profile;
- customer id;
- operation;
- expected resource version;
- observation handle;
- attempt state;
- timestamps and available HTTP/detail evidence.

The tamper-evident journal also records the attempt id, destination/account,
observation handle and attempt state around authorization, dispatch intent and
outcome.

## Migration

Older CRM execution permits without an `execution_binding` are readable as
historical artifacts but cannot authorize this automatic mutation path.

The external validation recorded in
`docs/eep-external-validation-v1.md` predates this profile and therefore does
not prove C06 destination/precondition or durable-attempt guarantees.

## What C06 does not prove

This profile does not prove:

- provider-independent exactly-once mutation;
- remote fencing for a provider that ignores If-Match;
- safe automatic failover to another CRM endpoint;
- universal replay recovery;
- verified intended postcondition.

The last item is owned by C07. C06 establishes bounded mutation admission and
attempt custody, not the final outcome oracle.
