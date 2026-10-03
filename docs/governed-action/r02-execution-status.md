# R02 Execution Status — Failure-Domain Separation

Status: SURVIVES_R02 — scoped executable falsification decision recorded.

R02 moved the R01-style compound action across distinct runtime/storage boundaries without changing the frozen v1 oracle:

- E1: PostgreSQL service container.
- E2: provider-A HTTP process with its own durable file store.
- E3: provider-B HTTP process with its own durable file store.

The decisive schedule demonstrated:

- provider A durably accepted E2 and exited before acknowledgement;
- provider A became unavailable while provider B remained healthy;
- provider B advanced its native destination fence from 1 to 2;
- stale E3 at fence 1 reached provider B and was rejected with HTTP 409;
- provider A restarted from its own store and recovered E2 as CAPTURED;
- the same old webhook event was delivered twice;
- PostgreSQL independently reversed E1;
- provider A later returned NOT_CAPTURED for exact E2 while an unrelated same-value effect preserved aggregate 73100;
- provider-B clean control at fence 2 created one durable shipment, and the duplicate created none;
- exact compound postcondition remained false;
- production contradiction reconciliation minted no authorization;
- frozen K07 CE6, CE7 and CE10 remained unchanged.

Evidence:

- source head: `92c53d167ea285c5feb55af406c682f99c904df9`
- PostgreSQL run: `37090111863` — success
- artifact: `11261977575`
- artifact digest: `sha256:dfd08ac60df3df9696e752ebcaa713aa03c122d59078d382db69dfdab876fa97`
- D04 run: `37090111832` — success
- CI run: `37090111827` — unit + KinD success

Decision: `SURVIVES_R02`.

Scope limit: these are independent process/storage/network boundaries on one CI host. The next stronger falsification must separate administrative/physical failure domains rather than merely processes on the same host.
