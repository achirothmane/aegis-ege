# R01 Execution Status — Split-Brain Fulfillment

Status: SURVIVES_R01 — scoped executable falsification decision recorded

## Frozen rule

R01 must not modify the frozen v1 oracle to pass. The experiment ends only in one of:

- SURVIVES_R01
- COUNTEREXAMPLE_R01
- INCONCLUSIVE_R01

No test may hard-code the final verdict.

## Reality

One logical action, `FulfillOrder(order-731)`, crosses three independent effect boundaries:

1. E1 — PostgreSQL inventory reservation.
2. E2 — provider-A payment capture.
3. E3 — provider-B shipment creation.

Required compound truth:

`FULFILLED => EXACT(E1) && EXACT(E2) && EXACT(E3) && SAME_ACTION_LINEAGE && CURRENT_AUTHORITY_AT_EACH_REQUIRED_BOUNDARY`

## Current proof map

| Vector | Claim | Current executable evidence |
|---|---|---|
| R01-01 | possible E2 cannot be blindly replayed | frozen K07 CE3 projection + R01 independent vector |
| R01-02 | expired/revoked authority cannot silently authorize later E3 | production `decision.ValidateAuthorization` composition |
| R01-03 | stale worker cannot advance E3 without current exclusivity/authority | frozen K07 CE6 projection |
| R01-04 | duplicate callback must not create duplicate E3 or false certainty | PASS — PostgreSQL native-cardinality run 37058606097, source head 9e42c149709ee7e0c2fc01e89aded040c3ca9f2a |
| R01-05 | same aggregate value is not exact E2 lineage | frozen K07 CE7 projection |
| R01-06 | independent reversal of E1 prevents compound success | frozen K07 exact-postcondition relation |
| R01-07 | contradictory provider observations cannot mint authority or VERIFIED success | production `Evaluate` + `ReconcileContradiction` composition |
| R01-08 | clean exact trace remains useful | frozen K07 positive exact-postcondition case |

## R01-04 native experiment

The decisive schedule does not rely on permit expiry, an in-memory mutex, or process-local deduplication.

Two independent worker processes:

1. receive the same `ActionRef` and `EffectIdentity`;
2. independently observe current authority;
3. synchronize before the effect;
4. revalidate authority at the effect boundary;
5. concurrently execute a PostgreSQL destination mutation;
6. PostgreSQL enforces `PRIMARY KEY(effect_id)` with `ON CONFLICT DO NOTHING`;
7. evidence must show two valid callback deliveries but exactly one committed shipment row.

Pass condition:

`2 valid callback processes -> 1 durable effect row -> 1 winner`

A second durable row is a real R01-04 counterexample.

## Evidence discipline

The earlier process-local concurrency test is only a sanity check and is not sufficient to close R01-04.

The previous branch's constant `SURVIVES_R01` assertion was intentionally not carried forward.

R01-04 is now closed by native evidence:

- workflow run: `37058606097`
- source head: `9e42c149709ee7e0c2fc01e89aded040c3ca9f2a`
- artifact id: `11249667178`
- artifact digest: `sha256:585638e76c555cffc75779c1a71e407c93a498a28e1f98a4b4ec45e2148d3d1e`
- both workers held current authority before the race and at the effect boundary
- callback-a created no effect
- callback-b created the effect
- durable rows: 1
- winners: 1

## Whole-trace closure

R01-A was executed as one native schedule on source head `2c9c3a818dede1c8370fbd4c510856c82c7c7ef7`.

Evidence:

- PostgreSQL workflow run: `37060044985` — success
- artifact: `11249254001`
- artifact digest: `sha256:4a687e7bc0f5312871503b6e6bf8a81a6edfd3a9cbea37e27f10ed8f60e6f146`
- D04 run: `37060044877` — success
- CI run: `37060044754` — unit + KinD success

Whole-trace facts:

- E1 was initially present under exact lineage, then ended `REVERSED`.
- E2 provider acceptance survived caller exit `93` with no success receipt.
- the same old webhook was delivered twice.
- webhook evidence said `CAPTURED`; later provider API evidence said `NOT_CAPTURED`.
- an unrelated same-value effect preserved aggregate amount `73100`, demonstrating semantic ABA without exact lineage.
- old authority expired; takeover advanced to `worker-b`, fence `2`.
- two stale E3 attempts exited before mutation: `[41, 41]`.
- E3 durable rows remained `0`.
- exact compound postcondition remained false.
- production contradiction reconciliation minted no authorization.
- frozen K07 rejected false-verified and stale-takeover outcomes.

## Decision

`SURVIVES_R01`

This is a scoped decision for the registered R01 executable falsification reality. No frozen-oracle edit and no new normative relation were required.

It does **not** establish universal kernel correctness, production complete mediation, physical failure-domain independence across real external providers, or the Complexity Dividend. Those remain separate proof obligations.
