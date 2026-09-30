# Kernel v1 Freeze — Issue-to-Evidence Checklist

Freeze ID: `candidate-kernel-contract-v1`  
Owner: `achirothmane`  
Status: **FROZEN BASELINE RECORD — K06**

This checklist maps the queue's required repairs/semantic items to the immutable evidence recorded by K06.

| Item | Required issue addressed | Evidence | Freeze disposition |
|---|---|---|---|
| C01 | legacy node-drain governance bypass | Aegis PR #68 head `774fb9ac...`, CI 36628899842 | COMPLETE |
| C03 | temporal validity / input shape | Aegis #69; WFL #110; EASL #13; AAG #11; assumption-gate #2; TGP #3 | COMPLETE |
| C04 | scope / authority trust | Aegis #70; WFL #111; AAG #12; assumption-gate #3 | COMPLETE |
| C05 | canonical representation / determinism | Aegis #71; WFL #112; AAG #13; assumption-gate #4; TGP #4 | COMPLETE |
| C06 | EEP mutation attempt binding/custody | Aegis #72 head `292a2faa...`, CI 36641503613 | COMPLETE |
| C07 | EEP intended outcome verification | Aegis #73 head `3f134274...`, CI 36643796577 | COMPLETE |
| C08 | Genesis assurance / current subject | Aegis #74 + EASL #14 | COMPLETE with bounded claims |
| C09 | evidence-independence claims | Aegis #75 head `716c6883...`, CI 36647979579 | COMPLETE |
| E01 | cross-language StateBinding conformance | EASL #8/#9, WFL #96, blob `82d15153...` identical | COMPLETE |
| K01 | revision/basis/profile binding | Aegis #76 | COMPLETE |
| K02 | effect/attempt/custody | Aegis #77 | COMPLETE |
| K03 | temporal/resumption semantics | Aegis #78 | COMPLETE |
| K04 | truthful closure / UNKNOWN | Aegis #79 | COMPLETE |
| K05 | normative vectors / change control | Aegis #80 + pre-freeze refinement #81; 28 frozen traces covering CE1–CE12 + positive seeds | COMPLETE |

## Freeze exclusions

These are not counted as prerequisites for candidate kernel contract v1:

- **C02** — ModFactory candidate verification; explicitly excluded from kernel evidence;
- **C10** — portfolio proof closeout; explicitly not required for this freeze;
- **K07** — executable frozen conformance; starts after K06;
- **D00–D06** — experiments/measurement/generalization after freeze as scheduled;
- **Aegis PR #64 / #65** — open and not counted as C08 protection;
- all Lxx extraction items.

## G checklist mapping

| G requirement | Evidence |
|---|---|
| Six concepts / five record families | `docs/governed-action/kernel-v1.md` |
| I1–I6 | frozen K01–K04 sections + K05 CE vectors |
| Trusted profile semantics | K01 + CE1 |
| Accepted/rejected vectors | `testdata/governed-action/v1/normative-cases.json` |
| Temporal/resumption | K03 |
| Effect/attempt | K02 |
| UNKNOWN/closure | K04 |
| Domain preservation | `domain-profiles-v1.md` |
| Version/change control | K05 oracle + change-control cases/template |
| Evidence provenance | freeze manifest exact commits/blob hashes/run IDs |

## Adversarial evidence checks

- stale CI result from another head: **not credited**;
- moving branch/tag used as immutable evidence: **not sufficient**;
- silently changed normative fixture: **detected by freeze blob-hash test**;
- open PR represented as protection: **PR #64/#65 explicitly excluded**;
- missing or inadequate profile requirement treated as sufficient: **CE1/CE9/K01 rejects**;
- contradictory expected verdict under one case ID: **K05 validator rejects**;
- trace-affecting “clarification” retaining v1 identity: **forbidden by frozen change-control rule**.

## Reviewer attribution

Actual attributed reviewer/merge authority:

- `achirothmane` — repository owner / contract steward / merge approver for cited prerequisite PRs.

No separate independent reviewer approval is represented.

## Freeze boundary

A PASS here means only:

> the candidate kernel contract v1 has an immutable, owner-reviewed normative baseline.

It does **not** mean:

- platform maturity;
- independent implementation;
- K07 executable conformance;
- D01/D02 real-substrate validation;
- D03 held-out generalization;
- commercial evidence.
