# Candidate Kernel Contract v1 — K06 Freeze Record

Status: **FROZEN SPECIFICATION BASELINE**  
Freeze ID: `candidate-kernel-contract-v1`  
Queue item: **K06 — Record the Kernel v1 Freeze Gate**  
Normative semantics parent: `b03147090870dc8f0c75213ebf0cb6679931d0e2`

This record freezes the K01–K05 candidate governed-action contract as **candidate kernel contract v1**.

It is a reproducible specification milestone. It is **not**:

- a demonstrated platform kernel;
- a runtime release;
- proof that all implementations conform;
- proof of held-out generalization;
- a new repository or shared service;
- evidence that K07 or D01–D06 have completed.

The immutable artifact identities and prerequisite evidence are recorded in
[`kernel-v1-freeze-manifest.json`](kernel-v1-freeze-manifest.json).

## 1. Freeze decision

**Decision: FREEZE — candidate kernel contract v1.**

The exact K06 prerequisite set is satisfied by merged, exact-head evidence for:

```text
C01
C03 C04 C05 C06 C07 C08 C09
E01
K01 K02 K03 K04 K05
```

The freeze does not count C02, C10, K07, D00–D06 or any Lxx item as complete.

The open Aegis PRs #64 and #65 are explicitly **not** counted as C08 protection or as part of this frozen baseline.

## 2. Normative frozen set

The frozen contract consists of these exact Git blobs:

| Artifact | Git blob SHA |
|---|---|
| `docs/governed-action/kernel-v1.md` | `3b45e4521b995f1cbf8d4523c426279a31052a80` |
| `docs/governed-action/domain-profiles-v1.md` | `a8bd83497e8420f1e4e98028fb74ed4a855e99e8` |
| `docs/governed-action/normative-vectors-and-change-control-v1.md` | `7d4b3a1cef0463cec0ca598095c5f61fb3833d28` |
| `testdata/governed-action/v1/schema.json` | `963c81fc4682d25cf7ee9442e178f3762ed8f6ef` |
| `testdata/governed-action/v1/normative-cases.json` | `37e2e0a0867fa78df37f9d4243a1c4107d62094b` |
| `testdata/governed-action/v1/change-control-cases.json` | `5de2a6e3d28ddd5a89b8bcf0635b636b631e7961` |
| `testdata/governed-action/v1/change-log-template.json` | `e2e1d0f711e5452b0dad852264a0493266bd6517` |

The case set remains versioned as:

```text
governed-action.normative-cases/v1
contract_status = FROZEN
```

Consumers must pin these immutable identities or an immutable commit containing
exactly these blobs. A moving branch/tag name is insufficient.

## 3. External semantic corpora pinned by the freeze

### Workflow Failure Lab

Pinned current reviewed main:

`d44bd4c47f8748bfca706a4c4833adf8ce940cf6`

Relevant immutable references include:

- `eba.integration/v0.1` documentation blob
  `8c846a9618351f6c38137198ae78aab841681bdc`;
- `eba.temporal/v1` vector blob
  `0a161956b19e16d6adaaf3fa2cbeb453a7ddbcc3`;
- `eba.context/v1` vector blob
  `6f3d062e5c02c8844142c72097bf86e85c034982`;
- `eba.canonical-json/v1` vector blob
  `99b13dbb634e3894aa6610c70e1f9820fc1c73d8`;
- vendored StateBinding vector blob
  `82d151531da6f98262de1e247658d89a8299c53c`.

### EASL

Pinned current reviewed main:

`7c4e1e28218853919d00362dc071e1eb6f61cc56`

StateBinding source vector blob:

`82d151531da6f98262de1e247658d89a8299c53c`

The EASL source vector and WFL vendored mirror are byte-identical by Git blob identity.

Aegis's actual module pin at freeze is:

`github.com/achirothmane/easl v0.0.0-20260928052341-f7e3b79c6892`

This freeze does not reinterpret StateBinding as a universal state snapshot or an atomic destination guard.

## 4. Prerequisite verification

### Aegis repair / semantic chain

| ID | PR | Exact reviewed head | Merge commit | CI |
|---|---:|---|---|---|
| C01 | #68 | `774fb9ac19949e599098526d4566b5074ea9700d` | `a4fb223caea1e03eea1939a2e0ad4974850653f3` | success — run 36628899842 |
| C03 | #69 | `31461753efd789744e81bdef64c7db85fc7d0163` | `718ce08c414f731912041121b57041ce7223aa4e` | success — run 36632755727 |
| C04 | #70 | `d8bb967035022c0b13823d30498730e41177b64c` | `3e591ec4ccf284e798b5f1668863831f3866167a` | success — run 36635400478 |
| C05 | #71 | `d24f40a47bcad34874f1ec81ae163554b7aeb1dc` | `f73524136514a3f93f37eab79ccf13476f782bcc` | success — run 36639136998 |
| C06 | #72 | `292a2faadb8e12d6f24b8b1064e62ba90fe33110` | `177a7a56ee8e572cb69e9c0e7a8e0d6e03c72234` | success — run 36641503613 |
| C07 | #73 | `3f1342749d0b83b3ef505f41e7f7d01b7070b548` | `b49e89ad17a62d0d81d6d3f34cab51f09e9332af` | success — run 36643796577 |
| C08 | #74 | `c483f2ba56db473e41117ffe3aa591ce01f206e2` | `339af9d1ce4b07640fecfea059115e7b4bbdf99d` | success — run 36645506966 |
| C09 | #75 | `716c6883b5a226698bac6dab57e87e42048d236d` | `0d94613e1a05ae467170e615633d79c31a309d36` | success — run 36647979579 |
| K01 | #76 | `5336bfbe67742c4bb9cc02f15367c8c893a1801b` | `86d5b2184ee2084d206280ad3069b6da4fbdb2f5` | success — run 36655718172 |
| K02 | #77 | `750545f58be6d2c287fe6cfb3aa4656a7fd10f75` | `8ba7ff710c3f75fe662ffd90f3569ecc81e98227` | success — run 36656752699 |
| K03 | #78 | `c0dbba3cd18f49a01f8b7315438e38f8b63553ef` | `b6d25fe39f98b0a253c25fd8758cdc928331dce2` | success — run 36658121460 |
| K04 | #79 | `2baf4eee3f1f28212fcd0461b34901502e866da7` | `6130e941437bc005ccc94006f9ff277edbcebd2f` | success — run 36658875888 |
| K05 | #81 (refines merged #80) | `cbcd30eaa4134ac736cc5790f54db3881ad2a91d` | `b03147090870dc8f0c75213ebf0cb6679931d0e2` | success — run 36660867843 |

K05 was published in #80 and then deliberately refined before freeze by #81. PR #81 CI ran on the exact refinement head after #80 was already in its base, exercising the integrated C01/C03–C09/K01–K05 chain plus CE9–CE12 and the strengthened oracle validator.

K06 itself must pass the repository's full CI again before merge.

### Cross-repository C03–C05 evidence

K06 also checked the distributed repair owners rather than treating the Aegis final consumer as the entire repair.

Recorded successful exact-head evidence includes:

- WFL C03 #110, C04 #111, C05 #112 — CI, Compatibility Matrix and Remote v1 Consumer E2E all successful;
- EASL C03 #13 — CI successful;
- Agent Action Guard C03 #11, C04 #12, C05 #13 — policy/RETEST CI successful;
- assumption-gate C03 #2, C04 #3, C05 #4 — CI successful;
- token-governance-protocol C03 #3 and C05 #4 — CI successful.

The exact heads/run IDs are preserved in the freeze manifest.

### E01 StateBinding evidence

E01 is frozen only for the already-earned StateBinding semantic slice.

Evidence includes:

- EASL PR #8 vector publication head
  `dce94c3b41f0662077b56de344fd505ab3f4d032`,
  CI run 36322393166 — success;
- EASL PR #9 consumer-proof documentation merged as
  `35addcbfe610345b2f97d9fec06a9dc63670505a`;
- WFL PR #96 Python conformance head
  `2127c52d277e60d0d695dd93aecf3c538a92f649`,
  CI / Compatibility Matrix / Remote v1 Consumer E2E all successful;
- current EASL/WFL vector blob identity
  `82d151531da6f98262de1e247658d89a8299c53c`;
- current repaired WFL C05 head also passed all three workflow suites;
- current repaired EASL C08 head passed CI;
- Aegis consumes EASL through the recorded real module pin.

No whole-platform sharing claim is derived from E01.

## 5. G Freeze Gate checklist

| Required content | Frozen evidence | Decision |
|---|---|---|
| Six concepts / five record families | `kernel-v1.md` | PASS |
| I1–I6 | K01–K04 relations + CE1–CE12 vectors | PASS |
| Trusted profile semantics | K01 sections + domain mappings + CE1 | PASS |
| Accepted/rejected example vectors | 28 K05 normative traces covering CE1–CE12 with useful positive counterparts and seed cases | PASS |
| Temporal/resumption semantics | K03 frozen section and mappings | PASS |
| Effect/attempt semantics | K02 frozen section and mappings | PASS |
| UNKNOWN/closure disposition | K04 frozen section and mappings | PASS |
| Domain preservation | CI/Kubernetes/EEP typed mappings; unsupported guarantees retained | PASS |
| Version/change control | K05 change-control document/cases/template | PASS |
| Evidence provenance | exact PR heads, merge commits, CI run IDs, external blob identities | PASS |

No unresolved acceptance-rule contradiction was found by the published oracle validator: one case ID cannot carry contradictory validity, CE1–CE12 each have rejected and useful positive counterparts, and rejected cases identify the violated invariant/domain rule.

## 6. Adversarial freeze checks

K06 explicitly rejects these evidence mistakes:

### Stale result from another revision

A workflow run is credited only to the exact head recorded in the manifest.

A successful run from a different revision is not substituted.

### Silently changed fixture after review

The normative artifact Git blob SHAs are frozen.

K06 CI recomputes Git blob identity from local bytes and compares it with the manifest.

### Pending PR described as merged protection

Aegis PR #64 and #65 remain OPEN and are explicitly excluded.

No claim in this freeze depends on them.

### Missing profile requirement disguised as optional metadata

The frozen K01 contract still requires every profile-mandatory predicate and rejects missing/unknown validators/profile versions.

CE1 remains a rejected trace for caller-selected empty/weaker obligations.

## 7. Review attribution

The actual repository identity attached to the cited prerequisite work is:

**achirothmane**

GitHub metadata for the cited Aegis and cross-repository prerequisite PRs shows the PRs authored by and merged by `achirothmane`.

For this freeze, that identity is attributed as:

- repository owner;
- Aegis contract steward;
- merge approver for the cited prerequisite PRs;
- owner/maintainer of the cited WFL/EASL/AAG/assumption-gate/TGP evidence.

**No independent reviewer is claimed.**

The freeze therefore establishes an owner-reviewed immutable baseline, not independent validation or independent implementability.

Independent held-out evidence remains a later D03 requirement.

## 8. Change process after freeze

The frozen v1 baseline is append-only in meaning.

If a proposed change:

- changes a core relation;
- changes `valid_trace` for the same interpretation/profile;
- adds a previously unstated rule needed to make a failing case pass;
- reinterprets an existing predicate/profile field;

then it is a **normative core change**, including when called a clarification.

Required response:

1. retain the v1 freeze record;
2. record the failing/motivating trace;
3. record old rule versus new rule;
4. issue a new normative version;
5. perform a new freeze before later held-out testing;
6. mark any cohort that informed the redefinition design-visible.

An implementation fix under the unchanged v1 oracle does not require semantic redefinition.

## 9. What this freeze permits next

K06 unblocks **K07 — execute the frozen conformance/counterexample vectors**.

This freeze by itself does not authorize external credentials or production mutations.

It also does not allow D03 to skip the other scheduled prerequisites: D03 still depends on K07, D00, D01 and D02 and on an independently selected bounded domain/participant after freeze.

## 10. Withdrawal / rollback

If the freeze manifest, prerequisite evidence or normative baseline is later shown defective:

- do not overwrite this record;
- explicitly mark the freeze withdrawn/superseded;
- preserve the old artifact identities and consumed-cohort history;
- repair under a new normative version when meaning changes;
- issue a new freeze record.

A missing future implementation result is not by itself a reason to reopen architecture discovery.
