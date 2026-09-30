# D03 — held-out readiness gate

Status: **BLOCKED / UNSTARTED**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

This record does **not** select a held-out cohort and does not claim independent
validation. It records that the engineering prerequisites are complete while
the operational prerequisite for D03 is not yet satisfied.

## Engineering prerequisites

The queue dependencies are satisfied by the following merged evidence:

| Item | Repository | PR | Merge |
|---|---|---:|---|
| K06 | `achirothmane/aegis-ege` | #83 | `b3fb4da1fe26511be806cf8a959e2aa3bd6b6a65` |
| K07 | `achirothmane/aegis-ege` | #84 | `2b08f173d7e0dc7390b7ba9fec57ab10e28c48ba` |
| D00 | `achirothmane/workflow-failure-lab` | #114 | `0e049d78538602e4ce1e068020abb32f4c4c558c` |
| D01 | `achirothmane/ci-retry-gate-consumer-e2e` | #20 | `36b11f6deb504153304552d7f07f64b2c816b0c5` |
| D02 | `achirothmane/aegis-ege` | #87 | `f2fbece23ce168e5e7bda7a799dd2bec5c638a8f` |

The frozen oracle remains unchanged.

## Missing operational prerequisite

D03 requires one **independent domain maintainer** operating in that maintainer's
**existing repository**, on a **materially different native substrate**, with
typed domain semantics for transactionality/idempotency, authority,
observation, recovery and outcome.

The selected run also needs a bounded test grant appropriate to that substrate
and a post-freeze applicability/oracle commitment before integration.

Two public recruitment requests are now pending at `padurean/gosmig#1` and
`maragudk/migrate#87`, but neither independent maintainer has explicitly
accepted participation. Therefore no
qualified participant, cohort selection, bounded test grant, applicability/oracle
commitment, or independent implementation is yet recorded. The same-owner
repositories used for D00-D02 do not satisfy independence.

Therefore:

```text
D03 = BLOCKED_UNSTARTED
reason = INDEPENDENT_PARTICIPANT_NOT_YET_RECORDED
```

This is not a frozen-contract failure. It is an operational prerequisite that
has not yet been met.

## Parallel public-incident falsification track

While recruitment remains blocked, D03 may accumulate a **public incident
corpus** from independently owned repositories whose failure and later
resolution are publicly reconstructable.

That corpus is recorded in
`docs/governed-action/d03-public-incident-corpus.md` and
`testdata/governed-action/d03/public-incident-corpus.json`.

Its purpose is to increase falsification pressure without waiting for maintainer
responses. It can expose incorrect retry assumptions, bad evidence
classification and fail-open behavior against real incidents.

It does **not** satisfy the operational prerequisite above and does not change:

```text
D03 = BLOCKED_UNSTARTED
reason = INDEPENDENT_PARTICIPANT_NOT_YET_RECORDED
```

External incident replay and independent held-out implementation are separate
forms of evidence and must not be relabeled as one another.

## What does not count

The following do not satisfy D03:

- treating EEP as a third independent domain;
- using another `achirothmane/*` repository as independent adoption;
- creating a fresh repository under the same owner solely to manufacture an
  independent cohort;
- implementing the held-out adapter ourselves and calling it independent;
- copying hidden reference-runtime behavior rather than implementing from the
  written frozen contract and published vectors;
- selecting concrete held-out cases and feeding them back into the core before
  the independent maintainer commits the cohort.

## Recruitment state

Recruitment may proceed in parallel across qualified candidates. Contact alone
never counts as consent or cohort selection. The first qualified independent
maintainer who explicitly accepts may proceed to the separate post-freeze
selection/applicability/oracle record required by Protocol J.

This avoids making progress depend on a single maintainer response while
preserving the holdout boundary.

## Readiness condition

D03 may move from `BLOCKED_UNSTARTED` to `SELECTED` only when all of the
following are named and recorded:

1. independent maintainer;
2. that maintainer's existing repository;
3. materially different domain/substrate;
4. bounded authority/test grant;
5. applicability boundary and native comparator;
6. held-out oracle commitment;
7. independence provenance and reused-code disclosure.

Only after that record exists may implementation begin.

## Candidate categories are not cohorts

Database change, credential lifecycle, metered API and long-running SaaS work
remain only example recruitment categories. None is selected by this record.

## Claim limits

This readiness record creates:

- no new runtime;
- no new authority;
- no normative change;
- no independent-validation claim;
- no held-out-generalization claim;
- no platform-kernel claim.

It exists to prevent same-owner work from being relabeled as independent
evidence merely to keep the queue moving.
