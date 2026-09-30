# D03 — independent candidate reconnaissance

Status: **RECRUITMENT RECON ONLY — NO COHORT SELECTED**

Frozen contract: `candidate-kernel-contract-v1`  
Frozen oracle blob: `37e2e0a0867fa78df37f9d4243a1c4107d62094b`

This artifact performs only the next permitted operational step after the D03
readiness gate: identify plausible independent repositories/maintainers that
could satisfy the held-out prerequisite.

It does **not** select a domain, maintainer, repository, oracle or test cohort.

## Screening rules

A recruitment candidate must already have:

- an owner independent from `achirothmane`;
- an existing repository rather than a repo created for this experiment;
- a materially different native substrate from CI rerun and Kubernetes node
  mutation;
- public evidence of an executable/local test surface;
- a contribution or maintainer interaction path;
- a plausible bounded non-production test setup.

This screening intentionally avoids reading or defining candidate-specific
held-out adversarial cases. Those must remain under the independent maintainer's
post-selection control.

## Candidate set

| Repository | Category | Existing native/test surface | Current status |
|---|---|---|---|
| `maragudk/migrate` | database migration | Go `database/sql`, transactional rollback, CI | not contacted / not confirmed |
| `padurean/gosmig` | database migration | Go + PostgreSQL integration tests, transaction/version-conflict semantics | not contacted / not confirmed |
| `openmeterio/openmeter` | usage metering/billing | self-hosted Docker evaluation stack, CI, contribution guide | not contacted / not confirmed |
| `hatchet-dev/hatchet` | durable workflows | self-hosted durable engine, unit + Docker integration testing | not contacted / not confirmed |
| `Infisical/infisical` | secrets/credential lifecycle | self-hosted Docker path and public contribution process | not contacted / not confirmed |

These are **recruitment candidates**, not ranked D03 winners and not consumed
held-out cohorts.

## Why this does not start D03

D03 requires the independent maintainer to actually participate and to own the
held-out cohort selection in that maintainer's existing repository.

Therefore every candidate remains:

```text
participation = NOT_CONFIRMED
selected = false
```

No same-owner implementation, unsolicited fork, or locally invented adapter can
convert this list into independent evidence.

## Protection of the holdout

This reconnaissance records only coarse operational suitability.

It deliberately does **not** record:

- a concrete candidate-specific oracle;
- domain-specific adversarial schedules;
- acceptance/rejection examples;
- adapter implementation rules;
- a proposed core change;
- a selected native comparator case.

If a maintainer accepts participation, a new cohort-selection record must be
created **before integration**. That record names the maintainer, repository,
bounded authority, applicability and oracle commitment while preserving the
frozen core.

## Next permitted action

Obtain explicit participation from one listed or equivalently qualified
independent maintainer.

Until then:

`D03 = BLOCKED_UNSTARTED`

and D04 remains blocked.
