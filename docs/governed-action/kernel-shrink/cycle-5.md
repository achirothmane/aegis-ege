# Cycle 5: unify the native business effect and causal completion record

Baseline: merged #240, `b94b59a2ab6b9a0c0cc1eb1050513d0eff5381c2`.

This cycle follows the first successful custody demotion with a narrower question:
after removing the separate mutable effect-owner register, does the PostgreSQL
profile still require a second durable completion/receipt table distinct from
the physical business effect?

The candidate keeps all semantic distinctions proven necessary by #235, #236,
#239 and #240, but carries two of them in one native row.

## Candidate

The destination contains no mutable custody table and no separate completion
table. One append-like business-effect row contains:

- the stable logical effect identifier;
- the actual attempt and executor identity;
- the exact before/after transition;
- admission binding and authority epoch/generation;
- commit time;
- the business payload itself.

The row is therefore both the physical externally relevant database effect and
the immutable exact-cause record. Its `effect_id` is unique and the executor
also checks for an existing row under the target transaction lock.

This is representation unification. It does not infer causality from state,
does not infer current closure from historical commit, and does not turn UNKNOWN
into retry permission.

## Required native cases

The composite PostgreSQL gate requires all of the following without skips:

| Case | Required result |
| --- | --- |
| Commit, lose callback acknowledgement, executor exits, fresh observer | one physical row; original exact cause remains recoverable |
| Same crash with exact observation withheld | UNKNOWN; read-only recovery changes no effect count; successor cannot replay |
| Process dies before transaction commit | no row survives; separately authorized successor may commit exactly once |
| Two fresh successors race | exactly one effect row; winner owns the exact cause; loser cannot inherit it |
| Later target-state drift | immutable historical cause remains exact; false current CLOSED is still rejected |
| Fresh successor after lost ACK | stable effect identity prevents a second physical row |

The independent evidence consumer remains unchanged.

## Falsification trial

`scripts/run_effect_record_unification.py` erases the replay-exclusion relation
from the candidate in both places where it is enforced:

1. the `effect_id` uniqueness constraint;
2. the live existing-effect lookup before insertion.

It then compiles the actual mutated native test executable and replays the
lost-acknowledgement successor case.

The mutation counts only if it reaches the intended semantic assertion and
commits exactly two physical business-effect rows:

`unified replay exclusion erased: committed_effects=2 successor_error=<nil>`

Compilation failures, skips or unrelated failures do not count. The source is
restored byte-for-byte and the complete positive candidate corpus is rerun.

## Interpretation

A positive result would justify:

- DEMOTE a separate mutable custody register in the bounded atomic profile
  (already established by #240);
- DEMOTE a separate completion/receipt table in the same profile;
- KEEP stable effect identity/replay exclusion;
- KEEP actual-attempt causal attribution;
- KEEP independent current-state closure verification.

It would not establish that replay exclusion, causality and closure are one
semantic relation merely because one row carries several of them. One
representation can satisfy several obligations without making the obligations
logically identical.

The generic production runtime remains unchanged. Four carrier types and three
generic retained obligations are therefore not reduced by this cycle. The
result, if green, is a stronger representation-minimality result for one
transactionally closed PostgreSQL profile, not a global minimality theorem.

The next admissible reduction question after this cycle is not "can we rename
the remaining fields?" It must either remove a genuine relation while preserving
the same independent claims, or show that one of the remaining relations is
policy/substrate-owned rather than universally kernel-owned.
