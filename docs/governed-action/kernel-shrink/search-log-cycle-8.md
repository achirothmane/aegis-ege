# Cycle 8 precedence search log

Cutoff and inspection date: 2026-10-04. The source repository was frozen at
`271c40bbf46d75f8c3c09c04fe651195e572ab2b`. Search was public/read-only.
Mappings in the responsibility matrix are our technical inferences from the
listed primary sections, not statements that their authors proved A/C/P.

## Search strategy and decision changes

| Round | Representative exact searches | Decision-changing result |
|---|---|---|
| Semantic triad | `"authorization" "provenance" "postcondition"`; `"authorization" "causality" "current state" transaction`; `authorization provenance postconditions independence theorem transactions` | Found joint ledger/transaction models; separate literature silos were insufficient comparators. |
| Continuing authority | `"ongoing authorization" "usage control" UCONABC formal`; `"authorization" "non-derivability"`; source sections on commit-time mediation, capability validity and reference mediation | UCON's ongoing predicates and the reference-monitor principle already explain A. Formal UCON handles mutable conditions but excludes post-use obligations from its core. |
| Execution/recovery | `"RIFL" "completion record" exactly once 2015`; source sections on RPC identity, duplicate suppression and completion durability | RIFL and DBOS already supply atomic effect/result identity coupling. Logical RPC identity must not be silently substituted for exact physical attempt/executor. |
| Joined systems | `"transaction" "authorization" "post-conditions" Clarity SIP-005`; `"authorization" "causality" "ledger" Daml formal 2020`; `"provenance-based access control" model policy` | Daml's 2019 structured ledger and SIP-005 defeat a claim that composition of authorization, origin and result conditions was invented here. PBAC distinguishes authorization/action-validation over history. |
| Causality and accountability | `site.arxiv.org provenance causality database Meliou 2010 causality responsibility`; `"authorization" "causal attribution" "current"`; source sections on causal provenance and operation origin | W3C generation/activity/agent/invalidation relations are suitable known components. Query counterfactual cause is a different question from exact physical execution identity. |
| Temporal/formal | `Hoare rely guarantee postcondition interference Jones 1983`; `site.arxiv.org runtime verification temporal logic three valued Bauer Leucker Schallhart`; `site.cs.arizona.edu Snodgrass temporal databases valid time transaction time 1999 pdf` | Rely/guarantee explains preservation restrictions; temporal databases distinguish historical recording from fact-specific current validity; monitors require truthful observations and assumptions. |
| Proof/trust | `proof carrying authorization revocation freshness Appel Felten 1999`; `site.cs.princeton.edu Appel Felten proof carrying authentication 1999 pdf` | The author's actual PCA paper treats expiry/revocation and verifier assumptions. TUF, CT, in-toto, SLSA and Sigstore provide known independent-policy/history machinery. |
| Agents | `"Proof-of-Continuity" "2607.08906"`; source sections on authorization/current-policy/receipt distinctions | PIC explicitly binds authority to causal lineage but leaves practical revocation extension questions; OAuth actor receipts separate historical attestation from current authority. MCP is request/transport authorization, not physical-effect proof. |
| Patents/older origin | `site.patents.google.com authorization transaction provenance postcondition`; citations from US20230351391A1 | Examined 2021/2023 disclosures and the cited 2018 transaction-integrity patent. Recorded publication dates separately from listed priority dates; no legal patentability judgment. |
| Theorem confirmation | `"authorization" "causality" "postcondition" theorem`; `"authorization" "provenance" "independent" "temporal" theorem`; `"authorized" "historical" "current" "receipt" distributed systems`; targeted academic-domain repeats | No examined primary result establishes the same three fixed projection separations in the same open mutable domain. No valid general derivation under the frozen assumptions was found. This is an examined-source conclusion, not proof of universal absence. |
| Proof-family coverage check | `Necula proof carrying code 1997 paper author pdf Berkeley`; `Chiesa Tromer proof carrying data 2010 paper MIT pdf`; `"By Reason and Authority" Whitehead Abadi Necula pdf`; author-bibliography follow-through | BLF (2004) joins authorization logic and semantic proofs while distinguishing signer origin from correctness. Its conservativity theorem and PCD's transcript soundness do not establish current external-effect truth. This strengthens N1 without supplying a general ACP derivation. |

We additionally opened the primary sources listed in
[the complete matrix](prior-art-cycle-8.json), including Chubby sequencers,
Herlihy/Wing linearizability, Raft client serial numbers, Temporal's lost worker
completion, DBOS atomic outcome recording, event sourcing and SQLite isolation.
The matrix identifies sections, dates, scope, boundaries, assumptions and all
requested responsibility fields for every serious candidate.

## Source quality and coverage limits

Only primary academic/author, official standards, official implementation or
patent-disclosure sources support the conclusions. Search snippets and secondary
summaries were discovery aids. Some combined-keyword searches returned generic
or irrelevant pages; those results provide **no negative evidence** of novelty.
ACM/PDF endpoints that failed were followed with author copies where available.
The scanned Sagas report supplied bibliographic/scope context, not an examined
A/C/P theorem. The Corcoran preprint and ERC live draft were not backdated or used
to establish the earliest origin. Live vendor documentation supports capability
mapping at inspection, not an asserted historical introduction date.

Covered families: reference mediation/capabilities; UCON/PBAC/authorization
evaluation; RPC/durable execution/transactions/compensation; locks/epochs/
linearizability/replicated machines; generation/provenance/query causality;
temporal fact validity/interference/runtime monitors; independently checked
authorization/artifact provenance; root rotation/transparency/authenticated
history; ledger and agent/tool governance. Proof-carrying code/data were followed
to primary material and BLF's theorem sections. The original PCC scan was not
text-extractable, so its matrix scope uses the primary abstract and author
bibliography rather than an unexamined theorem. BLF and PCD supply explicit
semantic/proof compositions; neither was credited with unmodeled current
external truth.

## Strongest precedent and replacement test

Closest joined source: Daml's structured ledger, especially its separate
authorization context, atomic update actors and created-but-not-consumed state.
Closest explicit transaction triple: SIP-005's authorization, originating/sending
accounts and transaction postconditions. Neither source is credited with the
open mutable projection theorem. Their closed valid-ledger assumptions exclude
some negative corners and their operation identities differ from the exact
external physical attempt under test.

The strongest substitute uses an ordinary scoped authorization predicate,
destination serialization, stable operation key, atomic effect/origin record,
current read, authenticated history/checkpoint and independently selected
question/roots. `experiments/precedence_repro/substitute.py` implements these
mechanisms without Aegis imports. The separate specification-only SQLite and
event/history implementations test the whole reachable profile space.
This reconstructs a known-mechanism composition; it is not a claim to run
unmodified RIFL, DBOS, Daml or TUF software or replace Aegis's complete runtime.

## Stop rule

The final targeted round supplied no new candidate that could change the
definitions, strongest joint precedent, replacement architecture or
classification decision. Further broad keyword accumulation had low expected
decision value, so it stopped. A precise newly identified full separation theorem
would reopen precedence review. It would not, by itself, falsify a correct
reproduction; attribution and truth are different questions.
