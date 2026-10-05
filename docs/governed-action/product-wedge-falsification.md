# Product-wedge falsification: external-effect finality

Date: 2026-10-05. Inspected live main and tested baseline:
`04434db12fa0c85d3497faf6ebb40df937092c5d` (PR #245).
Research classification remains **N1 / R4 / P1**. Academic novelty is not reopened.

## Decision

**W1 — GLUE ONLY, within the tested trusted transactional-destination profile.**

The strongest substitute reproduces the meaningful closure results using
existing authorization/delegation, durable-execution semantics, destination
serialization and idempotency, an atomic business-effect/origin record, a fresh
native observation and ordinary independent verification. No Aegis-only semantic
advantage or lower adoption/recovery cost was demonstrated.

For a completely mediated destination already exposing these facts, the
standalone-platform proposition receives **W0**. Retaining the reusable claim
checker, evidence adapter and failure corpus as a library/integration layer is
the narrower **W1** disposition. **W2, W3 and W4 are not established.** Remain
RETEST; do not expand a standalone platform on the basis of this experiment.

This is a bounded product result, not a declaration that every external target
or Aegis's complete Genesis/quorum deployment has been replaced. It also does
not establish that customers will buy the remaining library. No market-demand,
customer adoption or payment evidence was collected.

## What was actually executed

The source of truth was the complete live Cycle 8 report, its replay assurance,
the existing Cycle 8 substitute, the current `governedaction/runtime` and
`evidenceverify` code, and the repository's native-succession tests. Earlier
research was used as implementation context, not as a novelty argument.

The new experiment is `experiments/product_wedge/run.py`. Its common native
destination is the existing `experiments/precedence_repro/substitute.py` with
its strongest scoped-authority fence enabled. A separate SQLite workflow journal
represents durable issued/completed steps and atomic successor ownership changes.
The same recovered destination facts are then consumed by the ordinary checker
and the **actual unchanged** `aegis-evidence-inspect` binary, built from the pinned
main. No Python reimplementation was substituted for Aegis.

Validation:

- All **10** primary schedules matched on CLOSED versus UNKNOWN.
- Three real child processes exited after COMMIT without acknowledging it;
  reopened storage retained the original effect and winning origin.
- Eight concurrent same-key deliveries preserved one physical effect; eight
  concurrent successor ownership CAS operations produced one winner.
- Seven supplementary controls passed, including signed executor overstatement,
  stale offline evidence, restored observation, broken history and modified key
  succession.
- The original eight Cycle 8 substitute tests passed.
- **317 existing Go tests/subtests passed**: 175 verifier/journal checks and 142
  governed-action/runtime checks, with the race detector. The CLI package has no
  test files; that package-level skip is not an omitted test.
- Repository CI on experiment commit
  `1689df731ea5b46588abb6294ef5b32d5c199039` also completed successfully.

CI evidence: [product comparison run](https://github.com/achirothmane/aegis-ege/actions/runs/37254638619)
and [repository CI](https://github.com/achirothmane/aegis-ege/actions/runs/37254638585).
The downloaded initial artifact has SHA-256
`83dbb0fa2505ecc352a31023987b95ae23c9f619c7db801d09b53d7ebca32847`.
The final local replay adds the concurrent ownership and supplementary controls
using that exact pinned binary; final results accompany this report.

### Evidence limits

The effects execute in real SQLite transactions. Mapping their facts into the
fixed Aegis PostgreSQL wire profile is explicitly **SIMULATION grade**. Neither
the Aegis PostgreSQL executor nor two complete vendor stacks performed these
SQLite effects. The comparison tests a shared native substrate and the actual
Aegis evidence consumer; existing Go tests separately exercise its runtime.

AADP/AIP/AIDP, Temporal and Restate were **not installed**. Their relevant
documented semantics were represented minimally, as permitted by the mission.
This is not protocol conformance, production benchmarking, network-partition
testing, hardware power-loss testing or an independent customer deployment.

The fixture scheduler/destination adapter grounds the attempt and executor
names. A production adapter must derive them from authenticated execution
context; caller-supplied names inserted into a row are insufficient. The
experiment does not test dishonest privileged writers, compromised destinations,
protected signing processes or independent organizations. All signing seeds are
public fixture seeds, never deployment secrets.

The CLI policy independently pins claim strength, build/case/profile, roots and
checkpoint. Exact request/attempt metadata also relies on its authenticated
execution statement and the upstream binding contract; the policy does not
carry a separate complete expected request. This corpus's artifact mapper starts
from the relying party's already fixed request. It therefore does **not** prove
that the raw CLI can determine the intended request from wholly untrusted
executor metadata. An upstream intent/attempt binding check remains necessary,
just as externally justified freshness remains necessary. Neither integration
responsibility is silently credited to the current consumer.

History signer replacement is verified with an ordinary dual-signed transition
and installed through the relying party's independent channel. Both consumers
receive the resulting independently selected root. This exercises history
succession **discharged upstream**, not Aegis's additional internal
Genesis/enrollment/quorum succession profile. That stronger profile is not
declared replaced by two signatures. Its cost and guarantees need a separate
comparison if they are part of a buyer's requirements.

## Strongest realistic substitute

The functional stack is:

1. Existing workload identity plus attenuated delegation/provenance.
2. AADP-style stateful per-action PDP/PEP authorization.
3. Restate- or Temporal-class durable executor, correctly configured for the
   destination's retry contract.
4. Destination-native stable idempotency key, scope/parameter binding, generation
   fence, CAS/transaction and authenticated winner capture where available.
5. Fresh destination observation, retained ordinary audit/checkpoint, independently
   selected claim/roots, and a small relying-party checker.

These are responsibilities, **not five required commercial products**. Existing
services can co-locate authorization state, effect records and audit checkpoints.
Identity and workflow systems remain pre-existing dependencies on both sides.
Aegis receives no credit for replacing them.

The native profile holds the relevant authority state under the same
serialization boundary as the physical effect. Revocation and effect commitment
are ordered there. The effect row retains the actual winning attempt/executor
and authority snapshot; it is also the business effect and replay rendezvous.
A successor retrieves this row instead of inventing a new effect identity.

This is a substantial but reasonable destination advantage, already available
to Aegis's own native adapters. It is credited equally. A remote PDP revocation
that has not reached the destination is a different profile; a local SQL fence
does not silently prove globally immediate revocation.

### Upstream guarantee ledger

| Component | Guarantee credited | Boundary and withheld claim |
|---|---|---|
| AIP, `draft-prakash-aip-01`, including a workload/possession binding supplied externally | Verifiable attenuated delegation, issuer/agent context, signed audit artifacts; counter-signed and third-party completion attestations are possible | A token or a completion label alone does not identify a physical winning attempt |
| AIDP, `draft-vandoulas-aidp-03` | Structured intent, constrained delegation, execution-boundary checks, signed bound observations, retained/pullable results and replay suppression | Execution-boundary attestations require a trusted observer and destination mechanism for stronger physical-effect claims |
| AADP, `draft-saha-aadp-04` | Stateful action decisions, atomic budget reservation, approval lifecycle, durable intent/report linkage, no blind uncertain-outcome retry and downstream idempotency propagation | Permission and decision/report durability do not alone establish an external physical commit |
| Restate durable steps | Recorded results replay durably; unresolved external work can be retried according to configuration | The external sink must make repeated calls safe; a journaled return value supplies only its recorded semantics |
| Temporal Activities | Durable workflow history and retries after an Activity fails to report; completed recorded Activities are not re-executed by workflow replay | Destination idempotency remains application/sink responsibility |
| Destination transaction/fence/CAS | Authority/revocation ordering, atomic business effect and winner record, single-key serialization and stable replay exclusion in the declared mediated profile | No credit beyond the actual enforcement boundary; unrestricted bypass writers invalidate the guarantee |
| Fresh observer and ordinary audit/checkpoint | Present predicate at a justified read point; authenticated records/history under independently accepted roots | A valid signature proves statement authenticity, not an honest observer, permanent freshness or an unavailable physical fact |

Primary references, all inspected on 2026-10-05:
[AADP](https://www.ietf.org/archive/id/draft-saha-aadp-04.html),
[AIP](https://www.ietf.org/archive/id/draft-prakash-aip-01.html),
[AIDP](https://datatracker.ietf.org/doc/html/draft-vandoulas-aidp-03),
[Restate durable steps](https://docs.restate.dev/develop/python/durable-steps),
[Temporal Activity definition](https://docs.temporal.io/activity-definition),
[PostgreSQL locking](https://www.postgresql.org/docs/current/explicit-locking.html),
[PostgreSQL isolation](https://www.postgresql.org/docs/current/transaction-iso.html),
[SQLite transactions](https://www.sqlite.org/lang_transaction.html).
The three agent protocols are individual Internet-Drafts, not adopted IETF
standards. AIP here means Prakash's delegation proposal; similarly named identity
drafts are not conflated with it.

## A/C/P/F comparison

F is a relying-party verification requirement through recovery, not a newly
asserted fourth independent kernel primitive. It includes the justified result,
the retained question/roots and required history. An honest verified UNKNOWN
counts as a justified result; it does not count as resolved physical truth or
retry permission.

| Requirement | Authorization/delegation + durable workflow alone | Strongest substitute with native discharge and ordinary checker | Current Aegis on the same supplied evidence |
|---|---|---|---|
| A: authority at actual commit | Earlier permission and issuance context; commit ordering needs another mechanism | Established by serialized native authority/fence and commit snapshot | Uses that same native evidence; supplies no extra enforcement without it |
| C: exact actual attempt/executor | Issued request/provenance and logical execution identity do not necessarily identify the physical winner | Established by authenticated winner capture atomic with the business effect; replay retains the original winner | Exact commit-record matching; foreign winner cannot be promoted to claimant success |
| P: current independent predicate | A durable successful step can be historical | Established by a fresh independent query of the selected predicate | Checks supplied observed state; offline verifier does not autonomously refresh it |
| F: independent justified result after recovery/succession | Possible with third-party attestations, but their physical evidence/trust mechanism must be supplied | Native evidence + independently retained question/roots/checkpoint + upstream verified key succession suffice in this profile | Portable independent checker reaches the same closure/history result; its extra internal succession profile remains separately scoped |

The complete native substitute can answer the required effect question. The
upstream protocols alone do not magically provide every physical fact, but that
fact does not make the missing observer/record exclusive to Aegis.

### Claim → evidence → mechanism → enforcement → trust

| Claimed guarantee | Evidence | Mechanism | Enforcement point | Trust assumption |
|---|---|---|---|---|
| A | Exact scoped authority snapshot in the committed business row | Fence read and effect insert in one serialized transaction, with revocation ordered against it | Destination transaction/commit | All governed writes and revocations use this boundary; upstream state is coupled as declared |
| C | Retained winning attempt AND executor in the same physical business row | Trusted execution context recorded atomically with the effect | Authenticated destination write path | Adapter/context is honest; identity labels cannot be chosen freely by the caller |
| One physical effect | Stable key and unique business row retained across restart | Native uniqueness and replay returning the original row | Destination | Key scope/parameters and retention match the recovery horizon; a new key is a new operation |
| P | Fresh observed target plus separately selected predicate | New destination read at a justified observation point | Observer/read transaction | Observer is current and honest; memoized old reads are excluded |
| F | Original facts, independent question/roots, authenticated checkpoint and accepted succession | Signature/binding/history checks and native reconciliation | Independent relying-party checker, plus upstream root installation | Accepted observers/custodians and preserved checkpoints are trusted; executor completion assertions are insufficient |

No receipt receives credit because its fields were renamed. Atomic storage of a
caller-supplied assertion does not upgrade it to a physical-origin proof. A
cached idempotent response does not mean the successor caused the original
effect. A signed old observation does not mean the current predicate remains
true. A history head does not mean effect closure.

## Identical hard-failure corpus

The independently selected question is EXACT_EFFECT for the original specified
attempt. Numeric vectors below describe physical A/C/P facts; they are not
accepted merely because a producer labels them. `—` means no effect committed,
so A-at-commit and actual-effect causality are inapplicable.

| # | Schedule | Physical A/C/P | Strongest substitute | Actual pinned Aegis consumer | Credited source of the result |
|---|---|---|---|---|---|
| 1 | Authorized, then revocation reaches native boundary before commit | —; zero effects | Native DENIED_AUTHORITY; no CLOSED claim | UNKNOWN; no causal commit asserted | Destination authority fence; no Aegis advantage |
| 2 | Other authorized attempt/executor produces exact desired state | 101 | UNKNOWN for claimant; foreign winner retained | UNKNOWN; commit/request mismatch rejected | Native winner record + independently fixed question |
| 3 | Exact authorized commit, then target changes | 110 | UNKNOWN for current EXACT_EFFECT | UNKNOWN; historical A/C retained | Fresh native observation; historical commit is preserved |
| 4 | COMMIT, lost ACK, actual child-process exit, successor recovery | 111 | CLOSED from original row and fresh read | CLOSED + TRUSTED_HISTORY | Native atomic row + read-only recovery |
| 5 | Successor considers retry while original may already exist | 111 | Same-key replay returns original; one effect; CLOSED for original attempt | CLOSED for original attempt | Destination idempotency; no fresh logical key or false successor attribution |
| 6 | Eight duplicate deliveries and eight concurrent successor CAS contenders | 111 | One effect, original winner, one ownership CAS winner; CLOSED | CLOSED on those same native facts | Native uniqueness and CAS |
| 7 | Durable workflow records completion; currently available destination observation is state-only | 111 physically, but A/C evidence unavailable | UNKNOWN; does not infer origin from state | UNKNOWN + TRUSTED_HISTORY; STATE_ONLY | Honest evidence-strength ceiling; shared limitation |
| 8 | Issued-request provenance names claimant; native winner was another attempt | 101 | UNKNOWN for claimant; actual winner retained | UNKNOWN; mismatch rejected | Native origin beats issued-request provenance |
| 9 | Historical commit/history still valid; current target predicate false | 110 | UNKNOWN closure with TRUSTED history | UNKNOWN + TRUSTED_HISTORY | Fresh predicate separate from authenticated history |
| 10 | Lost ACK, executor death, successor recovery and upstream-verified history signer succession; independent reader only | 111 | CLOSED without executor's completion report | CLOSED + TRUSTED_HISTORY under independently installed current root | Native facts + ordinary succession + independent verification |

Case 7 is the stipulated weak-observation failure mode, not a deliberately
weakened competitor awarded to Aegis. The full native row still exists but is
unavailable through that observation profile. A supplementary access-restoration
control confirms that **both** checkers subsequently close from a fresh full
native read. If the strongest deployed stack already has that read access, it
uses it and solves the case; this limitation contributes no wedge.

The case 2/8 diagnostic outputs are not identical: Aegis's current checker
marks commit-point authority UNPROVEN and causality STATE_ONLY after the origin
mismatch, and rejects the packaged claim. The native evidence still identifies
the authorized foreign winner. A purpose-specific ordinary checker can expose
that known-negative attribution directly. Equal conservative closure results
must not be advertised as equal diagnostic detail or proof that all fields are
independently projected by the present CLI.

### Supplementary controls

| Control | Observed result | Product consequence |
|---|---|---|
| Remove the native authority fence after earlier permission | One effect commits under revoked authority; ordinary observer returns UNKNOWN | A userspace pre-check cannot manufacture commit-point enforcement; no unique Aegis advantage established |
| Restore full native observation after weaker evidence | CLOSED is available from the destination | Credit the destination/observer equally |
| Authentically signed executor overstates success after real target drift | Both withhold CLOSED; Aegis rejects the claimed success | Useful verification behavior, reproducible with ordinary checking |
| Restore actual predicate, observe again, perform no new effect | Both close | Reconciliation needs new truth, not a new effect |
| Reuse authentic old evidence after later mutation | Both offline consumers still describe the old CLOSED result; fresh read yields UNKNOWN | Offline authenticity is not current-time freshness |
| Break required history while retaining a true closure bit | Ordinary checker reports CLOSED plus UNTRUSTED history; composite finality withheld | Consumers must enforce the full required contract, not select a convenient field |
| Modify the dual-signed history transition | Transition rejected | Ordinary signatures and independent predecessor/root bindings suffice for this scoped succession |

## Subtraction from Aegis

These are product-boundary decisions, not an instruction to delete functioning
production code before replacing its dependency. No production files were
removed or changed. No defect in an existing bounded guarantee required a fix.

| Existing responsibility / example source | Disposition | What, if anything, remains at the effect-finality boundary |
|---|---|---|
| Caller identity and authorization plumbing, `internal/server/auth.go` | INTEGRATE upstream identity | Verify already-established subject/executor binding on the effect evidence |
| Execution-origin/delegation checks, `governedaction/origin.go` | DEMOTE to consuming external provenance/identity | Exact actual winner must still come from an enforcing destination/observer, not delegation alone |
| Approval/permission minting, `governedaction/approval_use.go` | INTEGRATE upstream action authorization | Match external decision/approval to the exact governed effect; consume its revocation contract |
| Credential brokerage, `governedaction/credential_use.go`, `internal/secretbroker` | Upstream execution/gateway concern, outside V1 wedge | No credential platform owned by effect-finality library |
| Tool/runtime/MCP enforcement and taint concerns, `governedaction/taint.go` | Outside this product wedge | Do not sell the library as an agent gateway or firewall |
| Scheduling, durable workflow results and generic restart orchestration | INTEGRATE Temporal/Restate-class executor | Effect-specific reconciliation callback plus explicit retry/continuation decision |
| Generic audit logging, journal storage and ordinary signer rotation | INTEGRATE existing audit/PKI where its trust contract suffices | Consume exact accepted checkpoint and succession evidence; retain stronger quorum checking only when independently required |
| Native uniqueness, fencing, CAS and atomic transactions | CREDIT DESTINATION; retain thin adapter | Describe and test the precise capability, retention and mediation boundary |
| Admission policy/risk engine | Upstream policy dependency | Selected claim/predicate and evidence-strength policy must remain independently bound |
| Typed effect evidence, exact-origin matching, current-vs-historical separation, conservative reconciliation and portable checker | RETAIN as library/integration hypothesis | This is the small residue; no standalone-platform entitlement follows |

After complete subtraction, the candidate surface is a destination-capability
profile, an evidence mapper, a relying-party claim checker and a reconciliation
contract. It must say which facts are proved, refuted or unavailable, which
observation point is justified, and what continuation is actually permitted.
It owns neither upstream authorization nor the physical truth source.

## Interoperability contracts

These are report-level interface contracts, not new production APIs.

| Input/output | Required binding and meaning | Owned by |
|---|---|---|
| AuthorizationEvidence | External decision/permit reference, request/effect digest, subject, target/account/boundary, authority epoch/generation, validity, delegating authority references and declared revocation semantics | AADP-style PDP plus identity/delegation layer |
| DurableAttemptReference | Stable logical operation key separate from exact attempt/executor; issued step, returned/result-recorded state, recovery owner; original identities survive replay | Durable executor |
| DestinationCapabilityProfile | Idempotency retention/scope/parameter rules; atomic authority enforcement; authenticated winner capture; available current reads; complete-mediation boundary | Destination adapter/owner |
| CommitEvidence | Destination-authenticated original winning attempt/executor, exact effect/target/state relation, authority state at commitment and native ordering reference | Destination, transaction or trusted independent observer |
| CurrentTruthEvidence | Independently required predicate reference, actual current observation, scope/revision and externally justified observation point/freshness | Observer, independent of executor outcome assertion |
| FinalityAssessment | Separate A/C/P evidence status; CLOSED/UNKNOWN under selected claim; history/succession status; original winner; continuation/retry allowance and reason | Small checker/integration library |

An issuance-time permit alone cannot fill CommitEvidence. A workflow-completed
flag cannot fill CurrentTruthEvidence. A fresh observer response cannot silently
prove unknown origin. Root installation and freshness come through the relying
party's independently trusted channel, never through a bundle declaring its
own keys or choosing a weaker question.

The candidate architecture remains upstream identity/delegation → per-action
authorization → durable executor → optional Aegis evidence/reconciliation library
→ destination. Native enforcement and observers supply the facts. The word
“optional” reflects the demonstrated substitute, not a claim that Aegis has
earned a necessary commercial layer.

## Integration and adoption complexity

### Measured fixture facts

| Measure | Strongest ordinary substitute | Aegis on the same upstream/native substrate |
|---|---|---|
| Deployed vendor products in this experiment | 0; documented semantics modeled | 0 additional vendor products; real pinned CLI used |
| Native fixture stores | Destination DB + durable-workflow DB | Same two stores |
| Finality consumers | Small ordinary in-process checker | One existing read-only CLI plus artifact mapper |
| Independent finality invocation | One call with external question, roots, expected head/read point | One CLI invocation with separately supplied bundle/policy; upstream root/scope/freshness installation still required |
| Schema/role configuration | 11 question fields, observer/history roots, expected checkpoint and observation point | 11 top-level policy fields plus five role/key bindings and request/artifact mapping |
| Mutation privilege needed at effect boundary | Native owner installs/enforces transaction/fence; worker uses bounded mutation path | Same native privileges; CLI itself only reads two files |
| Operator actions in automated schedules | 0 | 0 |
| Observation rounds to resolve recoverable UNKNOWN | One fresh native snapshot once storage/evidence access is available | Same snapshot; then CLI verification |
| New physical effects during observation-only recovery | 0 | 0 |
| Portable evidence | Standard signatures, retained native facts/checkpoint, independent roots | Existing typed bundle and independent policy; richer reusable validation |

Roles are not necessarily separate processes, products or independent failure
domains. The native observer and signer trust assumptions remain on both sides;
Aegis's five role labels do not manufacture operational independence.

Code inventory in this bounded reconstruction:

- Existing ordinary substitute: **229 lines / 9,812 bytes**, including destination,
  signing, verifier and representative trials. The destination class is 90 lines;
  the ordinary independent checking function is 36 lines.
- Added minimal durable-workflow model: 25 lines. Dual-signed history transition
  construction/checking: 16 lines. These are ordinary scoped mechanisms, not
  production-complete products.
- Shared experiment: **434 lines**, including schedules, controls, artifact
  rendering and assertions. Its Aegis artifact mapper is 80 lines and CLI wrapper
  14 lines. This is benchmark code, not a claimed production integration LOC total.
- Current reusable Aegis consumer: **six production Go files / 1,254 lines /
  50,108 bytes**, including stricter parsing, canonicalization, full history and
  internal Genesis/quorum succession support. Those broader guarantees make a
  direct LOC-quality comparison inappropriate.

### Costs not yet measured

| Requested measure | Available evidence | Decision implication |
|---|---|---|
| Real time to first governed effect | No vendor/customer setup study; only this prepared fixture | No adoption advantage demonstrated |
| Real time to resolve UNKNOWN | One read in recoverable fixture cases; impossible until evidence exists in weak cases | No production recovery-time advantage demonstrated |
| Production custom glue/recovery LOC | Small executable reconstruction; full production adapters/vendors not integrated | No proven reduction attributable to Aegis |
| Configuration/onboarding burden | Fixture bindings inventoried; no independent installer | No proven compression |
| Privileged permissions and trust setup | Mechanism-level requirements identified, not deployed independently | No demonstrated reduction in privilege or trust assumptions |
| Independent verification effort | Both automate a check; only Aegis already provides a larger reusable strict consumer | Potential packaging value; not measured customer savings |

The local replay completed in roughly 0.29 seconds. The ordinary in-process
verification and CLI process timings are recorded in JSON, but they have
different process-start and validation costs and are **not** a product-speed
comparison. Fixture runtime is not time-to-adoption. No invented hours, savings,
operator labor price or production percentile is presented as a measurement.

## Where Aegis loses, ties and retains value

**Loses as a necessary standalone layer:** a fully mediated native destination
already holding exact authority/origin/current facts can support independent
recovery and verification with a small checker. Ordinary idempotency, CAS,
workflow durability, third-party attestations and audit authentication cannot
be counted as Aegis moat. Installing Aegis adds an artifact mapping/consumer
without a demonstrated reduction elsewhere.

**Ties:** all ten bounded closure results, safe native replay, current-state drift
detection, rejection of executor overstatement and the honest evidence ceiling.
No case was observed in which the strongest substitute falsely closed while
the unchanged Aegis consumer correctly refused it.

**Shared limitations:** neither system can know a missing physical winning
attempt from matching state or workflow provenance alone; prevent a revocation
race at a non-participating destination by adding another userspace check;
recover destroyed/unobservable evidence; or establish present truth indefinitely
from an old signed artifact. Neither can escape its destination/observer trust
assumptions.

**Aegis-specific integration limitation:** the raw consumer requires its trusted
execution-metadata/binding input as well as external freshness. The ordinary
checker takes the complete independent question explicitly. The current CLI's
claim-strength policy alone is not a substitute for separately retaining that
question. This limits the demonstrated F claim and adds binding work for an
integration; it is not represented as a newly reproduced production defect.

**Useful retained implementation value:** Aegis already has a strict portable
consumer, independently selected claim type, precise bindings, history checks,
broader internal succession validation and a substantial executable failure
corpus. These can spare an integrator from writing/testing checks. This is an
engineering packaging opportunity, not an observed exclusive guarantee or
measured product win. The larger succession profile could be valuable where
required, but its own strongest-substitute/cost comparison remains open.

## Does independent finality remain distinct?

**Yes as a relying-party question; no as an exclusive Aegis capability in this
profile.** It is distinct from authorizing an action, retaining a workflow result
or accepting an executor's signed completion claim. Its evidence must survive
recovery and remain answerable under the relying party's selected question and
trust contract. But a trusted destination record, fresh observer and ordinary
verification/succession can answer it without Aegis.

The remaining distinction is predominantly **integration/packaging and honest
evidence interpretation**, not a demonstrated unfillable semantic gap. In
weaker external targets a semantic evidence gap remains, but Aegis currently
inherits it. Naming that gap, or classifying it UNKNOWN, does not mean Aegis
resolves it.

Conditional positioning, if later evidence supports a product, may be
“external-effect finality for consequential automation.” For now the supported
description is a reusable external-effect evidence/reconciliation checker. Do
not market it as Agent IAM, gateway, firewall, workflow engine, generic policy
engine or generic provenance platform.

## Exact evidence needed before RETEST → INVEST

W1 does not justify standalone-platform investment. The next experiment should
first identify a buyer's concrete incident and strongest existing stack. The
following are **proposed pre-registered advancement thresholds**, not achieved
results or externally validated prices:

1. **Demand and consequence:** at least three unrelated teams supply real
   consequential-automation incidents or retained traces involving uncertain
   external effects after an existing durable/authorization stack. Name the
   costly decision, budget owner and currently paid substitute. At least two
   independently accepted paid pilots are needed; interest or a repository star
   does not satisfy this gate.
2. **Full-stack replacement test:** execute the identical pre-registered corpus
   in the chosen real Temporal/Restate-class deployment and its real destination,
   with destination-native idempotency/fencing enabled and expert ordinary glue.
   Include both a strong native target and the candidate's actual weaker target.
   Preserve every baseline success. Test complete executor recovery and any
   buyer-required internal Genesis/quorum succession, not only a bundle consumer.
3. **Actual differential:** show at least one economically material case where
   Aegis obtains a justified answer or safe continuation that the strongest
   practical substitute cannot obtain at comparable effort. Identify the actual
   new evidence mechanism and enforcement point. If the difference is ordinary
   glue alone, retain W1 and stop platform expansion.
4. **Measured compression:** independent engineers using the same pre-existing
   upstream stack must demonstrate at least 50% less custom reconciliation work
   or operator recovery effort, with no hidden extra trust/privilege burden.
   Pre-register the LOC/steps/time inclusion rules. Measure first governed effect
   from a clean documented integration and median/p95 UNKNOWN resolution; no
   degradation exceeding 10% at p95. A target of halving integration time and
   achieving the first governed effect within two hours is a test target, not a
   present promise.
5. **Correctness and verification:** zero false CLOSED, unauthorized native
   effects or duplicated logical effects across at least 1,000 pre-registered
   injected schedules plus three real incident families. Independently selected
   roots/question and fresh observation must work without the executor's account
   or mutable completion report. This count is an advancement gate, not a proof
   of universal safety.
6. **Reuse:** at least two non-author teams integrate from documentation and
   continue using the effect/recovery path for four weeks, recording recurring
   reconciliation decisions and paid continuation. A founder-assisted demo is
   insufficient evidence of lower adoption cost.

Only if a meaningful remaining gap and measured adoption/recovery advantage
survive together is **W4** warranted and INVEST justified. A theoretical known-
mechanism composition can reach W2 only after measured complexity savings;
recognizing an uncertain outcome alone earns neither W2 nor W3.

## Answer to the final question

After identity, delegation, authorization and durable execution, **the
destination's enforcing substrate and an independently trusted current observer
provide the facts about what reality did; a relying-party verifier evaluates
those facts under its own question and roots.**

In the tested profile, the existing stack can already do this with ordinary
glue. Aegis does not earn a standalone product boundary from the residual
question alone. Retain the checker/integration opportunity, preserve the evidence,
and require a demonstrated customer differential before building further.
