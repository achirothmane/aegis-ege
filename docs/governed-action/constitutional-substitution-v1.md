# Constitutional substitution v1 — executed falsification report

**Classification: U4 — STRONG BOUNDED UNIVERSALITY EVIDENCE.** Three external
operative policy fragments disagree on identical proposed native effects without
changing production execution or verification semantics. This classification is
conditional on truthful, independently provisioned evidence and admission
authorities and complete mediation through the evaluated admission path. It is
not universal proof.

An explicit falsification control exposed an important limit: a trusted admission
issuer can falsely attest admission, execute an effect whose external requirements
were unsatisfied, and obtain supported effect-finality verification. Consequently,
neither a policy hash nor an authentic admission signature alone proves underlying
normative compliance. The separate public-evidence policy replay detects the
missing requirement; the unchanged effect verifier does not perform that replay.
This report does not merge those two claims.

## 1. Repository, execution and artifact identity

The live repository is [achirothmane/aegis-ege](https://github.com/achirothmane/aegis-ege).
Live main at the resumed inspection was
`04434db12fa0c85d3497faf6ebb40df937092c5d`, with complete main Git tree
`fc1d47ada01a78c824074dd4d0e253d2d5beaf29`. It was checked again during execution
and had not advanced. This is the live post-Cycle-8 replay-assurance state, not an
assumed historical N1/R4/P1 SHA.

The implementation is additive research on `research/constitutional-substitution-v1`,
in [PR #247](https://github.com/achirothmane/aegis-ege/pull/247). No production
feature, constitution-specific kernel fork or product surface is introduced.
All **812** files present in the inspected main are preserved byte-for-byte with
their Git file modes, including existing fixtures and workflows.

The executed research-code revision is
`cc360f68a1b8c32654f12230b0edbe9b1296927e`.
Its native run is [37256521357](https://github.com/achirothmane/aegis-ege/actions/runs/37256521357).
Subsequent exact reviewed head `5fa1ee293a551eeb10db5ea41dfaa1bd6ba34eaf`
passed all **13** CI checks, including a fresh complete constitutional native run
[37257520071](https://github.com/achirothmane/aegis-ege/actions/runs/37257520071)
and the previously failing composite corpus. The executed normative code and
all baseline files are byte-identical between those revisions; only research
report/evidence files were added. These are historical exact-head validation
snapshots; a later reporting commit does not inherit an all-green CI claim.

The resumed review independently inspected exact head
`b399e5b3c2a2aa776e5ff8f25051d9d312a192c3`. Its constitutional native run
[37258339316](https://github.com/achirothmane/aegis-ege/actions/runs/37258339316)
passed, and replay of its downloaded public archive with the byte-identical
native-result checker reproduced the complete result. This head has **12 of 13**
passing CI checks: the preexisting restored Genesis/custody corpus failed both
its initial attempt and one targeted rerun. Section 9 and the execution index
retain both failures. The all-green statement above applies only to `5fa1ee...`.
Execution uses Go 1.25.3 with `-race -mod=readonly -count=1` and PostgreSQL 16.6
pinned to image SHA-256
`557fea37a744d5f4c8faab304b0a90858b53ab119735a88c131fd19dab802f36`.
No native test is allowed to skip. Local Go/PostgreSQL tooling was unavailable,
so the real native execution took place on the repository's GitHub Actions runner.

The preceding run,
[37255623397](https://github.com/achirothmane/aegis-ege/actions/runs/37255623397),
also passed the 51-world matrix. Its third-control fixture originally lacked
an explicit consent event despite its case name. The executed revision above
adds authenticated disclosure/consent events and a result check requiring actual
consent evidence. Evidence from the earlier run is not used to establish the
stronger consent-present third-control claim.

Execution metadata and artifact digests are in
[execution-results.json](../../experiments/constitutional-substitution/execution-results.json).
The authoritative public native archive contains `native-test.log`,
`verified-native-result.json`, whole-run invariance snapshots, 55 pairs of
per-trial fingerprints, public policy/evidence inputs, evaluation traces,
independent replay outputs, native effect bundles, and unchanged verifier reports.
Private fixture signing keys and administrative credentials are not uploaded.

The corrected native archive is artifact `11323285625`, 876288 bytes, SHA-256
`dc2a9f7c1f366c24533e6fa4acd10635316fdc5462537d06359e97d04853408d`.
It contains 449 public files. Its Actions retention expires on 2027-01-03;
the committed inventory and execution index retain the hashes and results.

The later all-green reviewed head's native archive is artifact `11323341830`,
887652 bytes, SHA-256
`ebe2f5d709115c45c2b36257a988a42f615bc62a294a9172a36059dec21a667e`.
It independently reproduces the same 51/28/23 matrix, 11 disagreements, 55 equal
fingerprint pairs and three drift controls. Both archives and exact CI snapshots
are identified in the execution index.

The resumed exact `b399e5...` head's native archive is artifact `11323841645`,
887599 bytes, SHA-256
`63e06f2d79d1f933c6181ad6d94b308319ded06658026d6d44748157b6d447a1`.
Its 449 public files reproduce 51 trials, 28 committed worlds, 23 blocked worlds,
11 disagreement triplets, 55 equal fingerprint pairs and three drift controls.
The unchanged result checker has Git blob
`40477abb13f08a30260997b3fb08bff94c0fbec8` and SHA-256
`5dfe5761e8768621c4088ea406c5fe3411d2eb4feb5a5885aa5ce5fea98d0766`.
Its replayed result is equal to the uploaded `verified-native-result.json`.
Whole-run invariance snapshots agree, the native log has no skips, and direct
main/head Git-tree comparison preserves all 812 baseline blobs and file modes.

## 2. Sources and exact coverage

The source gate is satisfied by the authoritative operational extracts supplied
in the user's resume instruction. Those extracts are recorded verbatim in
operational substance, with explicit provenance, in
[sources.md](../../experiments/constitutional-substitution/sources.md).
The experiment did not retrieve original PDF bytes, and does not invent original
file names, page numbers, dates, or source statements absent from the supplied
extracts. Its finding concerns these operative fragments, rather than completeness
of either full original document.

| Constitution | Exact supplied document and standing | Used location/version | Local source record |
| --- | --- | --- | --- |
| A | *From Halal Label to Accountable AI Use: A Short Islamic Ethical-Operational Note for SME AI Adoption*, Othmane Achir / Orionech | Supplied operational frame and six named principles; unpaginated; version/date not supplied | `sources.md`: A.OP and A.NAMES |
| B | *Runtime Governance for Multi-Agent LLM Systems*, Achraf Jarrou / Dario Salerni | Working Draft v0.4, §5, “Maqasid: An Exploratory Normative Layer”; page numbers not supplied | `sources.md`: B.5 and B.5.NAFS/AQL/MAL/NASL/DIN |
| Supporting provenance | *Guidelines for Sharia-Compliant AI Adoption in SMEs*, Concept Note, Dario Salerni | Title/attribution and historical role only; no executable expansion | `sources.md`: SUPPORT |
| T | Synthetic privacy-first control created for falsification | Experiment v1; no moral or religious authority claimed | `sources.md`: EXP and `policies.json`: T |

| Exact local experiment input | SHA-256 of bytes used by the executed revision |
| --- | --- |
| `sources.md` | `7d719bb6c65516b15d42d588529d029f8421ed81152a25febdc3b686ea873b57` |
| `source-extraction.md` | `242847899307e2ede2b7091e24ce01da3671651061f9d29e00d663a5bd84ebb8` |
| `policies.json` | `8f16d65943799aef2dd4db18101e1bc0ada10771334c5e8e3f391feb1f3abd9f` |

B retains the source's standing exactly: exploratory hypotheses, not rulings,
no religious authority, requiring review by qualified scholars. Financial
applications may additionally require a Sharia supervisory board. Fixture
signatures do not represent either form of review.

The source-derived A operational concepts are responsibility, accountable human
control, prevention of unjust harm, dignity/privacy, truthfulness/non-deception,
legitimate benefit, audit trail, human validation points, and evidence that
control was exercised. Its six names are Taqwa, Amana, Sidq, Huda,
La darar wa la dirar, and Maslaha. The extract supplies no individual executable
definition for each name, so the operational frame is mapped collectively.

B contributes only the five candidate requirements listed below. Its treatment
of gharar remains deliberately weak: predictive entropy is **not** a
formalisation of gharar. At most a computable uncertainty proxy can represent
one component of informational asymmetry and trigger disclosure. No gharar
compliance predicate, threshold or religious judgment is implemented.

## 3. Independent source extraction and traceability

The following requirement table was prepared before implementation in
[source-extraction.md](../../experiments/constitutional-substitution/source-extraction.md).
“Exact location” refers to the supplied extract headings; original page numbers
were not supplied. All enforcement below occurs externally before issuance and
native dispatch. Post-effect claims retain the existing generic exact-effect
and current-state questions.

| Source and exact supplied location | Supported normative statement | Minimal policy requirement | Required evidence and relying-party expectation | Decision and enforcement | Post-effect evidence |
| --- | --- | --- | --- | --- | --- |
| A.OP, operational frame → A.review | Responsibility, justified benefit, harm prevention, dignity/privacy, truthfulness and audit must appear in the workflow | One combined review record with ownership, purpose, harm, privacy, truth and audit checks | Trusted observer signs exact request/current state; concrete owner and control-record references agree with their flags; relying party expects an actual review, not an authority Boolean | Missing check: require evidence; adverse check: deny; issuer withholds admission | Retain the reviewed facts, owner, control record and evaluated rule trace; ordinary native effect/current-state proof remains separate |
| A.OP, human validation → A.validation | Accountable human control must be exercised | One accountable validation point in the minimal tested instantiation | Approved human-role principal signs the exact proposal, state and reviewed-facts digest; recorded validation sequence | Missing valid approval: require human approval; zero dispatch | Retain signed validation and evaluation; a fixture signature does not establish human cognition |
| B.5.NAFS, v0.4 §5 → B.safety | Potential life/physical-safety impact requires multi-party human approval | At least two distinct approved human principals when safety impact is present | Same signed safety-impact fact; state/facts-bound approvals; independently provisioned principal identity, not just key count | One principal insufficient: require human approval; zero dispatch | Retain the two validations; closure uses no safety-specific relation |
| B.5.AQL, v0.4 §5 → B.bias | No objective rewards exploitation of documented cognitive biases | Prohibit the conjunction of documented bias and an exploitation-reward objective | Trusted signed objective/audit facts covering both conditions; completeness is an observer obligation | Deny the prohibited conjunction before dispatch | Retain objective assessment; no new causality rule |
| B.5.MAL, v0.4 §5 → B.disclosure | Above a declared uncertainty threshold, disclose before consent | Fixture threshold 0.35; authenticated disclosure must precede authenticated consent | Signed uncertainty value; separate disclosure/consent role signatures over exact state/facts; disclosure value matches assessed value; trusted ordering sequence | Missing or reversed order: require disclosure; zero dispatch | Retain both ordered events; no entropy/gharar equivalence |
| B.5.NASL, v0.4 §5 → B.family | Biometric family/kinship inference requires explicit legal basis | Prohibit such inference when legal basis is absent | Signed inference-use and explicit-basis assessment; relying party must trust qualified domain/legal assessment; this fixture does not decide law | Deny before dispatch | Retain basis/inference assessment |
| B.5.DIN, v0.4 §5 → B.attribute | No religious-affiliation inference, derivation or feature use | Prohibit the religious-attribute-use assessment | Signed audit fact covering those three uses | Deny before dispatch | Retain audit; no religious compliance closure claim |
| EXP → T.privacy | Synthetic rule forbids committing a record using identifiable customer data, even with consent | Absolute prohibition when identifiable-data use is present | The same exact-request facts and authenticated consent available to A/B | Deny despite A/B admission | Existing exact-effect proof on otherwise permitted cases |
| EXP → X.conflict | Neither supplied extract supplies a priority for contradictory trusted assessments | Expose contradiction and require external resolution | Two trusted, exact-state fact records disagree; neither is silently preferred | REQUIRE_EXTERNAL_RESOLUTION; zero dispatch | Retained conflict trace; no fictional committed A=0 effect |

The numerical and procedural choices are explicit external provisioning, not
attributed theology: one approval is the smallest tested A instantiation, not a
claim that it always suffices; two distinct principals instantiate B's
multi-party rule; 0.35 is a declared fixture parameter, not a religious value.
The uncertainty numbers are synthetic normalized proxy values; no predictive
model or entropy-to-gharar measurement is produced by the experiment.
All requirements are conjunctive. Unsatisfied rules remain visible; the external
layer does not balance them through a hidden utility function.

Deliberately unmapped concepts are the six A names considered individually,
religious validity/certification, full theological completeness, a formal
definition of gharar, global benefit/harm optimisation, a general dignity metric,
and unspecified priorities between normative objectives. The supporting concept
note supplies no executable rule. These omissions prevent unsupported source
expansion. They are not encoded inside generic metadata.

## 4. Executable policies and the adapter boundary

[policies.json](../../experiments/constitutional-substitution/policies.json)
contains the complete reviewable policy artifacts. Their four external operators
are `require_facts`, `forbid_all`, `approvals`, and `disclosure`.

| Policy | Executable obligations | Admission-policy digest |
| --- | --- | --- |
| A | Require owner/purpose/harm/privacy/truth/audit review checks; require one state/facts-bound validated principal | `sha256:e5096682fd029f32fdd1bd35979466de38a3abf6a90ce757297d84bda39a068c` |
| B | Conditional two-principal safety approval; prohibit bias-reward conjunction; disclose uncertainty above 0.35 before consent; prohibit biometric-family inference lacking basis; prohibit religious-attribute use | `sha256:f08191828e9e56b07e6bf05f571a577b4882152808b3aeff4a768be9e8d7564e` |
| T | Synthetic absolute identifiable-data prohibition | `sha256:119c2f5fdfae2d728325961bcea099d0b9797c1eceac938b76ab62df47bcb86b` |

These digests cover the serialized individual compiled policy, not the whole
JSON specification or the truth of its evidence. The relying party supplies
the expected digest and public role/principal roots separately. A producer's
alternative policy fails the independently expected hash check.

The small adapter/evaluator is test-only code in
[constitution_policy_test.go](../../experiments/gosmig-simulation/constitution_policy_test.go).
Compilation validates a transparent typed requirement schema and rejects
unrecognized fields/operator kinds. Evaluation authenticates evidence, checks
exact proposal/state/facts bindings, counts distinct principals, evaluates every
rule, and emits witnesses and failure reasons. No adapter callbacks, opaque
executable blobs, new production claims, or consequence-class encodings exist.

Its output includes the policy/evidence/facts digests, accountable owner, control
record, each source-linked rule's outcome, required approval count, validated
principals and witness references. Thus A admission exposes the requirements
actually evaluated and the control evidence used; it is not a signed
`AuthorityActive=true` in place of review.

The adapter owns no database handle, private signing key, trust-root selection,
custody, native dispatch, physical causality, current observation or closure.
The independently provisioned admission authority signs only after ALLOW on the
ordinary path. Issuance and evaluation are logically separated in the harness,
not deployed as independently administered production services.

A fresh policy-replay process receives public policy, expected hash, request,
evidence and independently provisioned public roots through stdin. It receives
no SQL credential, DB handle or private signer key. Its evaluation must match the
primary evaluation exactly. This demonstrates process separation and reproducible
evaluation, not an independently written implementation or independent scholar.

## 5. Real native effect and identical-input disagreements

[constitution_native_test.go](../../experiments/gosmig-simulation/constitution_native_test.go)
calls the already existing `setupUnifiedEffectRecord`,
`executeUnifiedEffectRecord`, `observeUnifiedEffectRecord` and portable inspection
helpers. It does not replace their implementation. This is the repository's
existing native research profile, not a newly shipped execution adapter.

The physical effect is one non-idempotent PostgreSQL ledger INSERT with amount
1. The same atomic business-effect row retains the existing stable effect key,
attempt, executor, state and commit authority facts. Existing transactional
target/authority locks serialize admission authority through physical commit.
The retained native primary key excludes a repeated dispatch in the same world.

Within every A/B/T triplet the request bytes, executor, subject, target, actual
destination, available signed evidence, public roots, initial authority and
effect identity are identical. Only the external policy and its expected
admission hash change. A privileged fixture reset restores the same initial
database between counterfactual worlds. That reset is not runtime recovery or
permission to erase production history. Replay is tested inside each retained
allowed world, where no such reset intervenes.

| Fixed item | Value |
| --- | --- |
| Subject | `subject:native-001` / service |
| Executor | `executor:A` / worker |
| Attempt | `attempt:native-001` |
| Intent/operation | `append-native-ledger`, amount 1 |
| Target | `native-target:acct-001` |
| Before and required after state | `rev:1`, `sha256:native-state-1` |
| Destination | Same runner DB and `native_destination_fence_v1.ledger` within each comparison |
| Request digest | `sha256:c71b286726d1040e197e6e3b51c7d536749edc84a30d8f493749bdc0bf793666` |
| Existing admission binding | `sha256:ae33bbbbe133ea22f75dd898d6f7d6e43e8760c9af745661b278df3e0477e82f` |
| Existing effect identity | `sha256:929c722b00f01f6ad86ac4b694dcc763e0c2fed7dee16f3167f7fa7656857fa8` |
| Independent claim obligation | `EXACT_EFFECT`, `postgresql/native-fence/v1`, same current-state predicate |

The decisive A/B comparison has a satisfactory A review, one validated principal,
a safety-impact fact, low uncertainty and no prohibited B use. A allows and
commits one effect; B requires a second principal and does not dispatch. The
effect, claim type and evidence substrate do not change. With two distinct
principals both constitutions allow; two keys belonging to one principal do not
satisfy B. The topology difference comes solely from external policy.

The third control is materially different: even when the same facts record
favorable review and authenticated consent, its absolute identifiable-data
prohibition denies the effect that A/B allow. It is synthetic and makes no moral
authority claim. Approval or consent cannot override its explicit prohibition.

The reverse A/B comparison is also executable: with an ordinary non-safety
effect and no human validation, A requires approval while the B §5 fragment
allows under the common baseline. This result depends on the explicitly declared
operative-fragment scope. Section 5's silence is not a ruling that the full draft
authorizes all such actions. No priority or permission is attributed to the
unreviewed remainder of the document.

## 6. Executed decision matrix, capability and conflict controls

The native matrix contains **17** counterfactual scenarios × **3** constitutions
= **51** trials: **28** admitted committed worlds and **23** blocked worlds.
There are **11** decision triplets with identical-input disagreement. All allowed
matrix worlds produce exactly one physical effect, generic `EXACT_EFFECT`
verification with A/C/P = `111`, and `CLOSED`. Every other matrix world stops
before dispatch and has zero physical effects.

| Scenario | A | B | T |
| --- | --- | --- | --- |
| ordinary-validated | ALLOW | ALLOW | ALLOW |
| same-effect-safety-one-approval | ALLOW | REQUIRE_HUMAN_APPROVAL | ALLOW |
| safety-two-approvals | ALLOW | ALLOW | ALLOW |
| capability-without-validation | REQUIRE_HUMAN_APPROVAL | ALLOW | ALLOW |
| valid-policy-hash-failed-underlying-review | DENY | ALLOW | ALLOW |
| missing-required-evidence | REQUIRE_EVIDENCE | ALLOW | ALLOW |
| valid-human-signature-wrong-state | REQUIRE_EVIDENCE | REQUIRE_EVIDENCE | REQUIRE_EVIDENCE |
| high-uncertainty-without-disclosure | ALLOW | REQUIRE_DISCLOSURE | ALLOW |
| uncertainty-disclosed-before-consent | ALLOW | ALLOW | ALLOW |
| consent-before-disclosure | ALLOW | REQUIRE_DISCLOSURE | ALLOW |
| same-effect-identifiable-with-consent | ALLOW | ALLOW | DENY |
| documented-bias-reward | DENY | DENY | ALLOW |
| biometric-family-without-legal-basis | DENY | DENY | ALLOW |
| religious-attribute-use | DENY | DENY | ALLOW |
| conflicting-trusted-assessments | REQUIRE_EXTERNAL_RESOLUTION | REQUIRE_EXTERNAL_RESOLUTION | REQUIRE_EXTERNAL_RESOLUTION |
| missing-fact-attestation | REQUIRE_EVIDENCE | REQUIRE_EVIDENCE | REQUIRE_EVIDENCE |
| two-keys-one-human-principal | ALLOW | REQUIRE_HUMAN_APPROVAL | ALLOW |

For **Capability ≠ Authority**, SQL `has_table_privilege(current_user, ledger,
'INSERT')` returns true in every world. In A's no-validation world the review
is present but the required validation is absent: admission fails, dispatch is
blocked, and the native effect count is zero. A's validated comparison preserves
the capability, target and execution substrate, supplies the required evidence,
and commits one effect. The no-validation A/B comparison additionally changes
only constitution with identical available evidence. A-at-commit is **undefined**
in a no-effect world; no committed A=0 effect is manufactured. This operational
distinction is inherited, not an Aegis novelty claim.

The conflict case supplies two equally trusted exact-state records. One affirms
the harm review and the other contradicts it. Neither source extract specifies
a priority that would select one. The external policy exposes this and returns
REQUIRE_EXTERNAL_RESOLUTION under all three constitutions. No dispatch occurs.
Global benefit-versus-harm priorities remain unresolved rather than invented.

## 7. Anti-cheating and all required negative controls

| Required control | Executed result |
| --- | --- |
| Technical capability present but constitution denies | A negative harm review → DENY; INSERT privilege true; zero effects |
| Potentially permissible action lacks required evidence | A missing purpose check → REQUIRE_EVIDENCE; no dispatch |
| Correct policy hash, underlying sourced rule fails | A negative harm check with authentic evidence and correct hash → DENY; no dispatch |
| Valid human signature covers wrong state | Correct signature over a different state → REQUIRE_EVIDENCE; no dispatch |
| A allows, B requires stronger approval | One-principal safety triplet → A one effect; B zero effects |
| B allows, A blocks/escalates where source-grounded | Ordinary unvalidated action → A requires approval; B fragment allows; scope caveat above |
| Unresolved external conflict | Contradictory trusted assessments → external resolution; zero effects |
| Adapter self-authorization | Untrusted adapter admission key rejected by existing native boundary; zero effects |
| Success after valid admission | 28 matrix worlds → one effect each, A/C/P 111, CLOSED, generic consumer supports EXACT_EFFECT |
| Post-effect current-state drift | Three extra A/B/T worlds retain one effect and exact cause; current state drift changes 111 to 110 and closure to UNKNOWN |
| Producer substitutes policy | Independent expected policy hash rejects alternative policy before dispatch |
| External ALLOW followed by authority revocation | Native commit fence rejects execution; zero effects; commit coordinates undefined |
| Two keys presented as two people | Both keys map to one principal; B still requires a second principal |
| Trusted issuer violates its issuance contract | One deliberately noncompliant effect executes and effect-finality verifier supports CLOSED; external replay records the unsatisfied validation |

The last row is a deliberately **exposed limit**, not a successful normative
admission and not included in the 28 compliant matrix commits. The harness
withholds the A approval, evaluates REQUIRE_HUMAN_APPROVAL, then intentionally
bypasses that decision using the already trusted admission signer's key. The
unchanged native boundary and portable verifier accept its authentic assertion.
This falsifies any stronger assertion that authentic admission necessarily proves
the underlying source-derived checks. It does not require a constitution-specific
execution relation; it limits the existing trusted-issuer claim.

The total additional controls include three successful initial executions with
subsequent current-state drift, policy substitution, untrusted self-authorization,
revocation, and the trusted-issuer limit. Per-trial invariance is recorded for 55
paired trials: 51 matrix worlds, three initial drift worlds and one policy-
substitution world. The remaining native boundary controls are enclosed by the
whole-run invariance snapshots. Production sources do not change in any control.

### Semantic-smuggling inventory

| New item/dependency | Category | Why it is external, and its limit |
| --- | --- | --- |
| Policy IDs/source references, rule kind, conditions, minimum, threshold, conflict disposition | A: constitution-specific policy | Transparent finite operators; no opaque code, theological callback or closure rule |
| Owner, control record, purpose/harm/privacy/truth/audit flags | B: required evidence | Signed review assessments; not kernel truth coordinates and not machine proof that the assessment is correct |
| Safety impact, bias/reward, family inference/legal basis, protected-attribute/identifiable-data use, uncertainty value | B: required evidence | Trusted domain assessments; no new causal/effect relation; external observer completeness remains assumed |
| Proposal/state/facts digest, principal identity, approval/disclosure/consent event and sequence | B: required evidence | Authenticate the exact reviewed proposition and declared ordering; do not own effect identity or custody |
| Independent policy hash and public role/principal roots | A/B: relying-party provisioning | Supplied outside the adapter; producer cannot substitute them; this is fixture provisioning, not a production distribution service |
| Generic rule/evaluation trace, public replay input and decision labels | A/B: external policy/evidence | Transparent admission results; labels are not new runtime dispositions or portable effect claim types |
| Existing native SQL locks, stable ledger key, atomic origin row and current-state observation | C: domain enforcement | Entire preexisting implementation unchanged; no normative data is consulted by these functions |
| Existing evidence consumer, runtime binding/effect helpers, Ed25519/JSON, subprocess and fingerprint tooling | B/C: evaluation and inspection support | No new production dependency, kernel API, trust architecture or execution primitive |
| New universal execution-governance relation | D | **None required by these mapped operative fragments** |

No policy field secretly determines causality, rewrites authority-at-commit,
changes the selected closure question, transforms UNKNOWN into permission, or
grants replay. The facts map is inspectable and bounded by explicit rules; it is
not a giant policy blob encoding unimplemented execution semantics. Assertions
such as “harm review passed” remain externally attested judgments, with that
limitation stated rather than claimed as complete automated moral evaluation.

## 8. Kernel and verifier invariance

The complete production/type/public API inventory, including each source hash,
Git blob, type declaration and public declaration header, is retained in
[production-inventory.json](../../experiments/constitutional-substitution/production-inventory.json).
The lexical inventories supplement exact byte preservation; they are not
presented as an AST proof or a count of fundamental semantic primitives.

| Fingerprint | Kernel `governedaction` (K0) | Verifier `evidenceverify` (V0) |
| --- | --- | --- |
| Complete component Git tree | `6c6b1e754a369cf8d30f627af1ead8b9b3835f14` | `38b05674a4ab48989cfc5b25bf7351ccfd7dd64d` |
| Canonical production SHA-256 | `521371fb3ec22c7ab3054ba664ec0e5e7f570e8847113b1ad867b46e85a67ea1` | `66ee7a8ec32caffb2bd8fa28754b07a064455b2dac28d92eddd98895765a8e3d` |
| Non-test Go source files | 8 | 6 |
| Source lines / bytes | 1550 / 51499 | 1254 / 50108 |
| Lexical type declarations | 36 | 37 |
| Public declaration headers | 72 | 29 |
| Added production primitives/types/APIs/dependencies | 0 | 0 |

Canonical production SHA-256 uses sorted repository-relative non-test `.go`
paths, then path UTF-8 + NUL + an eight-byte big-endian byte length + exact source
bytes. Complete Git trees also pin component tests. Line counts are descriptive;
exact bytes and complete tree identities establish preservation.

| Stage | Kernel before → after | Verifier before → after | Production/type/API semantic delta |
| --- | --- | --- | --- |
| A, all matrix and current-truth trials | K0 → K0 | V0 → V0 | 0 |
| B, all matrix and current-truth trials | K0 → K0 | V0 → V0 | 0 |
| T, all matrix and current-truth trials | K0 → K0 | V0 → V0 | 0 |
| Anti-cheating and whole execution | K0 → K0 | V0 → V0 | 0 |

K0 and V0 in every cell denote the full exact fingerprints above, not similarity
of counts. Each ordinary trial has `fingerprint-before.json` and
`fingerprint-after.json`; the result checker compares every member except the
descriptive stage name. There are 55 equal pairs. Whole-run snapshots additionally
cover every other control. All existing repository files, not just these two
packages, are protected by the 812-file exact-byte/mode gate.

The semantic primitive inventory before/after remains `Identity`, `State`,
`Attestation`, `Transition`. A/C/P are truth coordinates, not three newly counted
Go types. Kernel type/public API inventories remain exact; the adapter's test-only
record types are not production primitives.

| Semantic obligation | Before | After A / B / T |
| --- | --- | --- |
| A(e) | Continuing governed authority for the exact subject, action/effect, target, generation/epoch and enforcing boundary was valid at actual physical commitment | Identical; external ALLOW cannot override a revoked native authority |
| C(e,q) | Actual physical effect caused by the exact evaluated attempt and executor | Identical; native retained origin supplies the same exact-attempt evidence |
| P(e,q,t_o) | Independently selected current required predicate true at observation | Identical; current drift stays a P failure regardless of constitution |
| Effect identity | Existing logical stable identity, separate from attempt/executor origin | Identical; no policy-dependent identity or physical-effect substitution |
| Supported portable claim types | EXACT_EFFECT, POSTCONDITION | Identical; all successful experiment worlds independently require EXACT_EFFECT |
| Runtime dispositions | REJECTED, UNKNOWN, CLOSED | Identical; external REQUIRE_* labels do not enter this enum |
| Custody phases | RESERVED, CROSSING, UNKNOWN, CLOSED | Identical; this existing native profile uses the unified effect/origin row and adds no custody register |
| Retry/replay | No automatic retry; UNKNOWN grants no retry; retained stable native effect key excludes replay | Identical; repeated admitted append rejected in each retained allowed world |
| Recovery/reconciliation | Existing read-only observation does not grant execution on uncertainty | Identical source/API; no normative recovery callback |
| Succession/current observation | Existing authority-generation/epoch and independent current-observation contract | Identical source/API; no constitution-specific succession rule |
| No-effect world | No physical commitment; A-at-commit undefined | Identical; no fabricated committed-effect cube point |

The question selected by the relying party remains fixed during each comparison;
its answer can change when current reality drifts. Normative admissibility never
absorbs post-effect truth. The three drift controls retain valid commit authority
and exact historical cause while changing only the observed state: `111` becomes
`110`, closure becomes UNKNOWN, and the effect count remains one.

The generic portable consumer is the unchanged production
`cmd/aegis-evidence-inspect`, built and executed in separate processes with public
policy and proof files. Its dependency check excludes runtime, internal producer,
SQL driver and constitution code. It checks authentic independently selected
admission/policy, exact physical-effect evidence, commit authority, required
current truth and claim support. It does not answer whether a constitution is
religiously valid, and it does not independently replay the external normative
facts. Native observation and role attestations remain trusted fixture inputs.
Binary hashes are retained in each archive; across build SHAs, VCS build metadata
may change the binary hash without changing these pinned production sources.
The unchanged consumer Git tree is `37e8f0f5ba38e3e4ddd9d30c812166367a073ed2`;
its production `main.go` SHA-256 is
`686f031e23ca28d47da2d1599fc39ec135743ddc8080058f75b0641e0922bfcf`.
The corrected run's consumer binary SHA-256 is
`7c9e2f79e3094c69ae5482e02dc77e76fae00d9956bf86107f3c47d8d2ff57b4`.

The leakage scan examines **249** production Go/BPF C/header files for Taqwa,
Amana, Sidq, Huda, Maslaha, La darar, Maqasid, the five Hifz names, Sharia and
Orionech. It finds **zero** lexical leaks. Neutral-name smuggling is also
excluded as an introduced production change by exact preservation of every
preexisting file and restriction of additions to research paths. External
admission facts and the trusted-issuer limitation were separately inspected.

## 9. Verification limits and unresolved questions

The first reviewed revision passed the constitutional native experiment. Its preexisting `composite-postgres` job failed in the restored
custody-elimination corpus, at
`TestPostgresCompositeNoCustodyGenesisHistorySuccession/UNKNOWN`, when a fresh
controller could not reach BOOTSTRAP_READY. A direct retry also failed at that
restored-corpus gate. The production and old test/script/workflow files were
unchanged and remain so.

The observed timing is consistent with an inherited fixture freshness limit:
`production_test.go` generates bootstrap receipt time `now - 1 minute`, with
`MaxAttestationAgeSeconds=120`; `production.go` strictly rejects a receipt at or
beyond that age. Export completed at 02:32:14 UTC in the first attempt, and the
failure appeared at 02:33:14. The retry's export completed at 02:42:59 and the
gate failed at 02:44:05. The child exposes the aggregate bootstrap failure rather
than its precise failing verifier condition, so the timing explanation is an
inference, not a fully instrumented root-cause proof. No age rule was weakened,
no baseline file patched, and no retry success fabricated. This legacy CI failure
is recorded separately from the successful constitutional native result.

At the corrected executed revision, 12 of the 13 CI checks passed, including
`constitution-native`, unit/integration, kernel shrink, native PostgreSQL and
the existing three-domain gate. The preexisting `composite-postgres` check again
failed at the restored custody corpus in
[run 37256521383](https://github.com/achirothmane/aegis-ege/actions/runs/37256521383/job/111594678633).
Its fixture export completed at 02:46:19 UTC and the gate failed at 02:47:25,
again consistent with that freshness inference. PR #247 remains a draft with
these earlier failures disclosed for research review.

At the subsequent exact head `5fa1ee293a551eeb10db5ea41dfaa1bd6ba34eaf`, all
13 checks passed. The unchanged composite corpus passed both restored custody
controls and native effect-record replay-exclusion falsification in
[run 37257520083](https://github.com/achirothmane/aegis-ege/actions/runs/37257520083/job/111597677179).
This later success required no source, fixture-generator, freshness-rule or
legacy workflow changes. It establishes a complete passing reviewed-head run;
it does not erase the earlier timing-sensitive failures or prove their precise
root cause. PR #247 remains a draft research artifact, not a merged product change.

**Resumed exact-head status.** At `b399e5b3c2a2aa776e5ff8f25051d9d312a192c3`,
the constitutional native experiment, unit/integration, kernel shrink,
native PostgreSQL and the existing three-domain gate passed. The first
`composite-postgres` attempt failed in the restored corpus at the same
`TestPostgresCompositeNoCustodyGenesisHistorySuccession/UNKNOWN` gate in
[job 111600053884](https://github.com/achirothmane/aegis-ege/actions/runs/37258339279/job/111600053884).
Its fixture export completed at 03:13:00.9901691 UTC; the controller's aggregate
BOOTSTRAP_READY rejection appeared at 03:14:00.226709892 UTC.

One targeted rerun, with no source or workflow changes, also failed at that gate
in [job 111619403785](https://github.com/achirothmane/aegis-ege/actions/runs/37258339279/job/111619403785).
Fixture export completed at 04:47:41.5826238 UTC; the same aggregate rejection
appeared at 04:48:41.075897202 UTC. The fixture exporter uses
`time.Now().UTC().Truncate(time.Second)` before the existing `now - 1 minute`
receipt is constructed. A failure slightly less than 60 seconds after export
completion can therefore be consistent with the strict 120-second receipt-age
limit. This remains a timing-consistent inference: the child does not expose the
exact failing verifier condition, and private Genesis inputs are not in the
public archive. No clock, freshness rule, baseline test or workflow was changed.
No further rerun was used to search for a favorable result.

The original failure archive, artifact `11322844146` (28848685 bytes), has SHA-256
`3729b2c57576ff7d30a788101fa3b3463fadedea0bb6d50b52a21400c76690ad`.
The rerun failure archive, artifact `11326146348` (28846785 bytes), has SHA-256
`5c70bb5a485d3a9dd7d684f9de3979a84b263dccc3b3ab9ea374226a7e2ddc8e`.
Both were downloaded and their digests checked; both retain the same restored
failure in `live-custody-reduction/restored.jsonl`, with no skipped restored
cases. The deliberate semantic/retention mutants' expected failures are separate
from this unmodified restored-corpus failure. Both attempt artifacts remain
available; the rerun does not replace the earlier observation.

The resumed head consequently has **12 passing checks and one failing legacy
check**, even though its normative code is identical to the earlier all-green
head. U4 remains a bounded constitutional-native finding; complete current-head
legacy CI stability is unresolved. PR #247 remains a draft for research review.
Subsequent report/index commits only document these exact-head snapshots; their
checks must be read at their own head and cannot be inferred from older runs.

Other bounds are substantial: this is one real native PostgreSQL research
substrate, finite policy fragments, synthetic human-role/observer evidence, and
trusted external issuers. It does not exercise physical safety hardware, establish
actual human deliberation, determine legal basis, automatically measure unjust
harm, or audit every obligation in the full source documents. Administrative
fixture reset capability is not an enforcement guarantee against an unmediated
privileged writer. Succession/recovery semantics are preserved by exact source
pins and existing controls, not newly generalized by the adapter.

Unresolved source priorities remain external. No source-grounded requirement in
the supplied operative fragments required a new universal relation. Unmapped
full-document/theological questions cannot be counted as proven portable. A future
requirement for cryptographically proven underlying normative evaluation despite
a dishonest trusted issuer would demand a stronger external issuance/evidence
contract than demonstrated here; this report does not silently treat its existing
admission assertion as such a proof.

## 10. Strongest justified claim and exact withheld claims

**Within the supplied operational fragments, independently provisioned truthful
evidence/admission contracts, and the existing native PostgreSQL profile, what
must be satisfied before an effect is allowed can change materially while exact
effect identity, commitment authority, actual-attempt causality, current truth,
replay exclusion, closure and generic independent effect verification stay
unchanged.** The same evidence can produce ALLOW, stronger approval, disclosure,
denial or external resolution solely through external transparent policy.
Three materially different policy fragments and identical-effect disagreements
justify the single U4 classification stated at the beginning, within these bounds.
The experiment also falsifies the stronger claim that the effect verifier alone
proves the underlying normative requirements from a trusted signed admission.

No new production primitive or universal execution-governance relation was
required. No kernel, verifier or existing public API was changed. This is evidence
for constitutional substitution under the declared trust contract; it is not
evidence that every normative system can be compiled honestly into that contract.

Claims explicitly withheld:

- Aegis is Sharia-compliant, issues religious rulings, or interprets Islam.
- The candidate Maqasid mappings have religious authority or qualified approval.
- Orionech is theologically complete or one approval is universally sufficient.
- Predictive entropy formalises gharar, or 0.35 is a religious threshold.
- Synthetic signatures prove real human judgment, scholarly review or legal validity.
- Full original-document coverage or invented original PDF page/file/version data.
- Authentic admission plus a policy hash proves underlying normative compliance.
- All moral/legal constitutions fit, universal proof, or universal kernel minimality.
- Aegis invented Capability ≠ Authority.
- A failure-free CI history, production readiness, or readiness to market a religious feature.

The bounded product implication is generic: an organization supplies its external
policy and trustworthy evidence/issuance contract; Aegis supplies execution
governance. No enterprise, regulatory, religious or sector-specific product
surface is built in this phase. Commercial value, adoption and integration or
recovery savings are outside this experiment and are not established by U4.
