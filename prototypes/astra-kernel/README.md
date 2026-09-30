# Astra — Executable Governed Action Kernel Prototype 0.1

**هذه نسخة تنفيذية أولية تعمل بالفعل:** تستقبل عملية محددة، تجمع حالة المجال، تتحقق من تصريح موقّع، تحفظ المحاولة ومسؤولية النتيجة قبل الأثر، ثم تنفّذ وتلاحظ النتيجة. تعمل فوق Linux؛ لا تحتوي على إدارة ذاكرة أو تعريفات أجهزة أو مجدول عمليات مثل نواة نظام التشغيل.

النموذج يختبر إمكانية بناء قلب تنفيذي قابل للتوسّع للحوكمة. لا يثبت بعد وجود نواة عامة أو منصة متعددة المجالات. الكود والاختبارات وسجل التجربة داخل هذه الحزمة.

## Run the executable demonstration

Tested on Linux with Python 3.12.14, SQLite 3.53.1 and cryptography 46.0.0. Python 3.12 or later is required. The signing dependency is pinned to the version used for this experiment, not claimed to be the latest release or vulnerability-audited.

Check out the experimental branch and enter the prototype directory:

```bash
git clone --branch prototype/astra-kernel-0.1 --single-branch https://github.com/achirothmane/aegis-ege.git
cd aegis-ege/prototypes/astra-kernel
```

From this directory:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -r requirements.txt
python3 -m astra_kernel demo
python3 verify.py
```

If the dependency already exists, the last two commands work directly. The demo creates and removes an isolated temporary home. It modifies real local files and a real SQLite database, and deliberately terminates an executing subprocess to test recovery. No GitHub, cloud, production database or paid API is contacted.

`evidence/validation.json`, `evidence/test-output.txt` and `evidence/demo-trace.json` contain the measured results. `verify.py` refreshes them from actual execution; it fails if any test or demo assertion fails.

## What is executable

| Kernel call | Actual behavior |
|---|---|
| `propose` | Obtain domain state automatically; normalize typed parameters; persist immutable revision, trusted profile and destination bindings. |
| `execute` | Verify issuer signature, actor/tenant, store, action revision, effect, destination, profile, time and revocation; validate domain state; commit the attempt and closure before invoking the adapter. |
| Native admission gate | Recheck authority, current profile and witness validity after preparatory IO, immediately before the pack begins its bounded effect. A gate can be consumed only once. |
| `observe` | Invoke the trusted domain observer; preserve its domain payload; record justified knowledge separately from administrative disposition. It never calls `apply`. |
| `retire_unknown` | Require a separate signed grant, elapsed profile horizon, retained custodian and explicit reason. UNKNOWN stays UNKNOWN and replay remains prohibited. |
| `revoke` | Verify an owner-signed revocation and preserve it in the journal. |
| `inspect` | Replay the journal, validate archived admission signatures/relations and expose attempts, closure and profile identities. |

The owner-side signer is separate from the Kernel API. The runtime's verifier receives a public key and operates with the issuer key removed. This demonstrates an interface separation, **not OS-enforced isolation when signer and runtime run as the same UID**.

There is no generic shell executor, arbitrary SQL endpoint, request-selectable weak profile, arbitrary plugin loader, universal retry or compensation operation.

## Two typed domain packs

| Pack | Scope and admission | Outcome and consistency |
|---|---|---|
| `file.replace` | Only `files/settings.txt`; at most 4096 UTF-8 bytes; old content hash must match; directory identity is pinned; target symlinks/hardlinks are refused. | A cooperating destination lock covers validation and replacement. A temporary stage file is attributable by effect ID. Desired content with no staging residue verifies the **current postcondition**, not causal attribution. An uncooperative OS owner can still write independently; universal filesystem CAS is not claimed. |
| `sqlite.add-column` | Only a typed TEXT NOT NULL DEFAULT column on the fixture's `people` table; schema, original rows and user_version bound; arbitrary SQL, triggers and column injection rejected. | `BEGIN IMMEDIATE` protects read and write. DDL, version increment and an effect/attempt/revision marker commit in one native transaction. Verification checks the actual column/default, preserved original rows, version and marker. Missing marker with changed state remains UNKNOWN. |

Their writable resources do not overlap: the file route cannot target the database. The core does not define either domain's state or result algebra. `VERIFIED`, `NOT_APPLIED`, `PARTIAL` and `UNKNOWN` are limited accountability projections; full typed domain payloads remain attached.

Both observation horizons are a **local profile policy of 30 seconds**. There is no automatic retirement timer. After the horizon, an explicitly authorized owner may accept residual uncertainty. This is not a universal deadline for real-world truth. Initial grants have a local maximum lifetime of 300 seconds; required state witnesses last one second and are rechecked at the native effect gate. Clock regression blocks new effects rather than resetting expiry.

This prototype deliberately permits **one attempt per logical effect**, including UNKNOWN or NOT_APPLIED attempts. A new revision or another pack cannot replay the same logical effect. That is conservative local containment, not global exactly-once execution. Further action needs a newly proposed, explicitly authorized intent; it is not an implicit retry.

## Boundary and crash semantics

SQLite records admission and accountable closure before the domain `apply` call. An abrupt process exit leaves a recoverable UNKNOWN obligation even when the response and observation were never recorded. Startup never replays effects; the operator can observe/reconcile instead.

The local journal uses a nonblocking process lock, synchronous EXTRA SQLite commits and an event hash chain. A second live runtime is refused. Takeover starts after the previous process exits; forceful overlapping worker takeover and distributed fencing are not implemented. A released runtime object cannot resume execution.

The SQLite pack's native transaction can provide negative evidence after an interrupted transaction. The file pack cannot infer historical non-execution from a currently old-looking file; it keeps UNKNOWN. A crash after staging produces PARTIAL with retained custody. There is no automatic cleanup/compensation mutation. An explicitly scoped recovery operation would require its own reviewed action and authority.

The SQLite adapter refuses an unsupported journal mode instead of changing it during observation. Opening a native SQLite connection can perform the database engine's own hot-journal recovery; this is intrinsic transaction recovery, not a new migration or application compensation command. If the observer cannot establish that recovery/state, it retains UNKNOWN.

An adapter exception never proves rollback. If the adapter may have run, the result is UNKNOWN until observation justifies more. An adapter that returns without invoking the native gate is detected as a contract violation; a reused gate is rejected. This is conformance checking of **trusted in-process packs**, not a sandbox against a malicious pack with arbitrary Python/OS access.

## Owner-controlled CLI use

```bash
python3 -m astra_kernel init /tmp/astra-new-demo-home
python3 -m astra_kernel propose-file --home /tmp/astra-new-demo-home --action config-1 --content 'mode=safe'
```

Copy the returned `action_key` into these commands:

```bash
python3 -m astra_kernel authorize --home /tmp/astra-new-demo-home --action-key ACTION_KEY --out /tmp/config-1-grant.json
python3 -m astra_kernel execute --home /tmp/astra-new-demo-home --action-key ACTION_KEY --grant /tmp/config-1-grant.json
python3 -m astra_kernel inspect --home /tmp/astra-new-demo-home
```

`authorize` is explicitly an owner-side operation using `owner/issuer.key`. That private key is never included in a proposal, permit, trace, journal or this delivered archive. Initial fixture creation necessarily creates its new demo files before the governed lifecycle; it is not a bootstrap into production Aegis/EASL.

For the database, use `propose-db --home HOME --action migration-1 --column status --default new`, then authorize/execute the returned exact revision. Use `observe --home HOME --effect-id EFFECT_ID` to reconcile a recorded possible effect. `execute --crash-at` supports four named **explicit test fault points**, not arbitrary code execution.

CLI exit codes: `0` successful command or verified execution; `2` DENY; `3` unresolved/nonverified execution or observation; `4` BUSY; `5` LOCKED/configuration/storage error; `86` injected abrupt process exit.

## Invariants represented

| Candidate invariant | Implementation and evidence |
|---|---|
| I1 Binding integrity | Revision hash includes parameters, actor, tenant, profile, effect and destination; grants bind the exact revision; tampering and revision drift are rejected. |
| I2 Admission at effect boundary | Mandatory owner authority plus actual typed domain checks; a native admission callback occurs after preparatory IO and before the first bounded effect. |
| I3 No implicit amplification | Exact destination/account pin, one local attempt per effect, single-use gate and disjoint domain write scopes. |
| I4 Continuation is not authorization | Waiting expiry, revocation/profile change after claim, clock regression, expired state witness and stale closed runtime are exercised. |
| I5 No unowned possible effect | ADMITTED attempt and closure are durable before dispatch; process-crash tests reconstruct custody and uncertainty. |
| I6 Truthful disposition | Adapter return/exception is not proof; marker/postcondition drift, stage residue, missing observation and UNKNOWN retirement retain honest dispositions. |

See `COUNTEREXAMPLES.md` for exact executable tests and coverage limits. This is empirical local conformance evidence, not a formal proof of the invariant family.

## Trust and evidence limits

- The kernel, reviewed packs, local configuration, OS UID and storage are trusted. The untrusted input boundary is structured requests/permits through the defined API/CLI. Compromise of the runtime or its OS owner is outside its enforcement guarantee.
- Local directory/resource restrictions are checked by this software. The test does not establish that a compromised control plane is architecturally incapable of accessing every resource its OS UID could reach. Dedicated OS identities and downstream least privilege would need separate deployment evidence.
- Journal chaining detects unrepaired corruption. An owner who can rewrite the journal can truncate or recompute it. There is no external audit anchor, anti-rollback guarantee, immutable evidence service or disaster recovery across loss of the whole home.
- Tests abruptly exit processes; they do not test machine power loss, dishonest fsync/storage, network partitions, multiple regions or real external providers.
- Stored domain payloads are local plaintext; only synthetic data is used. There is no multi-tenant service, encrypted evidence archive, credential broker, network listener, scheduler or dashboard.
- Both packs and all tests were implemented by one author. No held-out cohort, independent integration, native-composition value comparison, commercial demand or net human-work saving has been established.

## Relationship to the existing portfolio and queue

This is a **local executable experiment following the request to build a prototype**, hosted under `prototypes/astra-kernel/` on the `prototype/astra-kernel-0.1` branch of `achirothmane/aegis-ege`. It remains self-contained, without runtime wiring to Aegis. Its tests do not declare any Master Engineering Queue item complete or supersede the earlier reports, current normative contracts, or upstream engineering work. The upload contains synthetic test evidence and grants no production authority.

It instantiates the five candidate record families: ActionRef, DecisionBasis, EffectIdentity, ExecutionAttempt and ClosureObligation. StateWitness and signed authority are prototype boundary representations, not a replacement for earned EASL/StateBinding semantics or the Doctrine/Genesis trust spine. There is no compulsory independent ExecutionReceipt record.

This implementation is **candidate executable prototype 0.1**, not the Kernel v1 normative freeze. All test domains are design-visible. None count as post-freeze held-out generalization. A future port to Go or integration into Aegis must preserve measured behavior and use the approved, freshly verified repository state; no extraction/service decision follows merely from having this code.

## Extend deliberately

The pack contract in `astra_kernel/boundary.py` requires typed proposal construction, exact destination mapping, a protected admission session, a single native effect gate and a typed outcome observer. A new pack must be reviewed, pinned and registered by the deployment owner, retain its actual domain semantics and add conformance tests. Requests cannot install one. Dynamic/untrusted plugin isolation is not part of this prototype.

## Engineering references

The implementation uses existing mechanisms rather than claiming new cryptography or transaction machinery:

- [SQLite atomic commit](https://www.sqlite.org/atomiccommit.html)
- [SQLite synchronous behavior](https://www.sqlite.org/pragma.html#pragma_synchronous)
- [Official Ed25519 sign/verify API](https://cryptography.io/en/41.0.6/hazmat/primitives/asymmetric/ed25519/)

The API documentation reference is an earlier documented API; actual execution and package pin in this experiment use cryptography 46.0.0.
