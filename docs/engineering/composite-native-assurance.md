# Portable composite assurance: first executable profile

The read-only command evaluates existing evidence without execution authority:

```sh
go build -o aegis-evidence-inspect ./cmd/aegis-evidence-inspect
./aegis-evidence-inspect --bundle bundle.json --policy trusted-policy.json
./aegis-evidence-inspect --bundle bundle.json --policy trusted-policy.json --format json
```

Supply the policy through your own trusted channel. Obtain the expected build,
case, admission policy, role keys, stable history identity and exact checkpoint
from the relying party's provisioning or witness channel. Never promote keys or
a policy downloaded with an untrusted bundle into trust because that bundle asks
you to. The CLI has no root discovery, network access, database connection,
mutation adapter or signing key. It reads two local files, capped at 8 MiB each.

Exit 0 means the reported **claims are supported**, including a supported
UNKNOWN claim. It does not mean an effect succeeded or may be retried. Exit 1
means a claim exceeds its evidence; exit 2 means input/usage could not be read.
Operational closure, history and causality are independent report dimensions.

## The experiment

The existing experimental PostgreSQL native adapter supplies the strongest
available small destination boundary: one serializable transaction locks exact
custody, exact pre-state and admission authority before inserting one effect and
advancing state. Custody now captures the authority epoch and generation during
reservation. Commitment requires that same active epoch/generation, preventing
reactivation of an old admission under a new authority generation.

The corpus admits an exact request, reserves custody, and records authorization
in a real anchored journal. A separate executor process commits the native
effect and pauses before returning its callback acknowledgement. The supervisor
revokes authority and advances its generation, then terminates the executor
with exit 93. This loses the callback acknowledgement; it does **not** inject a
packet-level PostgreSQL acknowledgement failure. Durable custody remains
CROSSING. Execution takeover, runtime replay and direct native replay cannot
produce another effect.

A new process with a PostgreSQL SELECT-only role invokes the existing runtime's
observation-only Recover path. It has no destination mutation credential and
demonstrates that an actual SQL mutation is denied. Exact native evidence closes
the effect despite current authority having been revoked. The second case
deliberately withholds the exact observation; it remains UNKNOWN even though a
case-level native tally records one effect. Withholding is explicit experiment
fault injection, not an invented database outage. Both cases preserve the
original history identity and append an outcome through its existing external
head. Losing local files cannot reenroll that identity over its retained head.

The native observer checks complete attempt/custody/transition identity;
matching post-state plus a foreign effect does not establish causality. A
separate regression changes authority generation after the last successful
runtime check. The same regression against the previous adapter demonstrates
the baseline false closure with one unauthorized-by-new-generation effect.

## Independent judgment and boundaries

`evidenceverify` uses only the standard library. It independently implements
relation digests, role-separated Ed25519 checks, strict JSON decoding, journal
v2 hashing and anchor verification. Producer-generated journal records test
encoding compatibility. Signatures and history binding use compact JSON values;
outer transport indentation is ignored, while values, escapes and key ordering
remain bound. A native export exposed this transport failure and now has a
permanent positive/tampering regression. Signed payloads are bound to the final journal
outcome; a valid unrelated history cannot bless an unrelated bundle. The
checkpoint comes from policy, not the bundle. Invalid history never rewrites
an otherwise proven operational CLOSED result.

The PostgreSQL profile trusts its independently pinned admission issuer,
destination observer, execution recorder, history signer and witness. The
observer attests the native transaction record; an offline signature is not a
cryptographic proof of PostgreSQL internals or honesty of those issuers. The
executor and observer here are controlled test fixtures. Complete mediation
assumes the native adapter's write path and protected authority/custody rows;
an administrator with direct SQL mutation can bypass that profile. This PR
does not install production database privileges or a succession orchestrator.

The external head uses PostgreSQL durable CAS outside the executor process;
it shares the destination database's failure domain. It is not independent
provider consensus. The checkpoint is a point-in-time history judgment, not
a continuing-authority lease or a proof of current successor ownership.

The CI artifact preserves exact SQL observation, effect count, authority
epoch/generation, custody owner/generation/phase, attempt/effect identities,
build SHA, process exit, recovery result, signed bundle, pinned fixture policy,
journal chain and verifier reports. `fixture-policy.json` demonstrates a
separate input channel in the experiment. It is **not** an independently
provisioned policy for another operator and must not be trusted automatically.
No private signing keys or database credentials are exported.

Evidence grades are machine-readable and limited by independent policy.
This profile accepts unit, simulation and native. It rejects hardware and
independently_reproduced without a corresponding stronger verification
profile. A separate verifier process in our CI is native verification; it is
not independent operator reproduction or physical TPM evidence.

## First-use learning

Each native case imports its bundle twice through the actual CLI and records
first/second report times, two required input files, read-only permissions,
zero mutation credentials and its investigation result. The known friction
is independent policy provisioning and interpreting UNKNOWN correctly.
Human confusion, support effort and whether a second human use is easier have
not been measured. These are pending product experiments, not inferred from
an automated rerun.

## Genesis and custodian handoff during lost acknowledgement

The next corpus composes the existing protocols in one bounded native case:
freeze successor-governance authority, rotate the quorum over the exact operation
history head, activate the co-signed new authority, then append the recovery
outcome under a distinct history custodian. Both epoch sets come from actual
production-issued `VerifiedGenesisPin.ParseHistorySuccessionEpochs` calls for
the exact native executable. Those are experiment callers; production succession
remains library-capable, not production-orchestrated.

PostgreSQL holds four logical witness policies and per-history heads. Each CAS
locks policy and head in the same transaction. Policy transitions retain both
the frozen history head and frozen authority head. The first shared witness
freeze commits before its response is lost; resumption uses retained SQL state.
The old custodian cannot self-promote using the new public policy/key: a narrow
SQL function checks `session_user`, epoch, selected history and key at the CAS
boundary. Neither history account has destination mutation or policy mutation
permission. The controller/SQL administrator remains trusted. This is one SQL
failure domain, not independent-provider consensus.

The first native run exposed a real composition gap: FileJournal's identity-only
absent enrollment expectation was interpreted as an existing sequence-zero
head by QuorumHeadStore. The permanent producer regression reproduces this
failure on main, then verifies proper absent enrollment, refusal to replace a
retained empty anchor, and refusal to discard nonzero predecessor hints. The
fix changes this existing relation; it adds no Core primitive.

The portable proof includes both exact canonical signed Genesis payloads and
envelopes, both authority approvals, their exact predecessor, the old signed
anchor, and an ordered native quorum transcript. The independent policy must
provide both expected manifest hashes/roots, both authority roots, both history
keys, old history/authority checkpoints, expected new custodian, current
checkpoint and evaluation time. The final chain must still contain the retained
old prefix. A new signer who rehashes and signs a replacement prefix is rejected
even with a freshly attested final head. The transcript may not enable NEW before
every shared witness is frozen, or claim a different authority completion.

The evaluator's succession canonicalizer supports ASCII values and exact
nonnegative integers through 2^53-1. Unsupported encodings fail closed; tests
compare the supported encoding with the actual producer canonicalizer. It does
not reimplement the whole Genesis bootstrap assurance system. The existing
bootstrap fixtures use simulated attestation/proof records. Machine-readable
component grades therefore report effect=native, succession=native,
Genesis=simulation, and overall=simulation. A signed proof is not physical TPM
evidence or independent operator reproduction.

The report identifies the new holder as `AUTHORIZED_AT_CHECKPOINT` only when
authority handoff and predecessor continuity both verify. This is append/observe
authority at the retained checkpoint, not new destination effect permission or
an indefinite future lease. `UNKNOWN + TRUSTED_HISTORY` remains UNKNOWN without
exact effect evidence. The corpus exports re-signed semantic falsifications,
including prefix rewrite, mixed Genesis source, old-key continuation, early
activation and grade inflation, alongside both positive reports.
