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

The next highest-information experiment is composition with an actual
Verified-Genesis-derived succession orchestration boundary. The current
succession libraries remain library-capable, not production-orchestrated;
this experiment deliberately uses a native authority-generation transition
rather than fabricating a production Genesis caller.
