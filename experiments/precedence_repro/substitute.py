"""Known-mechanism substitute; no imports from any Aegis runtime or experiment.

SQL transaction + ongoing scoped authorization + exact writer provenance +
stable operation deduplication + current read + independently pinned policy,
Ed25519 roots and authenticated checkpoint. Fixture keys are public test seeds.
This is not an implementation of the named literature's production software.
"""
import hashlib
import json
import sqlite3
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return hashlib.sha256(encode(value)).hexdigest()


@dataclass(frozen=True)
class Question:
    subject: str = "operator"
    operation: str = "write"
    target: str = "account"
    boundary: str = "destination"
    epoch: int = 1
    generation: int = 1
    effect_key: str = "credit-1"
    attempt: str = "request-1"
    executor: str = "worker-1"
    required_value: int = 1
    claim_type: str = "EXACT_EFFECT"

    def scope(self):
        return [self.subject, self.operation, self.target, self.boundary,
                self.epoch, self.generation, self.effect_key]


class Destination:
    def __init__(self, path=":memory:", fenced=False, sole_origin=False,
                 immutable=False, expiring=False):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.fenced, self.sole_origin = fenced, sole_origin
        self.immutable, self.expiring = immutable, expiring
        self.db.executescript("""
        CREATE TABLE IF NOT EXISTS grants(subject TEXT,operation TEXT,target TEXT,
          boundary TEXT,epoch INTEGER,generation INTEGER,effect_key TEXT,active INTEGER);
        CREATE TABLE IF NOT EXISTS business(effect_key TEXT PRIMARY KEY,
          body TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS current_value(target TEXT PRIMARY KEY,
          value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS journal(seq INTEGER PRIMARY KEY,
          previous TEXT, body TEXT, hash TEXT);
        """)
        if not self.db.execute("SELECT 1 FROM grants").fetchone():
            self.db.execute("INSERT INTO grants VALUES ('operator','write','account',"
                            "'destination',1,1,'credit-1',1)")

    def revoke(self):
        self.db.execute("UPDATE grants SET active=0")

    def restore(self):
        self.db.execute("UPDATE grants SET active=1")

    def advance_generation(self):
        self.db.execute("UPDATE grants SET generation=generation+1")

    def commit(self, q, attempt="request-1", executor="worker-1"):
        self.db.execute("BEGIN IMMEDIATE")
        try:
            prior = self.db.execute("SELECT body FROM business WHERE effect_key=?",
                                    (q.effect_key,)).fetchone()
            if prior:
                self.db.execute("COMMIT")
                return "REPLAY", json.loads(prior[0])
            grant = self.db.execute("SELECT * FROM grants").fetchone()
            valid = list(grant[:7]) == q.scope() and grant[7] == 1
            if self.fenced and not valid:
                self.db.execute("ROLLBACK")
                return "DENIED_AUTHORITY", None
            if self.sole_origin and (attempt, executor) != (q.attempt, q.executor):
                self.db.execute("ROLLBACK")
                return "DENIED_ORIGIN", None
            row = {"scope": q.scope(), "attempt": attempt, "executor": executor,
                   "grant": list(grant), "value": q.required_value}
            self.db.execute("INSERT INTO business VALUES (?,?)",
                            (q.effect_key, encode(row).decode()))
            self.db.execute("INSERT OR REPLACE INTO current_value VALUES (?,?)",
                            (q.target, q.required_value))
            previous = self.head()
            history = {"kind": "business-commit", "row": row}
            h = digest({"previous": previous, "body": history})
            self.db.execute("INSERT INTO journal(previous,body,hash) VALUES (?,?,?)",
                            (previous, encode(history).decode(), h))
            self.db.execute("COMMIT")
            return "COMMITTED", row
        except Exception:
            if self.db.in_transaction:
                self.db.execute("ROLLBACK")
            raise

    def mutate(self, target="account", value=2):
        if self.immutable:
            raise ValueError("publish-only fixture boundary")
        self.db.execute("UPDATE current_value SET value=? WHERE target=?", (value, target))

    def erase_outside_boundary(self):
        self.db.execute("DELETE FROM business")

    def head(self):
        row = self.db.execute("SELECT hash FROM journal ORDER BY seq DESC LIMIT 1").fetchone()
        return row[0] if row else "0" * 64

    def history(self):
        return [{"previous": p, "body": json.loads(b), "hash": h}
                for p, b, h in self.db.execute("SELECT previous,body,hash FROM journal ORDER BY seq")]

    def observe(self, q, time=1):
        rows = [json.loads(row[0]) for row in self.db.execute(
            "SELECT body FROM business WHERE effect_key=?", (q.effect_key,))]
        current = self.db.execute("SELECT value FROM current_value WHERE target=?", (q.target,)).fetchone()
        if self.immutable:
            predicate = bool(rows) and (not self.expiring or time < 2)
        else:
            predicate = current is not None and current[0] == q.required_value
        return {"scope": q.scope(), "rows": rows, "present_value": current[0] if current else None,
                "predicate": predicate, "time": time, "head": self.head()}


def signing_key(label):
    # Deterministic PUBLIC fixture seed. Never an account or deployment key.
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(
        ("PUBLIC-CYCLE8-FIXTURE/" + label).encode()).digest())


def sign(body, key):
    return {"body": body, "signature": key.sign(encode(body)).hex()}


def trusted(envelope, root):
    try:
        root.verify(bytes.fromhex(envelope["signature"]), encode(envelope["body"]))
        return True
    except (InvalidSignature, ValueError, KeyError):
        return False


def independently_check(q, destination, observation_root, history, checkpoint,
                        history_root, expected_head, expected_time):
    """Relying-party inputs are separate from the producer's envelopes.

    expected_time is an independently justified observation point, not an offline
    claim to know the current wall clock or future state.
    """
    if q.claim_type not in ("EXACT_EFFECT", "POSTCONDITION"):
        return {"closure": "UNKNOWN", "history": "UNTRUSTED", "reason": "claim-policy"}
    if not trusted(destination, observation_root):
        return {"closure": "UNKNOWN", "history": "UNTRUSTED", "reason": "observation-root"}
    d = destination["body"]
    if d["scope"] != q.scope() or d["time"] != expected_time:
        return {"closure": "UNKNOWN", "history": "UNTRUSTED", "reason": "binding-or-current-view"}
    head = "0" * 64
    for entry in history:
        if entry["previous"] != head or entry["hash"] != digest(
                {"previous": head, "body": entry["body"]}):
            return {"closure": "UNKNOWN", "history": "UNTRUSTED", "reason": "history-chain"}
        head = entry["hash"]
    history_ok = (trusted(checkpoint, history_root) and
                  checkpoint["body"] == {"scope": q.scope(), "head": expected_head} and
                  head == expected_head == d["head"])
    if q.claim_type == "POSTCONDITION":
        closed = d["predicate"]
    else:
        closed = False
        if len(d["rows"]) == 1:
            row = d["rows"][0]
            grant = row["grant"]
            closed = (row["scope"] == q.scope() and grant[:7] == q.scope() and
                      grant[7] == 1 and row["attempt"] == q.attempt and
                      row["executor"] == q.executor and d["predicate"])
    return {"closure": "CLOSED" if closed else "UNKNOWN",
            "history": "TRUSTED" if history_ok else "UNTRUSTED",
            "reason": "evaluated"}


def fixture_bundle(destination, q, time=1):
    observer, custodian = signing_key("observer"), signing_key("custodian")
    observation = destination.observe(q, time)
    return (sign(observation, observer), observer.public_key(), destination.history(),
            sign({"scope": q.scope(), "head": destination.head()}, custodian),
            custodian.public_key(), destination.head(), time)


def trial():
    q = Question()
    results = {}
    for name, before, after, origin in [
        ("revoked-cause-present", "revoke", None, (q.attempt, q.executor)),
        ("authorized-foreign-present", None, None, ("request-2", "worker-2")),
        ("authorized-own-drift", None, "mutate", (q.attempt, q.executor)),
        ("authorized-own-present", None, None, (q.attempt, q.executor)),
    ]:
        d = Destination()
        if before:
            getattr(d, before)()
        outcome, row = d.commit(q, *origin)
        if before:
            d.restore()
        if after:
            getattr(d, after)()
        observation = d.observe(q)
        grant = row["grant"]
        truth = [int(grant[:7] == q.scope() and grant[7] == 1),
                 int((row["attempt"], row["executor"]) == (q.attempt, q.executor)),
                 int(observation["predicate"])]
        results[name] = {"truth": truth, "native_outcome": outcome,
                         "consumer": independently_check(q, *fixture_bundle(d, q))}
        d.db.close()
    return results


if __name__ == "__main__":
    print(json.dumps(trial(), indent=2, sort_keys=True))
