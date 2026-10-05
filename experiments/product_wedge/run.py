"""Bounded product falsification, with an actual unchanged Aegis consumer.

No AADP/AIP/AIDP/Temporal/Restate conformance claim. Their documented guarantees
are represented only where they affect the external-effect schedules.
"""
import argparse
import base64
import concurrent.futures
import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "experiments/precedence_repro"))
from substitute import (Destination, Question, encode, fixture_bundle,
                        independently_check, sign, signing_key, trusted)

BASE = "04434db12fa0c85d3497faf6ebb40df937092c5d"
SCHEMA = "aegis/composite-evidence/v1"
FIXTURE_TIME = "2026-10-05T02:00:00Z"


def wire(value):
    # Preserve insertion order for the Go journal's field-order encoding.
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


def cd(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def rd(*parts):
    h = hashlib.sha256()
    for part in parts:
        data = part.encode()
        h.update(struct.pack(">Q", len(data)))
        h.update(data)
    return "sha256:" + h.hexdigest()


def pub(key):
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def seal(role, value, key):
    payload = wire(value)
    message = (SCHEMA + "\0" + role + "\0").encode() + payload
    return {"key_id": role + ":fixture", "payload": value,
            "signature": base64.b64encode(key.sign(message)).decode()}


class DurableLog:
    """Minimal durable-workflow result journal + linearizable successor CAS."""
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level=None)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS step(id TEXT PRIMARY KEY,status TEXT,result TEXT);
          CREATE TABLE IF NOT EXISTS owner(id INTEGER PRIMARY KEY,name TEXT,generation INTEGER);
          INSERT OR IGNORE INTO owner VALUES(1,'worker-1',1);
        """)

    def begin(self):
        self.db.execute("INSERT OR IGNORE INTO step VALUES('credit-1','issued',NULL)")

    def complete(self, result):
        self.db.execute("UPDATE step SET status='completed',result=?", (json.dumps(result),))

    def takeover(self):
        changed = self.db.execute("UPDATE owner SET name='successor',generation=2 "
                                  "WHERE id=1 AND generation=1").rowcount
        return changed == 1

    def snapshot(self):
        return {"step": self.db.execute("SELECT * FROM step").fetchall(),
                "owner": self.db.execute("SELECT * FROM owner").fetchall()}


def child_commit(path):
    d = Destination(path, fenced=True)
    result, _ = d.commit(Question())
    assert result == "COMMITTED"
    # Actual process termination after durable COMMIT, without returning a result.
    os._exit(17)


def kill_after_commit(path):
    p = subprocess.run([sys.executable, "-B", str(Path(__file__).resolve()),
                        "--child", str(path)], capture_output=True)
    assert p.returncode == 17, (p.returncode, p.stderr.decode())


def fresh_bundle(d, q, serial, history_key):
    observer = signing_key("wedge-observer")
    body = d.observe(q, serial)
    grant = d.db.execute("SELECT active,generation FROM grants").fetchone()
    body["authority_currently_active"] = bool(grant[0])
    body["current_authority_generation"] = grant[1]
    return (sign(body, observer), observer.public_key(), d.history(),
            sign({"scope": q.scope(), "head": d.head()}, history_key),
            history_key.public_key(), d.head(), serial)


def authorize_history_rotation(q, head, case):
    old, new = signing_key("wedge-history-old"), signing_key("wedge-history-new")
    body = {"case": case, "scope": q.scope(), "previous_checkpoint": head,
            "old_key": pub(old), "new_key": pub(new), "generation": 2}
    rotation = {"old": sign(body, old), "new": sign(body, new)}
    # Roots, expected scope, generation and predecessor are independent inputs.
    assert check_rotation(rotation, q, head, case, old.public_key(), new.public_key())
    return rotation, new


def check_rotation(r, q, head, case, old_root, new_root):
    if not trusted(r["old"], old_root) or not trusted(r["new"], new_root):
        return False
    b = r["old"]["body"]
    return (b == r["new"]["body"] and b["scope"] == q.scope() and
            b["case"] == case and b["previous_checkpoint"] == head and
            b["generation"] == 2 and b["old_key"] == base64.b64encode(old_root.public_bytes_raw()).decode() and
            b["new_key"] == base64.b64encode(new_root.public_bytes_raw()).decode())


def aegis_inputs(q, observed, case, history_key, lose_ack=False, optimistic=False):
    """Artifact adapter; records come from native observation, never a result label.

    The fixed postgres wire profile is consumed at SIMULATION grade for this
    SQLite mapping. This is not a claim to have executed Aegis's PG adapter.
    """
    before = {"target": q.target, "revision": "1", "digest": "value:0"}
    after = {"target": q.target, "revision": "2", "digest": "value:1"}
    request = {"subject": {"id": q.subject, "kind": "subject"},
               "executor": {"id": q.executor, "kind": "worker"},
               "before": before, "after": after, "operation": q.operation,
               "attempt_id": q.attempt}
    parts = [q.subject, "subject", q.target, "1", "value:0", q.operation, "2", "value:1"]
    request["admission_binding"] = rd("admission-v0", *parts)
    effect_id = rd("effect-v0", *parts)
    rows = observed["rows"]
    row = rows[0] if len(rows) == 1 else None
    exact = bool(row and row["attempt"] == q.attempt and row["executor"] == q.executor)
    authority = bool(exact and row["grant"][:7] == q.scope() and row["grant"][7] == 1)
    closed = authority and observed["predicate"]
    cause = "EXACT_COMMIT_RECORD" if authority else "STATE_ONLY" if observed["predicate"] else "UNPROVEN"
    closure = "CLOSED" if closed or optimistic else "UNKNOWN"
    execution = {"build_sha": BASE, "case_id": case, "grade": "simulation",
                 "claim_type": "EXACT_EFFECT", "intent_id": "intent:" + case,
                 "request": request, "effect_id": effect_id, "custody_generation": 1,
                 "authority_epoch": 1, "authority_generation": 1, "admitted": True,
                 "acknowledgement_lost": lose_ack,
                 "recovered_by": {"id": "independent-native-reader", "kind": "observer"},
                 "claimed_closure": closure, "claimed_causality": cause,
                 "claimed_history": "TRUSTED_HISTORY"}
    policy_hash = cd(b"independently selected exact effect policy")
    admission = {"build_sha": BASE, "case_id": case, "policy_hash": policy_hash,
                 "request_binding": request["admission_binding"], "observed_before": before,
                 "allowed_operation": q.operation, "authority_epoch": 1,
                 "authority_generation": 1, "authority_active": True}
    present = after if observed["predicate"] else {"target": q.target, "revision": "3", "digest": "value:" + str(observed["present_value"])}
    destination = {"build_sha": BASE, "case_id": case, "profile": "postgresql/native-fence/v1",
                   "observed": present, "effect_count": len(rows),
                   "authority_currently_active": observed.get("authority_currently_active", True),
                   "current_authority_generation": observed.get("current_authority_generation", q.generation)}
    if row:
        destination["commit"] = {"effect_id": effect_id, "attempt_id": row["attempt"],
           "owner": {"id": row["executor"], "kind": "worker"}, "custody_generation": 1,
           "admission_binding": request["admission_binding"], "authority_epoch": row["grant"][4],
           "authority_generation": row["grant"][5], "authority_active": bool(row["grant"][7]),
           "operation": q.operation, "before": before, "after": after, "committed_at": FIXTURE_TIME}
    keys = {role: signing_key("wedge-" + role) for role in ("admission", "execution", "destination", "witness")}
    keys["history"] = history_key
    bundle = {"schema": SCHEMA, "admission": seal("admission", admission, keys["admission"]),
              "execution": seal("execution", execution, keys["execution"]),
              "destination": seal("destination", destination, keys["destination"])}
    # Canonical transport strings are authenticated exactly as the CLI expects.
    binding = rd("composite-history-v1", wire(admission).decode(),
                 wire(execution).decode(), wire(destination).decode())
    history_id = "history:" + case
    entries, previous = [], ""
    # Retain a commitment to the native predecessor, including its actual row.
    events = [{"type": "OBSERVATION", "payload_digest": cd(encode(observed)), "occurred_at": FIXTURE_TIME},
              {"type": "OUTCOME", "action_id": effect_id, "attempt_id": q.attempt,
               "outcome_verdict": closure, "payload_digest": binding, "occurred_at": FIXTURE_TIME}]
    for ordinal, event in enumerate(events, 1):
        entry = {"version": 2, "journal_id": history_id, "sequence": ordinal,
                 "prev_hash": previous, "event": event, "entry_hash": ""}
        entry["entry_hash"] = cd(wire(entry))
        previous = entry["entry_hash"]
        entries.append(entry)
    anchor = {"version": 2, "journal_id": history_id, "sequence": len(entries),
              "head_hash": previous, "key_id": "history:fixture", "updated_at": FIXTURE_TIME,
              "signature": ""}
    anchor["signature"] = base64.b64encode(history_key.sign(wire(anchor))).decode()
    head = {"journal_id": history_id, "sequence": len(entries), "head_hash": previous, "key_id": "history:fixture"}
    bundle["history"] = {"entries": entries, "anchor": anchor,
                         "witness": seal("witness", {"build_sha": BASE, "case_id": case, "head": head}, keys["witness"])}
    policy = {"schema": SCHEMA, "build_sha": BASE, "case_id": case,
              "destination_profile": "postgresql/native-fence/v1", "admission_policy_hash": policy_hash,
              "required_claim_type": "EXACT_EFFECT", "maximum_grade": "simulation",
              "public_keys": {role + ":fixture": pub(key) for role, key in keys.items()},
              "role_keys": {role: role + ":fixture" for role in keys},
              "history_id": history_id, "checkpoint": head}
    return bundle, policy


def consumer(binary, bundle, policy, directory):
    bpath, ppath = directory / "bundle.json", directory / "independent-policy.json"
    bpath.write_bytes(wire(bundle))
    ppath.write_bytes(wire(policy))
    if not binary:
        return {"execution": "NOT_RUN", "reason": "actual Aegis binary unavailable"}
    started = time.perf_counter_ns()
    p = subprocess.run([binary, "--bundle", str(bpath), "--policy", str(ppath), "--format", "json"], capture_output=True)
    assert p.returncode in (0, 1), (p.returncode, p.stderr.decode())
    result = json.loads(p.stdout)
    result["process_ns"] = time.perf_counter_ns() - started
    result["exit_code"] = p.returncode
    (directory / "aegis-report.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def run_case(number, out, binary):
    q = Question()
    case = f"WEDGE-{number:02d}"
    directory = out / case
    directory.mkdir(parents=True, exist_ok=True)
    dbpath = directory / "destination.sqlite"
    d = Destination(str(dbpath), fenced=True)
    workflow = DurableLog(str(directory / "workflow.sqlite"))
    workflow.begin()
    dispatches = []
    lose_ack = number in (4, 5, 10)
    if number == 1:
        d.revoke()
        dispatches.append(d.commit(q)[0])
        assert dispatches == ["DENIED_AUTHORITY"]
    elif number in (2, 8):
        dispatches.append(d.commit(q, "request-foreign", "worker-foreign")[0])
    elif lose_ack:
        d.db.close()
        kill_after_commit(dbpath)
        d = Destination(str(dbpath), fenced=True)
        assert workflow.takeover()
        dispatches.append("COMMITTED_THEN_PROCESS_EXIT_NO_ACK")
        if number == 5:
            # A native replay rendezvous, never a fresh logical effect key.
            outcome, row = d.commit(q, "successor-attempt", "successor")
            assert outcome == "REPLAY" and row["attempt"] == q.attempt
            dispatches.append(outcome)
    else:
        dispatches.append(d.commit(q)[0])
    if number in (3, 9):
        d.mutate()
    if number == 6:
        def contender(i):
            other = Destination(str(dbpath), fenced=True)
            try:
                return other.commit(q, f"duplicate-{i}", f"successor-{i}")[0]
            finally:
                other.db.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            dispatches.extend(pool.map(contender, range(8)))
        assert dispatches[1:] == ["REPLAY"] * 8
    if number == 7:
        workflow.complete({"provider_status": "completed", "verification": "state-only"})
    history_key = signing_key("wedge-history-old")
    rotation = None
    if number == 10:
        rotation, history_key = authorize_history_rotation(q, d.head(), case)
        (directory / "upstream-key-transition.json").write_text(json.dumps(rotation, indent=2) + "\n")
    physical = d.observe(q, number)
    proof = fresh_bundle(d, q, number, history_key)
    if number == 7:
        # A genuinely weaker observer interface: do not invent the missing row.
        weaker = copy.deepcopy(proof[0]["body"])
        weaker["rows"] = []
        proof = (sign(weaker, signing_key("wedge-observer")), *proof[1:])
    start = time.perf_counter_ns()
    ordinary = independently_check(q, *proof)
    ordinary["evaluation_ns"] = time.perf_counter_ns() - start
    b, p = aegis_inputs(q, proof[0]["body"], case, history_key, lose_ack)
    # The exact relying-party question is independently fixed above, before
    # any issued/completed worker statement; both consumers receive that binding.
    actual = consumer(binary, b, p, directory)
    expected = "CLOSED" if number in (4, 5, 6, 10) else "UNKNOWN"
    assert ordinary["closure"] == expected and ordinary["history"] == "TRUSTED", (case, ordinary)
    if binary:
        assert actual["closure"] == expected and actual["historical_trust"] == "TRUSTED_HISTORY", (case, actual)
        if number not in (2, 8):
            assert actual["claims_supported"], (case, actual)
    rows = physical["rows"]
    assert len(rows) == (0 if number == 1 else 1)
    truth = None if not rows else [int(rows[0]["grant"][7] == 1),
             int(rows[0]["attempt"] == q.attempt and rows[0]["executor"] == q.executor),
             int(physical["predicate"])]
    result = {"case": case, "physical_truth_ACP": truth, "physical_effect_count": len(rows),
              "dispatches": dispatches, "durable_workflow": workflow.snapshot(),
              "substitute": ordinary, "aegis": actual,
              "operator_actions": 0, "observer_reads_after_recovery": 1,
              "evidence_grade": "SQLite-native / Aegis wire simulation",
              "upstream_key_transition_verified": rotation is not None}
    (directory / "native-observation.json").write_text(json.dumps(physical, indent=2) + "\n")
    (directory / "standard-evidence.json").write_text(json.dumps({"observation": proof[0], "history": proof[2], "checkpoint": proof[3]}, indent=2) + "\n")
    (directory / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    workflow.db.close()
    d.db.close()
    return result


def controls(out, binary):
    q = Question()
    findings = {}
    # Real read/recheck-to-commit gap on a destination lacking an atomic fence.
    d = Destination(fenced=False)
    d.revoke()
    _, row = d.commit(q)
    assert row["grant"][7] == 0
    findings["no_native_authority_fence"] = {"effect_count": 1, "authority_at_commit": False,
        "substitute": independently_check(q, *fixture_bundle(d, q))["closure"],
        "aegis_enforcement_advantage": False}
    d.db.close()
    # Correct native observation retained as an old signed artifact is not NOW.
    d = Destination(fenced=True)
    d.commit(q)
    old = fixture_bundle(d, q, time=1)
    d.mutate()
    assert independently_check(q, *old)["closure"] == "CLOSED"
    assert independently_check(q, *fixture_bundle(d, q, time=2))["closure"] == "UNKNOWN"
    b, p = aegis_inputs(q, old[0]["body"], "STALE-OFFLINE", signing_key("wedge-history-old"))
    directory = out / "STALE-OFFLINE"
    directory.mkdir(exist_ok=True)
    actual = consumer(binary, b, p, directory)
    if binary:
        assert actual["closure"] == "CLOSED" and actual["claims_supported"]
    findings["authentic_offline_snapshot_after_drift"] = {
        "world_now": False, "ordinary_old_artifact": "CLOSED_AS_OF_OLD_OBSERVATION",
        "aegis_old_artifact": actual.get("closure", "NOT_RUN"),
        "fresh_native_observation": "UNKNOWN", "interpretation": "neither offline format establishes perpetual freshness"}
    # The strongest substitute must not use independently_check's closed bit
    # while silently ignoring an untrusted historical chain.
    broken = list(fixture_bundle(d, q, time=2))
    broken[2] = []
    report = independently_check(q, *broken)
    assert report["history"] == "UNTRUSTED"
    findings["broken_history"] = {"standalone_history": report["history"], "finality_allowed": False}
    d.db.close()
    oldkey, newkey = signing_key("wedge-history-old"), signing_key("wedge-history-new")
    rotation, _ = authorize_history_rotation(q, "head", "CONTROL")
    rotation["new"]["body"]["case"] = "OTHER"
    assert not check_rotation(rotation, q, "head", "CONTROL", oldkey.public_key(), newkey.public_key())
    findings["substituted_key_succession"] = "REJECTED"
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--child")
    parser.add_argument("--out", default="/tmp/product-wedge")
    parser.add_argument("--aegis-binary")
    args = parser.parse_args()
    if args.child:
        child_commit(args.child)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    for name in ("WEDGE-01", "WEDGE-02", "WEDGE-03", "WEDGE-04", "WEDGE-05", "WEDGE-06", "WEDGE-07", "WEDGE-08", "WEDGE-09", "WEDGE-10"):
        assert not (out / name / "destination.sqlite").exists(), "use a fresh output directory"
    start = time.perf_counter_ns()
    cases = [run_case(n, out, args.aegis_binary) for n in range(1, 11)]
    report = {"baseline_sha": BASE, "aegis_actual_executed": bool(args.aegis_binary),
              "vendor_products_installed": False, "cases": cases,
              "controls": controls(out, args.aegis_binary),
              "runtime": {"python": sys.version.split()[0], "sqlite": sqlite3.sqlite_version},
              "total_ns": time.perf_counter_ns() - start,
              "scope": "shared native destination + actual Aegis evidence consumer; NOT both full executors"}
    (out / "results.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({"cases": len(cases), "aegis_executed": bool(args.aegis_binary),
                      "closed": [c["case"] for c in cases if c["substitute"]["closure"] == "CLOSED"],
                      "semantic_advantages_demonstrated": 0}))


if __name__ == "__main__":
    main()
