"""Specification-only native SQLite realization; no external dependencies.

Physical history, live target/event state, and producer receipts are distinct.
The authority facts recorded in history are facts, not stored A/C/P answers.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Profile:
    kind: str = "mutable"
    guard: bool = False
    sole_attempt: bool = False

    @property
    def name(self):
        return f"{self.kind}:guard={int(self.guard)}:sole={int(self.sole_attempt)}"


Q = ("attempt-q", "executor-a")
ACTORS = (Q, ("attempt-r", "executor-a"), ("attempt-q", "executor-b"))
SUBJECT = "subject-7"
ACTION = "set-approved"
TARGET = "target-7"
BOUNDARY = "destination-writer"
OPERATION = "operation-7"
GENERATION = 0
VALUE = "approved"
EXPIRY = 3


class Store:
    def __init__(self, profile=Profile(), path=":memory:", image=None, initialize=True):
        self.profile = profile
        self.db = sqlite3.connect(path, isolation_level=None, timeout=0.1)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA foreign_keys=ON")
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
        if image is not None:
            self.db.deserialize(image)
        elif initialize:
            self._initialize()

    def _initialize(self):
        self.db.executescript("""
        CREATE TABLE settings(kind TEXT NOT NULL, guarded INTEGER NOT NULL,
                              sole_attempt INTEGER NOT NULL);
        CREATE TABLE runtime(id INTEGER PRIMARY KEY CHECK(id=1),
                             epoch INTEGER NOT NULL, now INTEGER NOT NULL);
        CREATE TABLE grants(executor TEXT PRIMARY KEY, subject TEXT NOT NULL,
                            action TEXT NOT NULL, target TEXT NOT NULL,
                            generation INTEGER NOT NULL, boundary TEXT NOT NULL,
                            active INTEGER NOT NULL CHECK(active IN (0,1)));
        CREATE TABLE commits(id INTEGER PRIMARY KEY, operation TEXT NOT NULL,
                            subject TEXT NOT NULL, action TEXT NOT NULL,
                            target TEXT NOT NULL, generation INTEGER NOT NULL,
                            boundary TEXT NOT NULL, value TEXT NOT NULL,
                            attempt TEXT NOT NULL, executor TEXT NOT NULL,
                            committed_at INTEGER NOT NULL, commit_order INTEGER NOT NULL,
                            grant_active INTEGER NOT NULL, grant_generation INTEGER NOT NULL,
                            epoch_at_commit INTEGER NOT NULL,
                            grant_subject TEXT NOT NULL, grant_action TEXT NOT NULL,
                            grant_target TEXT NOT NULL, grant_boundary TEXT NOT NULL);
        CREATE TABLE events(effect_id INTEGER PRIMARY KEY REFERENCES commits(id),
                            value TEXT NOT NULL, valid_before INTEGER NOT NULL);
        CREATE TABLE targets(target TEXT PRIMARY KEY, value TEXT NOT NULL,
                             last_effect_id INTEGER);
        CREATE TABLE journal(sequence INTEGER PRIMARY KEY, operation TEXT NOT NULL,
                             details TEXT NOT NULL, outcome TEXT NOT NULL);
        CREATE TABLE receipts(id INTEGER PRIMARY KEY, effect_id INTEGER NOT NULL,
                              requesting_attempt TEXT NOT NULL,
                              requesting_executor TEXT NOT NULL,
                              producer_claim TEXT NOT NULL);
        CREATE TRIGGER history_is_immutable BEFORE UPDATE ON commits
          BEGIN SELECT RAISE(ABORT, 'physical history is immutable'); END;
        CREATE TRIGGER history_cannot_disappear BEFORE DELETE ON commits
          BEGIN SELECT RAISE(ABORT, 'physical history is retained'); END;
        CREATE TRIGGER event_bytes_are_immutable BEFORE UPDATE ON events
          BEGIN SELECT RAISE(ABORT, 'event bytes are immutable'); END;
        CREATE TRIGGER retained_events_cannot_disappear BEFORE DELETE ON events
          WHEN (SELECT kind FROM settings) IN ('retained','expiring')
          BEGIN SELECT RAISE(ABORT, 'event retention restriction'); END;
        CREATE TRIGGER exact_authority_at_insert BEFORE INSERT ON commits
          WHEN (SELECT guarded FROM settings)=1
          BEGIN
            SELECT CASE WHEN NOT EXISTS (
              SELECT 1 FROM grants g, runtime r WHERE r.id=1
                AND g.executor=NEW.executor AND g.active=1
                AND g.subject=NEW.subject AND g.action=NEW.action
                AND g.target=NEW.target AND g.generation=NEW.generation
                AND g.boundary=NEW.boundary AND r.epoch=NEW.generation
            ) THEN RAISE(ABORT, 'authority restriction') END;
          END;
        CREATE TRIGGER exact_creator_at_insert BEFORE INSERT ON commits
          WHEN (SELECT sole_attempt FROM settings)=1
          BEGIN
            SELECT CASE WHEN NEW.attempt!='attempt-q' OR NEW.executor!='executor-a'
              THEN RAISE(ABORT, 'creator restriction') END;
          END;
        """)
        self.db.execute("INSERT INTO settings VALUES (?,?,?)",
                        (self.profile.kind, int(self.profile.guard), int(self.profile.sole_attempt)))
        self.db.execute("INSERT INTO runtime VALUES (1,0,0)")
        for executor in ("executor-a", "executor-b"):
            self.db.execute("INSERT INTO grants VALUES (?,?,?,?,?,?,1)",
                            (executor, SUBJECT, ACTION, TARGET, GENERATION, BOUNDARY))
        self.db.execute("INSERT INTO targets VALUES (?,?,NULL)", (TARGET, "absent"))

    def clone(self):
        return Store(self.profile, image=self.db.serialize())

    def close(self):
        self.db.close()

    def apply(self, operation, ack=True, precommit=None):
        """Each operation is a real SQLite transaction. No independent truth bits."""
        op, *args = operation
        self.db.execute("BEGIN IMMEDIATE")
        try:
            outcome = "ok"
            if op in ("revoke", "restore"):
                self.db.execute("UPDATE grants SET active=? WHERE executor=?",
                                (int(op == "restore"), args[0]))
            elif op == "epoch":
                self.db.execute("UPDATE runtime SET epoch=1 WHERE id=1")
            elif op == "tick":
                self.db.execute("UPDATE runtime SET now=MIN(now+1,?) WHERE id=1", (EXPIRY,))
            elif op in ("mutate", "restore_target"):
                value = "changed" if op == "mutate" else VALUE
                self.db.execute("UPDATE targets SET value=?, last_effect_id=NULL WHERE target=?",
                                (value, TARGET))
            elif op == "erase":
                if self.profile.kind in ("retained", "expiring"):
                    outcome = "denied:retention"
                else:
                    self.db.execute("DELETE FROM events")
            elif op in ("write", "write_again"):
                attempt, executor = args
                existing = None if op == "write_again" else self.db.execute(
                    "SELECT id FROM commits WHERE operation=? ORDER BY id LIMIT 1", (OPERATION,)
                ).fetchone()
                if existing:
                    outcome = f"duplicate:{existing['id']}"
                    effect_id = existing["id"]
                else:
                    grant = self.db.execute("SELECT * FROM grants WHERE executor=?", (executor,)).fetchone()
                    runtime = self.db.execute("SELECT epoch, now FROM runtime WHERE id=1").fetchone()
                    if self.profile.sole_attempt and (attempt, executor) != Q:
                        outcome = "denied:creator"
                    elif self.profile.guard and not (
                        grant["active"] and grant["subject"] == SUBJECT and grant["action"] == ACTION
                        and grant["target"] == TARGET and grant["generation"] == GENERATION
                        and grant["boundary"] == BOUNDARY and runtime["epoch"] == GENERATION
                    ):
                        outcome = "denied:authority"
                    else:
                        order = self.db.execute("SELECT COALESCE(MAX(sequence),0)+1 FROM journal").fetchone()[0]
                        row = self.db.execute("""INSERT INTO commits
                            (operation, subject, action, target, generation, boundary, value,
                             attempt, executor, committed_at, commit_order,
                             grant_active, grant_generation, epoch_at_commit,
                             grant_subject, grant_action, grant_target, grant_boundary)
                            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (OPERATION, SUBJECT, ACTION, TARGET, GENERATION, BOUNDARY, VALUE,
                             attempt, executor, runtime["now"], order, grant["active"],
                             grant["generation"], runtime["epoch"], grant["subject"], grant["action"],
                             grant["target"], grant["boundary"]))
                        effect_id = row.lastrowid
                        self.db.execute("INSERT INTO events VALUES (?,?,?)", (effect_id, VALUE, EXPIRY))
                        self.db.execute("UPDATE targets SET value=?,last_effect_id=? WHERE target=?",
                                        (VALUE, effect_id, TARGET))
                        outcome = f"created:{effect_id}"
                if outcome.startswith(("created:", "duplicate:")) and ack:
                    # This claim names the request. It does not rewrite physical causation.
                    claim = {"operation": OPERATION, "effect_id": effect_id,
                             "request_attempt": attempt, "request_executor": executor,
                             "status": "logical operation recorded"}
                    self.db.execute("INSERT INTO receipts(effect_id,requesting_attempt,requesting_executor,producer_claim) VALUES (?,?,?,?)",
                                    (effect_id, attempt, executor, json.dumps(claim, sort_keys=True)))
            elif op == "rescope_grant":
                field, value = args
                if field not in {"subject", "action", "target", "boundary", "generation"}:
                    raise ValueError(field)
                self.db.execute(f"UPDATE grants SET {field}=?", (value,))
            else:
                raise ValueError(operation)
            self.db.execute("INSERT INTO journal(operation,details,outcome) VALUES (?,?,?)",
                            (op, json.dumps(args, sort_keys=True), outcome))
            if precommit is not None:
                precommit()
            self.db.execute("COMMIT")
            return outcome
        except BaseException:
            self.db.execute("ROLLBACK")
            raise

    def physical_state(self):
        """Sufficient native facts for bounded continuation; receipts never decide truth."""
        runtime = dict(self.db.execute("SELECT epoch,now FROM runtime").fetchone())
        grants = [dict(x) for x in self.db.execute("SELECT * FROM grants ORDER BY executor")]
        commits = []
        for row in self.db.execute("SELECT * FROM commits ORDER BY id"):
            record = dict(row)
            record.pop("commit_order")  # Absolute journal order is represented by each retained trace.
            commits.append(record)
        return {"runtime": runtime, "grants": grants, "commits": commits,
                "events": [dict(x) for x in self.db.execute("SELECT * FROM events ORDER BY effect_id")],
                "target": dict(self.db.execute("SELECT * FROM targets WHERE target=?", (TARGET,)).fetchone())}

    def observe(self, evaluated=Q, effect_id=1):
        e = self.db.execute("SELECT * FROM commits WHERE id=?", (effect_id,)).fetchone()
        if e is None:
            return None
        # Authority is checked against commit facts; live governance is not substituted.
        a = bool(e["grant_active"] and e["grant_generation"] == e["generation"]
                 and e["epoch_at_commit"] == e["generation"]
                 and e["grant_subject"] == e["subject"] and e["grant_action"] == e["action"]
                 and e["grant_target"] == e["target"] and e["grant_boundary"] == e["boundary"])
        c = (e["attempt"], e["executor"]) == tuple(evaluated)
        event = self.db.execute("SELECT * FROM events WHERE effect_id=?", (effect_id,)).fetchone()
        now = self.db.execute("SELECT now FROM runtime WHERE id=1").fetchone()[0]
        target = self.db.execute("SELECT value FROM targets WHERE target=?", (TARGET,)).fetchone()[0]
        if self.profile.kind == "mutable":
            p = target == VALUE
        elif self.profile.kind in ("retained", "erasable"):
            p = event is not None
        elif self.profile.kind == "expiring":
            p = event is not None and now < event["valid_before"]
        else:
            raise ValueError(self.profile.kind)
        return {"A": int(a), "C": int(c), "P": int(p),
                "EXACT_EFFECT": bool(a and c and p), "effect_id": effect_id,
                "operation": e["operation"], "creator": [e["attempt"], e["executor"]],
                "commit_time": e["committed_at"], "commit_order": e["commit_order"],
                "observation_time": now,
                "evidence_facts": {"active_at_commit": e["grant_active"],
                                   "grant_generation": e["grant_generation"],
                                   "epoch_at_commit": e["epoch_at_commit"],
                                   "target_value_now": target, "event_retained": event is not None}}


def all_profiles():
    return [Profile(kind, guard, sole) for kind in ("mutable", "retained", "erasable", "expiring")
            for guard in (False, True) for sole in (False, True)]


def operations():
    return [(op, executor) for op in ("revoke", "restore") for executor in ("executor-a", "executor-b")] + [
        ("epoch",), ("tick",), *( ("write", *actor) for actor in ACTORS ),
        ("mutate",), ("restore_target",), ("erase",)]
