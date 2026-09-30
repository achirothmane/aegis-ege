from __future__ import annotations

import copy
import fcntl
import os
import sqlite3
from pathlib import Path

from .model import Busy, CorruptStore, canonical, digest, loads


class Journal:
    """Single local writer, FULL-sync transactions, event-derived projection.

    Hashes detect accidental corruption; a privileged rewrite/rollback is outside this boundary.
    """

    def __init__(self, directory: Path, store_id: str, config_digest: str, *, create: bool = False, verifier=None):
        self.connection = None
        self.lock_fd = None
        self.directory = directory
        self.verifier = verifier
        if directory.is_symlink() or not directory.is_dir():
            raise CorruptStore("state directory must be an existing non-symlink directory")
        self.lock_fd = os.open(directory / "runtime.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(self.lock_fd)
            self.lock_fd = None
            raise Busy("another runtime owns this journal; takeover requires its exit") from error
        try:
            path = directory / "journal.sqlite"
            if path.is_symlink():
                raise CorruptStore("symlink journal refused")
            if create:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            elif not path.is_file():
                raise CorruptStore("missing journal: refuse automatic reset")
            self.connection = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
            self.connection.execute("PRAGMA journal_mode=DELETE")
            self.connection.execute("PRAGMA synchronous=EXTRA")
            self.connection.execute("PRAGMA foreign_keys=ON")
            if create:
                self.connection.execute("BEGIN IMMEDIATE")
                self.connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                self.connection.executemany("INSERT INTO metadata VALUES (?,?)", [
                    ("format", "1"), ("store_id", store_id), ("config_digest", config_digest)])
                self.connection.execute("CREATE TABLE events (seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, "
                                        "body BLOB NOT NULL, previous TEXT NOT NULL, hash TEXT NOT NULL)")
                self.connection.execute("COMMIT")
            meta = dict(self.connection.execute("SELECT key,value FROM metadata"))
            if meta != {"format": "1", "store_id": store_id, "config_digest": config_digest}:
                raise CorruptStore("configuration/subject mismatch; no implicit policy migration")
            if self.connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise CorruptStore("SQLite integrity check failed")
            self._reload()
        except BaseException:
            self.close()
            raise

    @staticmethod
    def empty() -> dict:
        return {"actions": {}, "attempts": {}, "closures": {}, "revoked": {}, "last_clock_ns": 0}

    @staticmethod
    def project(state: dict, kind: str, body: dict, verifier=None) -> None:
        if kind == "ACTION":
            from .model import Proposal
            proposal = Proposal.parse(body)
            proposal.validate_binding()
            key = proposal.ref.key
            if key in state["actions"]:
                raise CorruptStore("duplicate action revision")
            state["actions"][key] = body
        elif kind == "ADMITTED":
            effect = body["attempt"]["effect"]["logical_id"]
            closure = body["closure"]
            if effect in state["attempts"] or closure["action_key"] not in state["actions"]:
                raise CorruptStore("duplicate effect or missing action")
            if closure["effect_id"] != effect or closure["attempt_id"] != body["attempt"]["attempt_id"]:
                raise CorruptStore("attempt/closure relation mismatch")
            action = state["actions"][closure["action_key"]]
            attempt = body["attempt"]
            basis = attempt["basis"]
            if (attempt["action"] != action["ref"] or attempt["effect"] != action["effect"] or
                basis["action"] != action["ref"] or basis["effect"] != action["effect"] or
                basis["profile_hash"] != action["profile_hash"] or
                basis["state"]["subject"] != action["effect"]["destination"] or
                closure["profile_hash"] != action["profile_hash"]):
                raise CorruptStore("admission binding mismatch")
            from .authority import Signed
            if verifier is None:
                raise CorruptStore("missing authority verifier")
            grant = verifier.grant(Signed.parse(body["authority"]))
            required = {"purpose": "execute", "store_id": action["store_id"],
                        "action_key": closure["action_key"], "action_revision": action["ref"]["revision"],
                        "effect_id": effect, "profile_hash": action["profile_hash"],
                        "tenant": action["actor"]["tenant"], "principal": action["actor"]["principal"],
                        "destination_digest": digest(action["effect"]["destination"])}
            if (any(getattr(grant, key) != value for key, value in required.items()) or
                basis["authority_grant_id"] != grant.grant_id or
                basis["authority_digest"] != digest(body["authority"]["payload"]) or
                grant.grant_id in state["revoked"] or
                not grant.not_before_ns <= basis["admitted_ns"] < grant.expires_ns):
                raise CorruptStore("archived authority does not justify admission")
            state["attempts"][effect] = attempt
            state["closures"][effect] = closure
        elif kind == "OBSERVED":
            observation = body["observation"]
            effect = observation["effect_id"]
            if effect not in state["closures"]:
                raise CorruptStore("unowned observation")
            closure = state["closures"][effect]
            if observation["attempt_id"] != closure["attempt_id"]:
                raise CorruptStore("observation attempt mismatch")
            closure["knowledge"] = observation["knowledge"]
            closure["observation"] = observation
            if observation["knowledge"] in {"VERIFIED", "NOT_APPLIED"}:
                closure["disposition"] = "CLOSED"
            elif closure["disposition"] != "RETIRED_UNKNOWN":
                closure["disposition"] = "OPEN"
        elif kind == "RETIRED":
            from .authority import Signed
            closure = state["closures"][body["effect_id"]]
            if closure["knowledge"] != "UNKNOWN":
                raise CorruptStore("only UNKNOWN can be retired by this profile")
            grant = verifier.grant(Signed.parse(body["authority"]))
            if (grant.purpose != "retire_unknown" or grant.action_key != closure["action_key"] or
                grant.effect_id != body["effect_id"] or grant.profile_hash != closure["profile_hash"] or
                grant.grant_id in state["revoked"] or grant.reason != body["reason"] or
                grant.custodian != body["custodian"]["principal"] or
                body["retired_ns"] < closure["horizon_ns"] or
                not grant.not_before_ns <= body["retired_ns"] < grant.expires_ns):
                raise CorruptStore("invalid UNKNOWN retirement authority")
            closure["disposition"] = "RETIRED_UNKNOWN"
            closure["retirement_reason"] = body["reason"]
            closure["custodian"] = body["custodian"]
        elif kind == "REVOKED":
            from .authority import Signed
            payload = verifier.payload(Signed.parse(body["authority"]))
            if payload["purpose"] != "revoke" or payload["grant_id"] != body["grant_id"] or payload["reason"] != body["reason"]:
                raise CorruptStore("invalid revocation authority")
            state["revoked"][body["grant_id"]] = body["reason"]
        elif kind == "CLOCK":
            current = body["now_ns"]
            if type(current) is not int or current < state["last_clock_ns"]:
                raise CorruptStore("clock regression in journal")
            state["last_clock_ns"] = current
        else:
            raise CorruptStore(f"unknown event kind: {kind}")

    def _reload(self) -> None:
        state = self.empty()
        previous = "0" * 64
        sequence = 0
        try:
            for seq, kind, raw, prev, entry_hash in self.connection.execute(
                    "SELECT seq,kind,body,previous,hash FROM events ORDER BY seq"):
                body = loads(raw)
                if seq != sequence + 1 or prev != previous or raw != canonical(body):
                    raise CorruptStore("journal sequence, chain or encoding mismatch")
                if entry_hash != digest({"seq": seq, "kind": kind, "body": body, "previous": prev}):
                    raise CorruptStore("journal entry hash mismatch")
                self.project(state, kind, body, self.verifier)
                previous, sequence = entry_hash, seq
        except CorruptStore:
            raise
        except (ValueError, KeyError, TypeError) as error:
            raise CorruptStore("malformed journal") from error
        self.state, self.head, self.sequence = state, previous, sequence

    def append(self, kind: str, body: dict) -> None:
        candidate = copy.deepcopy(self.state)
        body = loads(canonical(body))
        self.project(candidate, kind, body, self.verifier)
        sequence = self.sequence + 1
        new_hash = digest({"seq": sequence, "kind": kind, "body": body, "previous": self.head})
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            self.connection.execute("INSERT INTO events VALUES (?,?,?,?,?)",
                                    (sequence, kind, canonical(body), self.head, new_hash))
            self.connection.execute("COMMIT")
        except BaseException:
            if self.connection.in_transaction:
                self.connection.execute("ROLLBACK")
            raise
        self.state, self.sequence, self.head = candidate, sequence, new_hash

    def verify(self) -> dict:
        self._reload()
        return {"entries": self.sequence, "head_hash": self.head, "valid": True,
                "guarantee": "local-chain-integrity; no external anti-rollback anchor"}

    def close(self) -> None:
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None
