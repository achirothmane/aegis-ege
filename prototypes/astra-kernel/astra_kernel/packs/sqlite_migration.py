from __future__ import annotations

import dataclasses
import os
import re
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from ..boundary import Profile, implementation_digest
from ..model import (Denied, Destination, Knowledge, Observation, Proposal, StateWitness,
                     digest, exact, integer)


@dataclasses.dataclass(frozen=True)
class AddColumn:
    column: str
    default_text: str
    expected_schema_digest: str
    expected_rows_digest: str
    expected_user_version: int

    @classmethod
    def parse(cls, data: dict) -> AddColumn:
        exact(data, {f.name for f in dataclasses.fields(cls)})
        if (type(data["column"]) is not str or
            not re.fullmatch(r"[a-z][a-z0-9_]{0,30}", data["column"]) or
            data["column"] in {"id", "name"} or data["column"].startswith("astra_")):
            raise Denied("MIGRATION_COLUMN_SCOPE")
        default = data["default_text"]
        if type(default) is not str or "\x00" in default or len(default.encode("utf-8")) > 64:
            raise Denied("MIGRATION_DEFAULT_LIMIT")
        integer(data["expected_user_version"])
        if data["expected_user_version"] >= 2_147_483_647:
            raise Denied("MIGRATION_VERSION_LIMIT")
        for name in ("expected_schema_digest", "expected_rows_digest"):
            if type(data[name]) is not str or len(data[name]) != 64:
                raise Denied("INVALID_MIGRATION_BINDING")
        return cls(**data)


def database_identity(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise Denied("UNSAFE_DATABASE_TARGET")
    info = path.stat()
    with sqlite3.connect(path.as_uri() + "?mode=ro", uri=True) as conn:
        namespace = conn.execute("SELECT value FROM astra_metadata WHERE key='namespace'").fetchone()[0]
    return f"dev:{info.st_dev}:ino:{info.st_ino}:namespace:{namespace}"


class SQLiteMigration:
    def __init__(self, path: Path, expected_identity: str):
        self.path = path
        self.expected_identity = expected_identity
        self.profile = Profile(
            "sqlite.add-column", "1", "people only; typed TEXT NOT NULL DEFAULT; schema/rows/version checked in BEGIN IMMEDIATE",
            "atomic marker plus current column/default, preserved base rows and incremented schema version",
            "SQLite write transaction; OS-level database replacement/privileged marker forgery outside boundary",
            implementation_digest(type(self)))

    def connect(self) -> sqlite3.Connection:
        if database_identity(self.path) != self.expected_identity:
            raise Denied("DESTINATION_CHANGED")
        conn = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=2)
        conn.enable_load_extension(False)
        # Observe the deployment's transaction mode; never silently reconfigure an external database.
        if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "delete":
            conn.close()
            raise Denied("UNSUPPORTED_DATABASE_JOURNAL_MODE")
        conn.execute("PRAGMA synchronous=EXTRA")
        return conn

    @staticmethod
    def state(conn: sqlite3.Connection) -> dict:
        triggers = conn.execute("SELECT name FROM sqlite_schema WHERE type='trigger' AND tbl_name='people'").fetchall()
        if triggers:
            raise Denied("UNSUPPORTED_DATABASE_TRIGGERS")
        info = conn.execute("PRAGMA table_info(people)").fetchall()
        if not info or [row[1] for row in info[:2]] != ["id", "name"]:
            raise Denied("UNSUPPORTED_DATABASE_SCHEMA")
        return {"schema_digest": digest(info),
                "rows_digest": digest(conn.execute("SELECT id,name FROM people ORDER BY id").fetchall()),
                "user_version": conn.execute("PRAGMA user_version").fetchone()[0]}

    def propose(self, requested: dict) -> dict:
        exact(requested, {"column", "default_text"})
        AddColumn.parse({**requested, "expected_schema_digest": "0" * 64,
                         "expected_rows_digest": "0" * 64, "expected_user_version": 0})
        conn = self.connect()
        try:
            conn.execute("BEGIN")
            state = self.state(conn)
            if requested["column"] in {r[1] for r in conn.execute("PRAGMA table_info(people)")}:
                raise Denied("COLUMN_ALREADY_EXISTS")
            return {**requested, "expected_schema_digest": state["schema_digest"],
                    "expected_rows_digest": state["rows_digest"], "expected_user_version": state["user_version"]}
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def destination(self, parameters: dict) -> Destination:
        AddColumn.parse(parameters)
        return Destination("sqlite", str(self.path), "people", self.expected_identity)

    @contextmanager
    def session(self, proposal: Proposal, clock: Callable[[], int]):
        plan = AddColumn.parse(proposal.parameters)
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state = self.state(conn)
            if (state["schema_digest"] != plan.expected_schema_digest or
                state["rows_digest"] != plan.expected_rows_digest or
                state["user_version"] != plan.expected_user_version):
                raise Denied("STALE_STATE", "database schema, rows or version changed")
            if conn.execute("SELECT 1 FROM astra_effects WHERE effect_id=?", (proposal.effect.logical_id,)).fetchone():
                raise Denied("DESTINATION_EFFECT_ALREADY_RECORDED")
            now = clock()
            witness = StateWitness(self.destination(proposal.parameters), digest(state), now,
                                   now + 1_000_000_000, self.profile.consistency)
            yield MigrationSession(conn, plan, proposal.ref.revision, witness)
        finally:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            conn.close()

    def observe(self, proposal: Proposal, attempt_id: str, now_ns: int) -> Observation:
        plan = AddColumn.parse(proposal.parameters)
        knowledge = Knowledge.UNKNOWN
        details: dict = {"column": plan.column}
        conn = None
        try:
            conn = self.connect()
            conn.execute("BEGIN")
            marker = conn.execute("SELECT attempt_id,revision FROM astra_effects WHERE effect_id=?",
                                  (proposal.effect.logical_id,)).fetchone()
            state = self.state(conn)
            columns = {r[1]: r for r in conn.execute("PRAGMA table_info(people)")}
            if marker is None:
                unchanged = (state["schema_digest"] == plan.expected_schema_digest and
                             state["rows_digest"] == plan.expected_rows_digest and
                             state["user_version"] == plan.expected_user_version)
                if unchanged:
                    knowledge, details["result"] = Knowledge.NOT_APPLIED, "NO_COMMITTED_EFFECT_MARKER"
                else:
                    details["result"] = "MISSING_MARKER_WITH_STATE_DRIFT"
            elif marker != (attempt_id, proposal.ref.revision):
                details["result"] = "MARKER_BINDING_MISMATCH"
            elif plan.column not in columns:
                details["result"] = "MARKER_PRESENT_COLUMN_ABSENT"
            else:
                info = columns[plan.column]
                literal = "'" + plan.default_text.replace("'", "''") + "'"
                bad_values = conn.execute(f'SELECT count(*) FROM people WHERE "{plan.column}" IS NOT ?',
                                          (plan.default_text,)).fetchone()[0]
                exact_column = info[2] == "TEXT" and info[3] == 1 and info[4] == literal
                preserved = state["rows_digest"] == plan.expected_rows_digest
                version = state["user_version"] == plan.expected_user_version + 1
                details.update(column_contract_matches=exact_column, base_rows_preserved=preserved,
                               default_rows_match=bad_values == 0, schema_version_matches=version)
                if exact_column and preserved and version and bad_values == 0:
                    knowledge, details["result"] = Knowledge.VERIFIED, "MIGRATION_AND_POSTCONDITION_OBSERVED"
                else:
                    details["result"] = "COMMITTED_MARKER_WITH_POSTCONDITION_DRIFT"
        except (OSError, sqlite3.Error, Denied) as error:
            details.update(result="OBSERVATION_UNAVAILABLE", error_type=type(error).__name__)
        finally:
            if conn is not None:
                if conn.in_transaction:
                    conn.execute("ROLLBACK")
                conn.close()
        return Observation(proposal.effect.logical_id, attempt_id, "local-sqlite-observer-v1", now_ns,
                           knowledge, "sqlite.add-column.outcome.v1", details)


@dataclasses.dataclass
class MigrationSession:
    connection: sqlite3.Connection
    plan: AddColumn
    revision: str
    witness: StateWitness

    def apply(self, effect_id: str, attempt_id: str, admission_gate: Callable[[], None],
              fault: Callable[[str], None]) -> None:
        literal = "'" + self.plan.default_text.replace("'", "''") + "'"
        admission_gate()
        self.connection.execute(f'ALTER TABLE people ADD COLUMN "{self.plan.column}" TEXT NOT NULL DEFAULT {literal}')
        fault("sqlite_after_ddl_before_commit")
        self.connection.execute(f"PRAGMA user_version={self.plan.expected_user_version + 1}")
        self.connection.execute("INSERT INTO astra_effects VALUES (?,?,?)", (effect_id, attempt_id, self.revision))
        self.connection.execute("COMMIT")
