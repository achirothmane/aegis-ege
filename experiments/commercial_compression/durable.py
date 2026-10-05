"""Shared real one-step durable executor representation, not a workflow product."""

import json
import sqlite3


class Journal:
    def __init__(self, path):
        self.db = sqlite3.connect(path, isolation_level=None, timeout=15)
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(
            """
            CREATE TABLE IF NOT EXISTS step (
              id TEXT PRIMARY KEY, question TEXT, patch TEXT, status TEXT, result TEXT
            );
            CREATE TABLE IF NOT EXISTS owner (
              id TEXT PRIMARY KEY, generation INTEGER, name TEXT
            );
            """
        )

    def issue(self, question, patch):
        self.db.execute(
            "INSERT INTO step VALUES(?,?,?,'issued',NULL)",
            (question["logical_id"], json.dumps(question), json.dumps(patch)),
        )
        self.db.execute(
            "INSERT INTO owner VALUES(?,1,'executor')", (question["logical_id"],)
        )

    def load(self, effect):
        row = self.db.execute(
            "SELECT question,patch,status,result FROM step WHERE id=?", (effect,)
        ).fetchone()
        return {
            "question": json.loads(row[0]),
            "patch": json.loads(row[1]),
            "status": row[2],
            "result": json.loads(row[3]) if row[3] else None,
        }

    def takeover(self, effect, name):
        return (
            self.db.execute(
                "UPDATE owner SET generation=2,name=? WHERE id=? AND generation=1",
                (name, effect),
            ).rowcount
            == 1
        )

    def complete(self, effect, result):
        self.db.execute(
            "UPDATE step SET status=?,result=? WHERE id=?",
            (
                "completed" if result["closure"] == "CLOSED" else "observed_unknown",
                json.dumps(result),
                effect,
            ),
        )
