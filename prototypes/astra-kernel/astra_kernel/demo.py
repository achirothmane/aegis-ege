from __future__ import annotations

import subprocess
import sys
import tempfile
import time
from pathlib import Path

from .authority import OwnerAuthority
from .kernel import Kernel, initialize, write_private
from .model import Denied, canonical, local_actor


def run_demo() -> dict:
    cases: list[dict] = []
    with tempfile.TemporaryDirectory(prefix="astra-kernel-demo-", dir=Path.cwd()) as temp:
        home = Path(temp) / "home"
        initialize(home)
        owner = OwnerAuthority.load(home / "owner" / "issuer.key")
        actor = local_actor()
        with Kernel(home) as kernel:
            action = kernel.propose(actor, "file-success", "file.replace",
                                    {"filename": "settings.txt", "content_utf8": "mode=governed\n"})
            result = kernel.execute(actor, action.ref.key, owner.issue(action))
            assert result["knowledge"] == "VERIFIED"
            cases.append({"case": "bounded_file_replace", "knowledge": result["knowledge"],
                          "domain_outcome": result["observation"]["domain_payload"]["result"]})
            waiting = kernel.propose(actor, "expired-approval", "file.replace",
                                     {"filename": "settings.txt", "content_utf8": "mode=expired\n"})
            expired = owner.issue(waiting, now_ns=time.time_ns() - 120_000_000_000)
            try:
                kernel.execute(actor, waiting.ref.key, expired)
                raise AssertionError("expired grant was executed")
            except Denied as error:
                assert error.code == "AUTHORITY_TIME"
                cases.append({"case": "delayed_expired_authority", "decision": "DENY", "reason": error.code})
            drift = kernel.propose(actor, "stale-proposal", "file.replace",
                                   {"filename": "settings.txt", "content_utf8": "mode=stale\n"})
            (home / "files" / "settings.txt").write_text("mode=changed-by-operator\n")
            try:
                kernel.execute(actor, drift.ref.key, owner.issue(drift))
                raise AssertionError("stale file proposal was executed")
            except Denied as error:
                assert error.code == "STALE_STATE"
                cases.append({"case": "current_state_drift", "decision": "DENY", "reason": error.code})
            crash_action = kernel.propose(actor, "crash-after-effect", "file.replace",
                                          {"filename": "settings.txt", "content_utf8": "mode=recoverable\n"})
            grant_file = home / "crash-grant.json"
            write_private(grant_file, canonical(owner.issue(crash_action)))
        crashed = subprocess.run([sys.executable, "-m", "astra_kernel", "execute", "--home", str(home),
                                  "--action-key", crash_action.ref.key, "--grant", str(grant_file),
                                  "--crash-at", "after_effect_before_observation"], capture_output=True, timeout=15)
        assert crashed.returncode == 86, crashed.stderr.decode()
        with Kernel(home) as kernel:
            pending = kernel.closure(crash_action.effect.logical_id)
            assert pending["knowledge"] == "UNKNOWN" and pending["disposition"] == "OPEN"
            cases.append({"case": "process_crash_preserves_custody", "knowledge": pending["knowledge"],
                          "disposition": pending["disposition"], "process_exit_code": crashed.returncode})
            observed = kernel.observe(actor, crash_action.effect.logical_id)
            assert observed["knowledge"] == "VERIFIED"
            cases.append({"case": "restart_observes_without_replay", "knowledge": observed["knowledge"]})
            db_action = kernel.propose(actor, "database-migration", "sqlite.add-column",
                                       {"column": "status", "default_text": "new"})
            result = kernel.execute(actor, db_action.ref.key, owner.issue(db_action))
            assert result["knowledge"] == "VERIFIED"
            cases.append({"case": "native_sqlite_migration", "knowledge": result["knowledge"],
                          "domain_outcome": result["observation"]["domain_payload"]["result"]})
            cases.append({"case": "journal_replay_verification", **kernel.journal.verify()})
    return {"artifact": "Astra executable governed-action kernel prototype", "version": "0.1.0",
            "environment": "isolated temporary filesystem and SQLite database", "cases": cases,
            "claim": "local executable behavior only; no held-out or production generalization evidence"}
