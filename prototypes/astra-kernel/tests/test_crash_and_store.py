from __future__ import annotations

import base64
import copy
import json
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from astra_kernel.authority import OwnerAuthority
from astra_kernel.kernel import Kernel, initialize, write_private
from astra_kernel.model import Busy, CorruptStore, Denied, canonical, local_actor, loads
from astra_kernel.packs.file_replace import FileSession


class ProcessCases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="astra-process-", dir=Path.cwd())
        self.home = Path(self.temp.name) / "home"
        initialize(self.home)
        self.owner = OwnerAuthority.load(self.home / "owner" / "issuer.key")
        self.actor = local_actor()

    def tearDown(self):
        self.temp.cleanup()

    def prepare(self, kind="file.replace"):
        requested = ({"filename": "settings.txt", "content_utf8": "mode=survives-crash\n"}
                     if kind == "file.replace" else {"column": "status", "default_text": "new"})
        with Kernel(self.home) as kernel:
            action = kernel.propose(self.actor, "crash-case", kind, requested)
            grant = self.owner.issue(action)
            grant_file = self.home / "grant.json"
            write_private(grant_file, canonical(grant))
        return action, grant, grant_file

    def crash(self, action, grant_file, point):
        result = subprocess.run([sys.executable, "-m", "astra_kernel", "execute", "--home", str(self.home),
                                 "--action-key", action.ref.key, "--grant", str(grant_file), "--crash-at", point],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 86, result.stdout.decode() + result.stderr.decode())
        return result

    def test_real_process_death_before_effect_preserves_unknown_and_denies_replay(self):
        action, grant, path = self.prepare()
        self.crash(action, path, "after_claim_before_effect")
        with Kernel(self.home) as kernel:
            closure = kernel.closure(action.effect.logical_id)
            self.assertEqual((closure["knowledge"], closure["disposition"]), ("UNKNOWN", "OPEN"))
            self.assertEqual(closure["custodian"], {"tenant": self.actor.tenant, "principal": self.actor.principal})
            self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")
            with self.assertRaises(Denied) as raised:
                kernel.execute(self.actor, action.ref.key, grant)
            self.assertEqual(raised.exception.code, "EFFECT_ALREADY_ADMITTED")
            self.assertEqual(kernel.observe(self.actor, action.effect.logical_id)["knowledge"], "UNKNOWN")

    def test_real_process_death_after_file_effect_is_observed_without_reexecution(self):
        action, _, path = self.prepare()
        self.crash(action, path, "after_effect_before_observation")
        with Kernel(self.home) as kernel:
            self.assertEqual(kernel.closure(action.effect.logical_id)["knowledge"], "UNKNOWN")
            with patch.object(FileSession, "apply", side_effect=AssertionError("resumption must not reexecute")):
                closure = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual(closure["knowledge"], "VERIFIED")
            self.assertEqual(kernel.inspect()["attempts"], 1)

    def test_file_staging_crash_is_partial_and_accounted(self):
        action, _, path = self.prepare()
        self.crash(action, path, "file_after_stage_sync")
        with Kernel(self.home) as kernel:
            self.assertEqual(kernel.closure(action.effect.logical_id)["knowledge"], "UNKNOWN")
            result = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual(result["knowledge"], "PARTIAL")
            self.assertEqual(result["disposition"], "OPEN")
            self.assertTrue(result["observation"]["domain_payload"]["staging_present"])
            self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")
            self.assertTrue((self.home / "files" / (".astra-stage-" + action.effect.logical_id)).exists())

    def test_database_crash_before_effect_has_native_negative_evidence(self):
        action, _, path = self.prepare("sqlite.add-column")
        self.crash(action, path, "after_claim_before_effect")
        with Kernel(self.home) as kernel:
            result = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual(result["knowledge"], "NOT_APPLIED")
            self.assertEqual(result["observation"]["domain_payload"]["result"], "NO_COMMITTED_EFFECT_MARKER")

    def test_database_process_death_during_ddl_rolls_back_without_replay(self):
        action, grant, path = self.prepare("sqlite.add-column")
        self.crash(action, path, "sqlite_after_ddl_before_commit")
        with Kernel(self.home) as kernel:
            self.assertEqual(kernel.closure(action.effect.logical_id)["knowledge"], "UNKNOWN")
            result = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual(result["knowledge"], "NOT_APPLIED")
            with self.assertRaises(Denied):
                kernel.execute(self.actor, action.ref.key, grant)
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            self.assertNotIn("status", {r[1] for r in conn.execute("PRAGMA table_info(people)")})
            self.assertEqual(conn.execute("SELECT count(*) FROM astra_effects").fetchone()[0], 0)

    def test_database_commit_before_process_death_preserves_marker_and_rows(self):
        action, _, path = self.prepare("sqlite.add-column")
        self.crash(action, path, "after_effect_before_observation")
        with Kernel(self.home) as kernel:
            self.assertEqual(kernel.closure(action.effect.logical_id)["knowledge"], "UNKNOWN")
            result = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual(result["knowledge"], "VERIFIED")
            self.assertEqual(kernel.inspect()["attempts"], 1)
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM astra_effects").fetchone()[0], 1)

    def test_manual_takeover_cannot_overlap_live_worker(self):
        with Kernel(self.home) as kernel:
            child = subprocess.run([sys.executable, "-m", "astra_kernel", "inspect", "--home", str(self.home)],
                                   capture_output=True, timeout=15)
            self.assertEqual(child.returncode, 4)
            self.assertEqual(loads(child.stdout)["decision"], "BUSY")
            self.assertEqual(kernel.inspect()["attempts"], 0)
        with Kernel(self.home) as recovered:
            self.assertEqual(recovered.inspect()["attempts"], 0)

    def test_process_level_duplicate_execution_is_rejected_after_restart(self):
        action, grant, path = self.prepare()
        first = subprocess.run([sys.executable, "-m", "astra_kernel", "execute", "--home", str(self.home),
                                "--action-key", action.ref.key, "--grant", str(path)], capture_output=True, timeout=15)
        self.assertEqual(first.returncode, 0, first.stdout.decode())
        second = subprocess.run([sys.executable, "-m", "astra_kernel", "execute", "--home", str(self.home),
                                 "--action-key", action.ref.key, "--grant", str(path)], capture_output=True, timeout=15)
        self.assertEqual(second.returncode, 2)
        self.assertEqual(loads(second.stdout)["reason"], "EFFECT_ALREADY_ADMITTED")

    def test_missing_journal_never_becomes_fresh_authority_or_empty_history(self):
        (self.home / "state" / "journal.sqlite").unlink()
        with self.assertRaises(CorruptStore):
            Kernel(self.home)
        self.assertFalse((self.home / "state" / "journal.sqlite").exists())

    def test_corrupted_journal_is_locked_before_effect(self):
        action, _, _ = self.prepare()
        with sqlite3.connect(self.home / "state" / "journal.sqlite") as conn:
            conn.execute("UPDATE events SET body=? WHERE kind='ACTION'", (b'{"corrupt":true}',))
        with self.assertRaises(CorruptStore):
            Kernel(self.home)
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_config_downgrade_or_destination_rebinding_is_not_silent(self):
        path = self.home / "state" / "config.json"
        config = loads(path.read_bytes())
        config["file_identity"] = "a-different-destination"
        path.write_bytes(canonical(config))
        with self.assertRaises(CorruptStore):
            Kernel(self.home)

    def test_failed_journal_commit_prevents_domain_mutation(self):
        with Kernel(self.home) as kernel:
            action = kernel.propose(self.actor, "storage-failure", "file.replace",
                                    {"filename": "settings.txt", "content_utf8": "never write"})
            real_append = kernel.journal.append
            def unavailable(kind, body):
                if kind == "ADMITTED":
                    raise OSError("journal unavailable before effect")
                return real_append(kind, body)
            with patch.object(kernel.journal, "append", unavailable), self.assertRaises(OSError):
                kernel.execute(self.actor, action.ref.key, self.owner.issue(action))
            self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")
            self.assertEqual(kernel.inspect()["attempts"], 0)

    def test_runtime_verifier_does_not_require_signing_key(self):
        action, grant, _ = self.prepare()
        owner_key = self.home / "owner" / "issuer.key"
        moved = self.home / "owner-offline.key"
        owner_key.rename(moved)
        with Kernel(self.home) as kernel:
            self.assertEqual(kernel.execute(self.actor, action.ref.key, grant)["knowledge"], "VERIFIED")
            self.assertFalse(hasattr(kernel.verifier, "private_bytes"))

    def test_permanent_observation_gap_is_unknown_not_success(self):
        action, _, path = self.prepare()
        self.crash(action, path, "after_effect_before_observation")
        (self.home / "files").rename(self.home / "unavailable-destination")
        with Kernel(self.home) as kernel:
            result = kernel.observe(self.actor, action.effect.logical_id)
            self.assertEqual((result["knowledge"], result["disposition"]), ("UNKNOWN", "OPEN"))
            self.assertEqual(result["observation"]["domain_payload"]["result"], "OBSERVATION_UNAVAILABLE")

    def test_cross_runtime_grant_does_not_reuse_destination_authority(self):
        action, grant, _ = self.prepare()
        second_home = Path(self.temp.name) / "other"
        initialize(second_home)
        second_owner = OwnerAuthority.load(second_home / "owner" / "issuer.key")
        with Kernel(second_home) as other:
            other_action = other.propose(self.actor, "crash-case", "file.replace",
                                         {"filename": "settings.txt", "content_utf8": "mode=survives-crash\n"})
            # Even an envelope signed by this runtime's issuer cannot relabel another runtime's action as local.
            foreign_scope = second_owner.issue(action)
            with self.assertRaises(Denied) as raised:
                other.execute(self.actor, other_action.ref.key, foreign_scope)
            self.assertEqual(raised.exception.code, "AUTHORITY_BINDING")
            self.assertEqual(other.inspect()["attempts"], 0)


class NativeConcurrencyCases(unittest.TestCase):
    def test_sqlite_current_read_and_write_are_in_one_destination_transaction(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            home = Path(temp) / "home"
            initialize(home)
            owner = OwnerAuthority.load(home / "owner" / "issuer.key")
            actor = local_actor()
            with Kernel(home) as kernel:
                action = kernel.propose(actor, "native-cas", "sqlite.add-column", {"column": "status", "default_text": "new"})
                contested = []
                def competing_write(point):
                    if point == "after_claim_before_effect":
                        conn = sqlite3.connect(home / "database" / "people.sqlite", timeout=0.01)
                        try:
                            with self.assertRaises(sqlite3.OperationalError):
                                conn.execute("UPDATE people SET name='stale writer' WHERE id=1")
                            contested.append(True)
                        finally:
                            conn.close()
                kernel.fault = competing_write
                result = kernel.execute(actor, action.ref.key, owner.issue(action))
                self.assertEqual(result["knowledge"], "VERIFIED")
                self.assertEqual(contested, [True])

    def test_busy_file_destination_denies_without_unbounded_wait(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            home = Path(temp) / "home"
            initialize(home)
            actor = local_actor()
            owner = OwnerAuthority.load(home / "owner" / "issuer.key")
            with Kernel(home) as kernel:
                action = kernel.propose(actor, "locked", "file.replace", {"filename": "settings.txt", "content_utf8": "new"})
                with kernel.packs["file.replace"].locked_root(), self.assertRaises(Denied) as raised:
                    kernel.execute(actor, action.ref.key, owner.issue(action))
                self.assertEqual(raised.exception.code, "DESTINATION_BUSY")
                self.assertEqual(kernel.inspect()["attempts"], 0)
