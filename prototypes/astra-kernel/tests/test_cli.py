from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from astra_kernel.model import loads


class CLIFlowCases(unittest.TestCase):
    def command(self, *args, expected=0):
        result = subprocess.run([sys.executable, "-m", "astra_kernel", *map(str, args)],
                                capture_output=True, timeout=15)
        self.assertEqual(result.returncode, expected, result.stdout.decode() + result.stderr.decode())
        return loads(result.stdout)

    def test_separate_process_cli_prepare_authorize_execute_and_inspect(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            home = Path(temp) / "home"
            self.command("init", home)
            proposal = self.command("propose-file", "--home", home, "--action", "cli-request", "--content", "mode=cli\n")
            grant = Path(temp) / "grant.json"
            self.command("authorize", "--home", home, "--action-key", proposal["action_key"], "--out", grant)
            self.assertEqual(grant.stat().st_mode & 0o777, 0o600)
            result = self.command("execute", "--home", home, "--action-key", proposal["action_key"], "--grant", grant)
            self.assertEqual((result["knowledge"], result["disposition"]), ("VERIFIED", "CLOSED"))
            self.assertEqual((home / "files" / "settings.txt").read_text(), "mode=cli\n")
            status = self.command("inspect", "--home", home)
            self.assertEqual(status["attempts"], 1)
            self.assertTrue(status["journal"]["valid"])
            duplicate = self.command("execute", "--home", home, "--action-key", proposal["action_key"], "--grant", grant, expected=2)
            self.assertEqual(duplicate["reason"], "EFFECT_ALREADY_ADMITTED")

    def test_cli_revocation_blocks_native_operation(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            home = Path(temp) / "home"
            self.command("init", home)
            proposal = self.command("propose-file", "--home", home, "--action", "revoke-cli", "--content", "do not write")
            grant = Path(temp) / "grant.json"
            self.command("authorize", "--home", home, "--action-key", proposal["action_key"], "--out", grant)
            self.command("revoke", "--home", home, "--grant", grant, "--reason", "cancel exact permission")
            denied = self.command("execute", "--home", home, "--action-key", proposal["action_key"], "--grant", grant, expected=2)
            self.assertEqual(denied["reason"], "AUTHORITY_REVOKED")
            self.assertEqual((home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_cli_demo_is_an_executable_crash_and_outcome_trace(self):
        trace = self.command("demo")
        self.assertEqual(len(trace["cases"]), 7)
        cases = {case["case"]: case for case in trace["cases"]}
        self.assertEqual(cases["bounded_file_replace"]["knowledge"], "VERIFIED")
        self.assertEqual(cases["process_crash_preserves_custody"]["process_exit_code"], 86)
        self.assertEqual(cases["process_crash_preserves_custody"]["knowledge"], "UNKNOWN")
        self.assertEqual(cases["restart_observes_without_replay"]["knowledge"], "VERIFIED")

    def test_cli_refuses_to_reset_existing_runtime(self):
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp:
            home = Path(temp) / "home"
            self.command("init", home)
            result = self.command("init", home, expected=5)
            self.assertEqual(result["decision"], "LOCKED")
            self.assertEqual(self.command("inspect", "--home", home)["attempts"], 0)
