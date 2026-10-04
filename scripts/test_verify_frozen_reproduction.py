"""Negative controls use copies of the actual frozen evidence, never its sources."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from run_independent_reproduction import normalized
from verify_frozen_reproduction import ARTIFACTS, REGISTRATION, ROOT, verify_replay


class FrozenEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name)
        for replay, frozen in ARTIFACTS:
            destination = self.evidence / replay
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((ROOT / frozen).read_bytes())

    def change_json(self, path, change):
        output = self.evidence / path
        data = json.loads(output.read_bytes())
        change(data)
        output.write_text(json.dumps(data, indent=2, sort_keys=path.startswith("sqlite/")) + "\n")
        return data

    def check_failed(self, path):
        report = verify_replay(self.evidence)
        self.assertFalse(report["passed"])
        self.assertEqual([row["replay_file"] for row in report["artifacts"]
                          if row["status"] == "MISMATCH"], [path])

    def test_five_original_artifacts_pass_byte_for_byte(self):
        report = verify_replay(self.evidence)
        self.assertTrue(report["passed"])
        self.assertTrue(report["all_byte_identical"])
        self.assertEqual(len(report["artifacts"]), 5)

    def test_changed_witness_with_equal_old_projection_is_rejected(self):
        path = "sqlite/results.json"
        original = json.loads((self.evidence / path).read_bytes())
        altered = self.change_json(path, lambda data: data["exploration"]["profiles"]
            ["mutable:guard=0:sole=0"]["minimal_corner_witnesses"]["111"].update(trace=[]))
        producer = json.loads((ROOT / REGISTRATION).read_bytes())["producers"][0]
        self.assertEqual(normalized(producer, original), normalized(producer, altered))
        self.check_failed(path)

    def test_event_trace_and_reports_are_required(self):
        for path in ("event_model/trace-witnesses.json", "event_model/analysis.json",
                     "event_model/report.md", "sqlite/report.md"):
            output = self.evidence / path
            original = output.read_bytes()
            with self.subTest(path=path):
                output.write_bytes(original + b" ")
                self.check_failed(path)
            output.write_bytes(original)

    def test_runtime_versions_are_explicit_and_not_called_identical(self):
        self.change_json("sqlite/results.json", lambda data: data["provenance"].update(
            python="3.12.99", sqlite="3.45.1"))
        report = verify_replay(self.evidence)
        self.assertTrue(report["passed"])
        self.assertFalse(report["all_byte_identical"])
        row = report["artifacts"][0]
        self.assertEqual(row["status"], "RUNTIME_PROVENANCE_ONLY")
        self.assertEqual(set(row["runtime_differences"]), {"provenance.python", "provenance.sqlite"})

    def test_runtime_exception_cannot_hide_changed_facts(self):
        def alter(data):
            data["provenance"]["sqlite"] = "3.45.1"
            data["exploration"]["profiles"]["mutable:guard=0:sole=0"]["state_count"] += 1
        self.change_json("sqlite/results.json", alter)
        self.check_failed("sqlite/results.json")

    def test_runtime_exception_cannot_hide_serialization_changes(self):
        path = "sqlite/results.json"
        self.change_json(path, lambda d: d["provenance"].update(sqlite="3.45.1"))
        output = self.evidence / path
        output.write_bytes(output.read_bytes() + b" ")
        self.check_failed(path)

    def test_other_provenance_and_missing_version_are_rejected(self):
        path = "sqlite/results.json"
        original = (self.evidence / path).read_bytes()
        for alter in (lambda d: d["provenance"].update(semantic_input="another specification"),
                      lambda d: d["provenance"].pop("python"),
                      lambda d: d["provenance"].update(sqlite=None)):
            with self.subTest(alter=alter):
                self.change_json(path, alter)
                self.check_failed(path)
            (self.evidence / path).write_bytes(original)

    def test_formatting_duplicate_keys_and_nonfinite_numbers_are_rejected(self):
        path = "sqlite/results.json"
        original = (self.evidence / path).read_bytes()
        for raw in (original + b" ", original.replace(b'{', b'{"schema":"duplicate",', 1),
                    original.replace(b'"python": "3.12.14"', b'"python": NaN')):
            with self.subTest(raw_size=len(raw)):
                (self.evidence / path).write_bytes(raw)
                self.check_failed(path)

    def test_json_boolean_and_integer_are_not_interchangeable(self):
        self.change_json("sqlite/results.json", lambda d: d["provenance"].update(
            sqlite="3.45.1", stdlib_only=1))
        self.check_failed("sqlite/results.json")

    def test_missing_artifact_is_failure(self):
        path = "event_model/trace-witnesses.json"
        (self.evidence / path).unlink()
        self.check_failed(path)

    def test_registration_and_original_artifact_cannot_be_replaced(self):
        root = self.evidence / "root"
        for _, original in ARTIFACTS:
            output = root / original
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes((ROOT / original).read_bytes())
        registration = root / REGISTRATION
        registration.parent.mkdir(parents=True, exist_ok=True)
        raw = (ROOT / REGISTRATION).read_bytes()
        registration.write_bytes(raw)
        self.assertTrue(verify_replay(self.evidence, root)["passed"])
        (root / ARTIFACTS[0][1]).write_bytes(b"substitute original")
        self.assertFalse(verify_replay(self.evidence, root)["passed"])
        registration.write_bytes(raw + b" ")
        self.assertIn("registration differs", verify_replay(self.evidence, root)["error"])

    def test_cli_failure_retains_diagnostic_and_changed_evidence(self):
        path = self.evidence / "event_model/trace-witnesses.json"
        path.write_bytes(b"changed witness")
        result = subprocess.run([sys.executable, "-B", str(ROOT / "scripts/verify_frozen_reproduction.py"),
                                 "--evidence-dir", str(self.evidence)], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stderr)
        report = json.loads((self.evidence / "frozen-evidence-replay.json").read_bytes())
        self.assertFalse(report["passed"])
        self.assertEqual(path.read_bytes(), b"changed witness")


if __name__ == "__main__":
    unittest.main()
