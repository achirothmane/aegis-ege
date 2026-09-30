"""Run meaningful behavior tests and save measured evidence, with no network requests."""
from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import sqlite3
import sys
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

import cryptography

ROOT = Path(__file__).resolve().parent
os.chdir(ROOT)
sys.path.insert(0, str(ROOT))


class Results(unittest.TextTestResult):
    def __init__(self, *args):
        super().__init__(*args)
        self.completed_ids = []
        self.subtests = 0

    def stopTest(self, test):
        self.completed_ids.append(test.id())
        super().stopTest(test)

    def addSubTest(self, test, subtest, error):
        self.subtests += 1
        super().addSubTest(test, subtest, error)


def main():
    evidence = ROOT / "evidence"
    evidence.mkdir(exist_ok=True)
    stream = io.StringIO()
    start = time.perf_counter()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Results).run(suite)
    elapsed = time.perf_counter() - start
    (evidence / "test-output.txt").write_text(stream.getvalue(), encoding="utf-8")
    trace = None
    if result.wasSuccessful():
        from astra_kernel.demo import run_demo
        trace = run_demo()
        (evidence / "demo-trace.json").write_text(json.dumps(trace, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    sources = list((ROOT / "astra_kernel").rglob("*.py")) + list((ROOT / "tests").rglob("*.py"))
    sources += [ROOT / "pyproject.toml", ROOT / "requirements.txt", ROOT / "verify.py"]
    hashes = {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(sources)}
    validation = {"artifact": "candidate executable kernel prototype 0.1", "tested_at_utc": datetime.now(timezone.utc).isoformat(),
                  "environment": {"os": platform.system(), "architecture": platform.machine(),
                                  "python": platform.python_version(), "sqlite": sqlite3.sqlite_version,
                                  "cryptography": cryptography.__version__},
                  "tests": {"run": result.testsRun, "passed": result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
                            "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
                            "subtests": result.subtests, "seconds": round(elapsed, 4), "ids": result.completed_ids},
                  "demo_passed": trace is not None, "source_hashes": hashes,
                  "claims": {"real_native_effects": True, "abrupt_process_loss_exercised": True,
                             "production_ready": False, "held_out_generalization": False, "independent_consumer": False,
                             "os_kernel": False, "net_human_work_savings_measured": False,
                             "immutable_external_audit": False, "global_exactly_once": False}}
    (evidence / "validation.json").write_text(json.dumps(validation, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"tests": validation["tests"] | {"ids": "see evidence/validation.json"}, "demo_passed": trace is not None}))
    return 0 if result.wasSuccessful() and trace is not None else 1


if __name__ == "__main__":
    raise SystemExit(main())
