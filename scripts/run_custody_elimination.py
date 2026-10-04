"""Exercise native custody elimination and erase its retained completion.

The positive alternative is a real PostgreSQL transaction, not a model. The
negative trial compiles removal of its atomic completion write and requires
an actual second ledger append after an executor dies without acknowledgement.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "experiments/gosmig-simulation"
REPLAY = "TestPostgresCompositeNoCustodyReplayRetention"
CASES = {
    "TestPostgresCompositeNoCustodyCrashRecovery/CLOSED",
    "TestPostgresCompositeNoCustodyCrashRecovery/UNKNOWN",
    "TestPostgresCompositeNoCustodyCrashRecovery/PRE_COMMIT",
    REPLAY,
    "TestPostgresCompositeNoCustodyConcurrentSuccessors",
    "TestPostgresCompositeNoCustodyHistoricalCompletionDoesNotCloseDrift",
}
RETAIN = """\tif err := retainNativeCompletion(ctx, tx, req, effect, admission); err != nil {
\t\treturn err
\t}
"""


def blob(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def run(command, log, cwd=ROOT, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    return result


def controls(result):
    rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    passed = {r.get("Test") for r in rows if r["Action"] == "pass"}
    if result.returncode or any(r["Action"] in {"skip", "fail"} for r in rows) or not CASES <= passed:
        raise RuntimeError("native custody elimination did not pass all registered controls without skips")


def retained_effect_witness(result):
    rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    failed = {r["Test"] for r in rows if r["Action"] == "fail" and "Test" in r}
    output = "".join(r.get("Output", "") for r in rows)
    if result.returncode == 0 or failed != {REPLAY} or any(r["Action"] == "skip" for r in rows):
        raise RuntimeError("completion erasure survived or failed outside the native retention assertion")
    if not re.search(r"native retention erased: committed_effects=2 successor_error=<nil>", output):
        raise RuntimeError("completion erasure did not cause two genuine native ledger effects")


def pins(data):
    for path, expected in data["constitutional_source_blobs"].items():
        original = subprocess.check_output(["git", "show", data["baseline_source_head"] + ":" + path], cwd=ROOT)
        if blob(original) != expected or (ROOT / path).read_bytes() != original:
            raise RuntimeError("constitutional source changed: " + path)


def native_command(binary, pattern):
    return ["go", "tool", "test2json", "-t", "-p", "native-custody-elimination", str(binary.resolve()),
            "-test.v", "-test.run", pattern, "-test.timeout=3m"]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--native-test-binary", required=True, type=Path)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((ROOT / "testdata/governed-action/kernel-shrink/custody-elimination-v1.json").read_text())
    pins(data)
    source = ROOT / data["candidate_source_path"]
    original = source.read_bytes()
    if blob(original) != data["candidate_source_blob"] or original.decode().count(RETAIN) != 1:
        raise RuntimeError("completion erasure does not target the registered native relation")
    binary = args.native_test_binary.resolve()
    env = os.environ.copy()
    env["COMPOSITE_ARTIFACT_DIR"] = str(out / "unchanged-native")
    controls(run(native_command(binary, "^TestPostgresCompositeNoCustody"), out / "unchanged.jsonl", env=env))
    mutant = out / "erased-completion.test"
    try:
        source.write_text(original.decode().replace(RETAIN, ""))
        build = run(["go", "test", "-race", "-mod=readonly", "-c", "-o", str(mutant), "."], out / "erased-completion-build.log", cwd=MODULE)
        if build.returncode:
            raise RuntimeError("completion erasure did not compile into the real native executable")
        env["COMPOSITE_ARTIFACT_DIR"] = str(out / "erased-completion-native")
        retained_effect_witness(run(native_command(mutant, "^" + REPLAY + "$"), out / "erased-completion.jsonl", env=env))
    finally:
        source.write_bytes(original)
    if source.read_bytes() != original:
        raise RuntimeError("native alternative was not restored exactly")
    pins(data)
    env["COMPOSITE_ARTIFACT_DIR"] = str(out / "restored-native")
    controls(run(native_command(binary, "^TestPostgresCompositeNoCustody"), out / "restored.jsonl", env=env))
    result = {
        "schema_version": "aegis.native-custody-elimination-result/v1",
        "baseline_source_head": data["baseline_source_head"],
        "build_sha": os.environ["COMPOSITE_BUILD_SHA"],
        "mode": "native-postgresql-atomic-destination",
        "unchanged_controls_passed": True,
        "native_cases": sorted(CASES),
        "separate_mutable_custody_register": "absent",
        "retained_completion_erasure": {"outcome": "falsified", "committed_effects": 2, "counterexample": REPLAY},
        "durable_effect_completion_cause_relation": "retained",
        "new_independent_admission_required_for_successor_execution": True,
        "unknown_observation_grants_retry": False,
        "source_restored_sha256": hashlib.sha256(original).hexdigest(),
        "restored_controls_passed": True,
        "production_kernel_changed": False,
        "global_minimality_proven": False,
        "global_custody_elimination_claimed": False,
        "novel_primitive_claimed": False,
    }
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: separate custody eliminated in the atomic PostgreSQL profile; completion erasure commits two native effects; exact source restored")


if __name__ == "__main__":
    main()
