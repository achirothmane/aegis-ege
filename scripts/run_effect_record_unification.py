"""Exercise effect/receipt representation unification and erase replay exclusion.

The positive candidate uses one PostgreSQL business-effect row as both the
physical effect and exact causal completion. The negative trial removes the
stable effect-key exclusion relation and requires a genuine second committed
row after lost acknowledgement and fresh successor admission.
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
SOURCE = ROOT / "experiments/gosmig-simulation/effect_record_unification_test.go"
REPLAY = "TestPostgresCompositeUnifiedEffectRecordReplayExclusion"
CASES = {
    "TestPostgresCompositeUnifiedEffectRecordCrashRecovery/CLOSED",
    "TestPostgresCompositeUnifiedEffectRecordCrashRecovery/UNKNOWN",
    "TestPostgresCompositeUnifiedEffectRecordCrashRecovery/PRE_COMMIT",
    REPLAY,
    "TestPostgresCompositeUnifiedEffectRecordConcurrentSuccessors",
    "TestPostgresCompositeUnifiedEffectRecordHistoricalCauseDoesNotCloseDrift",
}
PRIMARY = "effect_id TEXT PRIMARY KEY, amount BIGINT NOT NULL, attempt_id TEXT NOT NULL, target TEXT NOT NULL, "
LOOKUP = """\tvar completed bool
\tif err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT FROM "+nativeFenceTable("ledger")+" WHERE effect_id=$1)", effect).Scan(&completed); err != nil {
\t\treturn err
\t}
\tif completed {
\t\treturn errNativeCompleted
\t}
"""


def blob(content):
    return hashlib.sha1(b"blob " + str(len(content)).encode() + b"\0" + content).hexdigest()


def run(command, log, cwd=ROOT, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    return result


def native_command(binary, pattern):
    return [
        "go", "tool", "test2json", "-t", "-p", "native-effect-record-unification",
        str(binary.resolve()), "-test.v", "-test.run", pattern, "-test.timeout=3m",
    ]


def controls(result):
    rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    passed = {r.get("Test") for r in rows if r["Action"] == "pass"}
    if result.returncode or any(r["Action"] in {"skip", "fail"} for r in rows) or not CASES <= passed:
        raise RuntimeError("unified effect-record candidate did not pass all registered controls without skips")


def replay_witness(result):
    rows = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    failed = {r["Test"] for r in rows if r["Action"] == "fail" and "Test" in r}
    output = "".join(r.get("Output", "") for r in rows)
    if result.returncode == 0 or failed != {REPLAY} or any(r["Action"] == "skip" for r in rows):
        raise RuntimeError("replay-exclusion erasure survived or failed outside its semantic assertion")
    if not re.search(r"unified replay exclusion erased: committed_effects=2 successor_error=<nil>", output):
        raise RuntimeError("erasing stable effect-key exclusion did not create two genuine committed effects")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--native-test-binary", required=True, type=Path)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)

    reg = json.loads((ROOT / "testdata/governed-action/kernel-shrink/effect-record-unification-v1.json").read_text())
    original = SOURCE.read_bytes()
    if blob(original) != reg["candidate_source_blob"]:
        raise RuntimeError("unified effect-record source does not match registered blob")
    text = original.decode()
    if text.count(PRIMARY) != 1 or text.count(LOOKUP) != 1:
        raise RuntimeError("replay exclusion mutation no longer targets one exact live relation")

    binary = args.native_test_binary.resolve()
    env = os.environ.copy()
    env["COMPOSITE_ARTIFACT_DIR"] = str(out / "unchanged-native")
    controls(run(native_command(binary, "^TestPostgresCompositeUnifiedEffectRecord"), out / "unchanged.jsonl", env=env))

    mutant = out / "erased-replay-exclusion.test"
    try:
        changed = text.replace(PRIMARY, "effect_id TEXT NOT NULL, amount BIGINT NOT NULL, attempt_id TEXT NOT NULL, target TEXT NOT NULL, ").replace(LOOKUP, "")
        SOURCE.write_text(changed)
        build = run(["go", "test", "-race", "-mod=readonly", "-c", "-o", str(mutant), "."], out / "erased-build.log", cwd=MODULE)
        if build.returncode:
            raise RuntimeError("replay-exclusion erasure did not compile into the real native executable")
        env["COMPOSITE_ARTIFACT_DIR"] = str(out / "erased-native")
        replay_witness(run(native_command(mutant, "^" + REPLAY + "$"), out / "erased.jsonl", env=env))
    finally:
        SOURCE.write_bytes(original)

    if SOURCE.read_bytes() != original:
        raise RuntimeError("unified effect-record source was not restored exactly")
    env["COMPOSITE_ARTIFACT_DIR"] = str(out / "restored-native")
    controls(run(native_command(binary, "^TestPostgresCompositeUnifiedEffectRecord"), out / "restored.jsonl", env=env))

    result = {
        "schema_version": "aegis.effect-record-unification-result/v1",
        "baseline_source_head": reg["baseline_source_head"],
        "build_sha": os.environ["COMPOSITE_BUILD_SHA"],
        "mode": "native-postgresql-single-effect-row",
        "separate_mutable_custody_register": "absent",
        "separate_completion_table": "absent",
        "physical_effect_and_causal_record": "one row",
        "replay_exclusion_erasure": {
            "outcome": "falsified",
            "committed_effects": 2,
            "counterexample": REPLAY,
        },
        "current_state_closure_remains_independent": True,
        "production_kernel_changed": False,
        "global_minimality_proven": False,
        "novel_primitive_claimed": False,
        "source_restored_sha256": hashlib.sha256(original).hexdigest(),
    }
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print("PASS: one native business-effect row carries exact cause; erasing stable replay exclusion commits two effects; exact source restored")


if __name__ == "__main__":
    main()
