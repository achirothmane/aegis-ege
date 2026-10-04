"""Try live closure/custody merges, then restore the exact production source.

The test oracle remains the current regression assertion. Each alternative is
compiled into the real evaluator; native mode runs its read-only executable
against actual PostgreSQL effects, never an alternative model verifier.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UNIT = "TestSemanticClosureCannotBeDerivedFromCustody"
NATIVE = "TestPostgresCompositeSemanticClosurePairs"
CASES = {"owned", "foreign-attempt", "changed-postcondition"}

COMMIT_JOIN = '''\tif d.Commit == nil {
\t\ta.uncertain("Matching state does not establish causality for this attempt")
\t\treturn
\t}
\tc := d.Commit
\tq := e.Request'''
DERIVED_COMMIT = '''\tq := e.Request
\tc := d.Commit
\tif c == nil {
\t\tc = &Commit{EffectID: e.EffectID, AttemptID: q.AttemptID,
\t\t\tOwner: q.Executor, CustodyGeneration: e.CustodyGeneration,
\t\t\tAdmissionBinding: q.AdmissionBinding, AuthorityEpoch: e.AuthorityEpoch,
\t\t\tAuthorityGeneration: e.AuthorityGeneration, AuthorityActive: a.r.Admitted,
\t\t\tOperation: q.Operation, Before: q.Before, After: q.After,
\t\t\tCommittedAt: time.Now().UTC().Format(time.RFC3339Nano)}
\t}'''
ALTERNATIVES = {
    "custody-as-commit": (COMMIT_JOIN, DERIVED_COMMIT),
    "commit-as-closure": ("\tif d.Observed == q.After {", "\tif true {"),
}


def run(command, log, cwd=ROOT, env=None):
    result = subprocess.run(command, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    return result


def outcomes(result, top, expected_failure=None, native=False):
    events = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
    if any(e["Action"] == "skip" for e in events):
        raise RuntimeError("semantic trial skipped")
    passed = {e.get("Test") for e in events if e["Action"] == "pass"}
    failed = {e.get("Test") for e in events if e["Action"] == "fail" and "Test" in e}
    output = "".join(e.get("Output", "") for e in events)
    if expected_failure is None:
        if result.returncode or failed or not {top + "/" + c for c in CASES} <= passed:
            raise RuntimeError("unchanged live evaluator did not pass the complete closure corpus")
        return
    witness = top + "/" + expected_failure
    if result.returncode == 0 or failed != {witness, top} or top + "/owned" not in passed:
        raise RuntimeError("alternative survived or failed outside its intended semantic assertion")
    false_closed = (re.search(r'"closure":\s*"CLOSED"', output) and
                    re.search(r'"claims_supported":\s*true', output)) if native else re.search(r"Closure:CLOSED.*ClaimsSupported:true", output)
    if "semantic closure merge changed" not in output or not false_closed:
        raise RuntimeError("trial did not demonstrate a supported false CLOSED judgment")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--native-test-binary", type=Path)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    data = json.loads((ROOT / "testdata/governed-action/kernel-shrink/semantic-closure-v1.json").read_text())
    source = ROOT / data["source_path"]
    original = source.read_bytes()
    baseline = subprocess.check_output(["git", "show", data["baseline_source_head"] + ":" + data["source_path"]], cwd=ROOT)
    blob = subprocess.check_output(["git", "hash-object", "--stdin"], input=baseline, cwd=ROOT).decode().strip()
    if blob != data["source_blob"] or original != baseline:
        raise RuntimeError("production evaluator differs from the registered live baseline")
    if {a["name"] for a in data["alternatives"]} != set(ALTERNATIVES):
        raise RuntimeError("unregistered semantic alternative")
    native = args.native_test_binary is not None
    top = NATIVE if native else UNIT
    command = (["go", "tool", "test2json", "-t", "-p", "native-semantic-closure", str(args.native_test_binary.resolve()), "-test.v", "-test.run", "^" + NATIVE + "$", "-test.timeout=2m"] if native else
               ["go", "test", "-race", "-mod=readonly", "-count=1", "-json", "-run", "^" + UNIT + "$", "./evidenceverify"])
    env = os.environ.copy()
    if native:
        env["COMPOSITE_ARTIFACT_DIR"] = str(out / "unchanged-native")
    outcomes(run(command, out / "unchanged.jsonl", env=env), top)
    killed = []
    try:
        for candidate in data["alternatives"]:
            name = candidate["name"]
            before, after = ALTERNATIVES[name]
            text = original.decode()
            if text.count(before) != 1:
                raise RuntimeError("alternative no longer targets exactly one live relation")
            source.write_text(text.replace(before, after))
            if native:
                binary = out / (name + "-consumer")
                build = run(["go", "build", "-mod=readonly", "-trimpath", "-o", str(binary), "./cmd/aegis-evidence-inspect"], out / (name + "-build.log"))
                if build.returncode:
                    raise RuntimeError("alternative did not compile into the real consumer")
                env["EVIDENCE_VERIFY_BINARY"] = str(binary)
                env["COMPOSITE_ARTIFACT_DIR"] = str(out / (name + "-native"))
            result = run(command, out / (name + ".jsonl"), env=env)
            outcomes(result, top, candidate["counterexample"], native)
            killed.append({"alternative": name, "counterexample": candidate["counterexample"], "false_judgment": "CLOSED with claims_supported=true"})
            source.write_bytes(original)
    finally:
        source.write_bytes(original)
    if source.read_bytes() != baseline:
        raise RuntimeError("exact live source restoration failed")
    env = os.environ.copy()
    if native:
        env["COMPOSITE_ARTIFACT_DIR"] = str(out / "restored-native")
    outcomes(run(command, out / "restored.jsonl", env=env), top)
    result = {"schema_version": "aegis.live-semantic-reduction-result/v1", "baseline_source_head": data["baseline_source_head"], "mode": "native-postgresql-consumer" if native else "unit-real-evaluator", "unchanged_controls_passed": True, "killed_alternatives": killed, "source_restored_sha256": hashlib.sha256(original).hexdigest(), "restored_controls_passed": True, "semantic_relations_removed": 0, "global_minimality_proven": False}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"PASS: {result['mode']}; two live semantic merges falsified by supported false CLOSED; exact evaluator restored")


if __name__ == "__main__":
    main()
