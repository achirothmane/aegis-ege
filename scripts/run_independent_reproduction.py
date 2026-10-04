"""Execute source-isolated producers before comparing to the constitutional corpus.

Registration supplies execution interfaces and *post-freeze* profile mapping.
It never supplies expected cubes/functions to the isolated implementations.
Every original repository blob is preserved, rather than just production Go.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
BASE = "271c40bbf46d75f8c3c09c04fe651195e572ab2b"
REGISTRATION = "testdata/governed-action/kernel-shrink/independent-reproduction-v1.json"


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def preserve(registration):
    if registration["baseline_source_head"] != BASE:
        raise AssertionError("independent reproduction baseline changed")
    files = []
    for raw in git("ls-tree", "-r", "-z", BASE).split(b"\0"):
        if not raw:
            continue
        meta, name = raw.split(b"\t", 1)
        path, original = name.decode(), meta.split()[2].decode()
        current = ROOT / path
        if not current.is_file() or git("hash-object", path).decode().strip() != original:
            raise AssertionError("preexisting constitutional/repository byte changed: " + path)
        files.append(path)
    for path, expected in registration["source_sha256"].items():
        actual = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
        if actual != expected:
            raise AssertionError("frozen independent input/source changed: " + path)
    originals = sorted(p for p in files if p.startswith("governedaction/")
                       and p.endswith(".go") and not p.endswith("_test.go"))
    sha = hashlib.sha256()
    for path in originals:
        raw = (ROOT / path).read_bytes()
        sha.update(path.encode() + b"\0" + len(raw).to_bytes(8, "big") + raw)
    return {"all_original_repository_files_preserved": len(files),
            "production_files": len(originals),
            "production_lines": sum(len((ROOT / p).read_bytes().splitlines()) for p in originals),
            "production_bytes": sum(len((ROOT / p).read_bytes()) for p in originals),
            "production_sha256": sha.hexdigest(),
            "governedaction_tree": git("rev-parse", BASE + ":governedaction").decode().strip(),
            "new_production_axes": 0, "new_production_apis": 0}


def run(argv, cwd, log):
    log.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = subprocess.run(argv, cwd=cwd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=300)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        log.write_text(output + "\nExecution timed out; partial evidence retained.\n")
        raise AssertionError("execution timed out; see " + str(log)) from error
    log.write_text(result.stdout)
    if result.returncode:
        raise AssertionError("execution failed; see " + str(log) + "\n" + result.stdout[-3000:])
    return result.stdout


def execute(producer, out):
    cwd = ROOT / producer["directory"]
    output = out / producer["id"]
    output.mkdir(parents=True, exist_ok=True)
    def command(argv):
        return [str(output) if item == "{out}" else item.replace("{out}", str(output)) for item in argv]
    run(command(producer["test_command"]), cwd, output / "tests.log")
    stdout = run(command(producer["result_command"]), cwd, output / "execution.log")
    if producer.get("result_file"):
        return json.loads((output / producer["result_file"]).read_text())
    result = json.loads(stdout)
    (output / "result.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def normalized(producer, result):
    """Read emitted facts using post-freeze interface metadata, not answer oracles."""
    profiles = result
    for field in producer.get("profiles_path", []):
        profiles = profiles[field]
    if isinstance(profiles, list):
        def profile_name(row):
            for field in producer["profile_name_field"].split("."):
                row = row[field]
            return row
        profiles = {profile_name(row): row for row in profiles}
    facts = {}
    for independent_name, baseline_name in producer["profile_mapping"].items():
        record = profiles[independent_name]
        corners = record
        for field in producer["corners_path"]:
            corners = corners[field]
        if isinstance(corners, dict):
            corners = list(corners)
        corners = sorted(c if isinstance(c, str) else "".join(map(str, c)) for c in corners)
        if not corners or any(len(c) != 3 or set(c) - {"0", "1"} for c in corners):
            raise AssertionError("producer emitted invalid/empty committed-effect truth set")
        functions = {}
        for axis, name in enumerate("ACP"):
            kept = [i for i in range(3) if i != axis]
            # Independently enumerate all sixteen total pair functions over emitted facts.
            functions[name] = [list(map(int, format(mask, "04b"))) for mask in range(16)
                if all(int(format(mask, "04b")[2 * int(c[kept[0]]) + int(c[kept[1]])]) == int(c[axis])
                       for c in corners)]
        facts[baseline_name] = {"corners": corners, "functions": functions}
    if len(facts) != len(producer["profile_mapping"]):
        raise AssertionError("multiple independent profiles mapped to one reference profile")
    return facts


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    reg = json.loads((ROOT / REGISTRATION).read_text())
    before = preserve(reg)
    # Freeze-independent programs receive only their own interface arguments.
    # The old model is executed and compared only after all independent programs finish.
    results = {p["id"]: execute(p, out) for p in reg["producers"]}
    run([sys.executable, "-B", "-m", "unittest", "discover", "-s",
         "experiments/precedence_repro", "-p", "test_substitute.py", "-v"], ROOT,
        out / "known-substitute-tests.log")
    substitute = run([sys.executable, "-B", "experiments/precedence_repro/substitute.py"], ROOT,
                     out / "known-substitute.json")
    json.loads(substitute)
    baseline = json.loads(run([sys.executable, "-B", "experiments/acpbasis/model.py"], ROOT,
                              out / "cycle7-reference.json"))
    disagreements = []
    comparison = {}
    for p in reg["producers"]:
        facts = normalized(p, results[p["id"]])
        if set(facts) != set(baseline):
            raise AssertionError("independent profile comparison omitted part of the reference domain")
        comparison[p["id"]] = facts
        for name, actual in facts.items():
            expected = {"corners": sorted(baseline[name]["cube"]),
                        "functions": baseline[name]["functions"]}
            if actual != expected:
                disagreements.append({"producer": p["id"], "profile": name,
                                      "independent": actual, "cycle7": expected})
    cross_comparison = {p["id"]: normalized(
        {**p, "profile_mapping": p["cross_profile_mapping"]}, results[p["id"]])
        for p in reg["producers"]}
    first_id = reg["producers"][0]["id"]
    first = cross_comparison[first_id]
    for producer_id, facts in cross_comparison.items():
        if set(facts) != set(first):
            raise AssertionError("cross-realization comparison omitted a restricted profile")
        for name, actual in facts.items():
            if actual != first[name]:
                disagreements.append({"producer": producer_id, "profile": name,
                                      "independent": actual, "other_producer": first_id,
                                      "other_result": first[name]})
    after = preserve(reg)
    if before != after:
        raise AssertionError("execution changed the preserved source/fingerprint")
    report = {"baseline_source_head": BASE, "fingerprint_before": before,
              "fingerprint_after": after, "post_freeze_comparison": comparison,
              "cross_realization_comparison": cross_comparison,
              "disagreements": disagreements}
    (out / "comparison.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"preserved_files": before["all_original_repository_files_preserved"],
                      "independent_producers": list(results), "disagreements": disagreements}))
    if disagreements:
        raise AssertionError("unresolved scientific disagreement; evidence preserved, implementations not corrected")


if __name__ == "__main__":
    main()
