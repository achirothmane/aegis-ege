"""Run cycle-7 finite/native-object experiments and preserve the constitutional sources."""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


BASE = "413229f06e7843e1e465062a795035d2c8272595"
ROOT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def preserve():
    registration = json.loads((ROOT / "testdata/governed-action/kernel-shrink/conditional-collapse-v1.json").read_text())
    if registration["baseline_source_head"] != BASE or registration["production_code_changed"] or registration["fourth_axis_added"]:
        raise AssertionError("conditional-collapse registration changed its scope")
    for path, blob in registration["source_pins"].items():
        if git("hash-object", path).decode().strip() != blob:
            raise AssertionError("unregistered candidate source: " + path)
    paths = git("ls-tree", "-r", "--name-only", BASE, "governedaction", "evidenceverify",
                "testdata/governed-action/kernel-shrink", "experiments/gosmig-simulation").decode().splitlines()
    # Every pre-existing source/corpus byte in these four areas is immutable in
    # this cycle. New tests are allowed; the candidate cannot rewrite its oracle.
    for path in paths:
        if (ROOT / path).read_bytes() != git("show", BASE + ":" + path):
            raise AssertionError("constitutional source changed: " + path)
    for module in ("governedaction", "evidenceverify"):
        for current in (ROOT / module).rglob("*.go"):
            path = current.relative_to(ROOT).as_posix()
            if path not in paths and not path.endswith("_test.go"):
                raise AssertionError("new production source was not authorized by this cycle: " + path)
    originals = [path for path in paths if path.startswith("governedaction/")
                 and path.endswith(".go") and not path.endswith("_test.go")]
    digest = hashlib.sha256()
    for path in originals:
        raw = (ROOT / path).read_bytes()
        digest.update(path.encode() + b"\0" + len(raw).to_bytes(8, "big") + raw)
    return {"constitutional_sources_preserved": len(paths),
            "governedaction_tree_before": git("rev-parse", BASE + ":governedaction").decode().strip(),
            "governedaction_tree_after": git("rev-parse", "HEAD:governedaction").decode().strip(),
            "production_files": len(originals),
            "production_bytes": sum(len((ROOT / p).read_bytes()) for p in originals),
            "production_lines": sum(len((ROOT / p).read_bytes().splitlines()) for p in originals),
            "production_sha256": digest.hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    measurements = preserve()
    result = subprocess.run([sys.executable, "-B", "-m", "unittest", "discover", "-s", "experiments/acpbasis", "-v"],
                            cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    (args.out / "tests.log").write_text(result.stdout)
    if result.returncode:
        raise AssertionError(result.stdout)
    raw = subprocess.check_output([sys.executable, "-B", "experiments/acpbasis/model.py"], cwd=ROOT)
    model = json.loads(raw)
    if len(model) != 7 or sum(v["states"] for v in model.values()) != 256:
        raise AssertionError("bounded state space differs from the registered cycle")
    (args.out / "reachable-state-model.json").write_bytes(raw)
    (args.out / "fingerprint.json").write_text(json.dumps(measurements, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"fingerprint": measurements, "model_states": {k: v["states"] for k, v in model.items()}}, sort_keys=True))
    print("PASS: all original constitutional sources preserved; bounded model and native object-store controls")


if __name__ == "__main__":
    main()
