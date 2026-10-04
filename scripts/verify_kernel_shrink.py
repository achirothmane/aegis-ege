"""Check a measured implementation reduction without rewriting the v1 freeze."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from verify_cross_domain_kernel_tree import entries, git, verify


REGISTRATION = "testdata/governed-action/kernel-shrink/registration-v1.json"
DEMOTION = "testdata/governed-action/kernel-shrink/fixture-demotion-v1.json"
ALLOWED = {"runtime/runtime.go", "runtime/recovery.go", "runtime/fenced.go"}


def surface(source):
    """Compare exact public declaration lines and import blocks, not type counts."""
    text = source.decode()
    public = re.findall(r"^(?:type [A-Z].*|func (?:\([^\n]*\) )?[A-Z][^\n]*)", text, re.M)
    public += re.findall(r"^type [A-Z]\w* (?:struct|interface) \{.*?^\}", text, re.M | re.S)
    public = [re.findall(r'"(?:\\.|[^"\\])*"|`[^`]*`|\w+|[^\s]', item) for item in public]
    imports = re.findall(r'^import \(.*?^\)|^import "[^"]+"', text, re.M | re.S)
    return public, imports


def production_size(tree, read_blob):
    files = [read_blob(entry[2]) for path, entry in tree.items()
             if path.endswith(".go") and not path.endswith("_test.go")]
    return {"files": len(files), "source_lines": sum(len(raw.splitlines()) for raw in files),
            "source_bytes": sum(map(len, files))}


def verify_fixture_demotion(tree, data, read_blob):
    """Permit only a byte-preserving move of the synthetic model into tests."""
    if data["schema_version"] != "aegis.kernel-fixture-demotion/v1":
        raise ValueError("unsupported fixture demotion")
    expected = dict(tree)
    pairs = {"taintflow/tracker.go": ("taint_fixture_test.go", b"func New(", b"func newTaintTracker("),
             "taintflow/tracker_test.go": ("taint_fixture_checks_test.go", b" := New(", b" := newTaintTracker(")}
    seen = set()
    for item in data["moves"]:
        path, destination = item["baseline_path"], item["test_only_path"]
        if path not in pairs or path in seen or destination != pairs[path][0]:
            raise ValueError("unapproved or duplicate fixture move")
        seen.add(path)
        old = ("100644", "blob", item["baseline_blob"])
        new = ("100644", "blob", item["test_only_blob"])
        if tree.get(path) != old or destination in tree:
            raise ValueError("fixture baseline or destination differs")
        raw = read_blob(old[2])
        renamed = raw.replace(b"package taintflow\n", b"package governedaction_test\n")
        renamed = renamed.replace(pairs[path][1], pairs[path][2])
        # The historical subpackage was outside D04's root-file format check.
        # Permit only its three known gofmt column corrections, not token edits.
        for name in (b"ErrUnknownProcess   ", b"ErrUnknownChannel   ", b"ErrInvalidLabel     "):
            renamed = renamed.replace(b"\t" + name + b" =", b"\t" + name + b"=")
        if read_blob(new[2]) != renamed:
            raise ValueError("fixture move changed the model or its tests")
        del expected[path]
        expected[destination] = new
    if seen != set(pairs):
        raise ValueError("both model and all original tests must move")
    for kind, path in (("corpus_caller", "origin_corpus_test.go"), ("documentation", "README.md")):
        item = data[kind]
        if item["path"] != path or tree.get(path) != ("100644", "blob", item["baseline_blob"]):
            raise ValueError("unapproved supporting replacement or baseline")
        before, after = read_blob(item["baseline_blob"]), read_blob(item["current_blob"])
        if kind == "corpus_caller":
            wanted = before.replace(b'\t"github.com/achirothmane/aegis-ege/governedaction/taintflow"\n', b"")
            wanted = wanted.replace(b"taintflow.New(", b"newTaintTracker(")
            if after != wanted:
                raise ValueError("corpus changed beyond the fixture namespace")
        elif not after.startswith(before):
            raise ValueError("documentation must preserve historical bytes")
        expected[path] = ("100644", "blob", item["current_blob"])
    measured = {"before": production_size(tree, read_blob), "after": production_size(expected, read_blob)}
    if measured != data["production_measurements"]:
        raise ValueError("fixture demotion measurements differ")
    return expected


def verify_reduction(baseline, current, replacements, read_blob, demotion=None):
    expected = dict(baseline)
    seen = set()
    before_bytes = after_bytes = before_lines = after_lines = 0
    for item in replacements:
        path = item["path"]
        if path not in ALLOWED or path in seen:
            raise ValueError(f"unapproved or duplicate reduction path: {path}")
        seen.add(path)
        old = ("100644", "blob", item["baseline_blob"])
        new = ("100644", "blob", item["reduced_blob"])
        if baseline.get(path) != old or old == new:
            raise ValueError(f"reduction baseline differs or no reduction: {path}")
        before, after = read_blob(old[2]), read_blob(new[2])
        if surface(before) != surface(after):
            raise ValueError(f"public surface or imports changed: {path}")
        before_bytes += len(before)
        after_bytes += len(after)
        before_lines += len(before.splitlines())
        after_lines += len(after.splitlines())
        expected[path] = new
    if seen != ALLOWED:
        raise ValueError("reduction must register all three runtime paths")
    if demotion is not None:
        expected = verify_fixture_demotion(expected, demotion, read_blob)
    if current != expected:
        changed = sorted(p for p in set(current) | set(expected) if current.get(p) != expected.get(p))
        raise ValueError("unregistered tree delta: " + ", ".join(changed))
    if after_bytes >= before_bytes or after_lines >= before_lines:
        raise ValueError("registered implementation did not become smaller")
    return {"source_bytes_before": before_bytes, "source_bytes_after": after_bytes,
            "source_lines_before": before_lines, "source_lines_after": after_lines,
            "public_surface_changed": False, "imports_changed": False}


def registration():
    data = json.loads(Path(REGISTRATION).read_text())
    if data["schema_version"] != "aegis.kernel-shrink/v1" or data["kernel_semantic_delta_expected"] != 0:
        raise ValueError("unsupported reduction or semantic delta")
    historical = data["historical_registration"]
    raw = Path(historical["path"]).read_bytes()
    actual = subprocess.check_output(["git", "hash-object", "--stdin"], input=raw).decode().strip()
    if actual != historical["blob"]:
        raise ValueError("historical v1 registration was rewritten")
    legacy = json.loads(raw)
    baseline = entries(data["baseline_source_head"] + ":governedaction")
    # Run the original frozen-tree gate against its exact registered baseline.
    # Nothing can be reclassified as a reduction to bypass a normative change.
    verify(entries(legacy["pins"]["governedaction_tree"]), baseline,
           legacy["reference_runtime_extension"]["files"], lambda sha: git("cat-file", "blob", sha))
    for profile in data["historical_profiles"]:
        raw = Path(profile["path"]).read_bytes()
        actual = subprocess.check_output(["git", "hash-object", "--stdin"], input=raw).decode().strip()
        if actual != profile["blob"]:
            raise ValueError("historical profile was rewritten: " + profile["path"])
        old = json.loads(raw)
        pins = old["pins"]
        for pin, path in (("runtime_blob", "runtime/runtime.go"),
                          ("recovery_blob", "runtime/recovery.go"),
                          ("fenced_runtime_blob", "runtime/fenced.go")):
            if pin in pins and baseline[path][2] != pins[pin]:
                raise ValueError("historical runtime baseline differs: " + profile["path"])
        if "governedaction_tree" in pins:
            verify(entries(pins["governedaction_tree"]), baseline,
                   old["reference_runtime_extension"]["files"], lambda sha: git("cat-file", "blob", sha))
    return data, baseline


def fixture_registration(data, baseline):
    demotion = json.loads(Path(DEMOTION).read_text())
    if demotion["runtime_registration_blob"] != git("hash-object", REGISTRATION).decode().strip():
        raise ValueError("cycle-1 registration was rewritten")
    # The complete prior implementation must still satisfy its original gate.
    prior = entries(demotion["baseline_source_head"] + ":governedaction")
    verify_reduction(baseline, prior, data["replacements"], lambda sha: git("cat-file", "blob", sha))
    return demotion


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--working-tree", action="store_true")
    args = parser.parse_args()
    data, baseline = registration()
    demotion = fixture_registration(data, baseline)
    if args.working_tree:
        current = {}
        for p in Path("governedaction").rglob("*"):
            if p.is_file():
                mode = "100755" if p.stat().st_mode & 0o111 else "100644"
                if p.is_symlink():
                    mode = "120000"
                current[str(p.relative_to("governedaction"))] = (mode, "blob", git("hash-object", "-w", str(p)).decode().strip())
    else:
        current = entries("HEAD:governedaction")
    measured = verify_reduction(baseline, current, data["replacements"], lambda sha: git("cat-file", "blob", sha), demotion)
    if measured != data["measurements"]:
        raise ValueError("registered measurements differ from exact source")
    print("PASS: immutable v1 baseline and exact reduced runtime implementation")
    print(json.dumps(measured, sort_keys=True))
    print("PASS: synthetic model is test-only; model, tests and corpus are preserved")
    print(json.dumps(demotion["production_measurements"], sort_keys=True))
    print("Historical native results remain scoped to their original source. Current CI must reprove the reduced source.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
