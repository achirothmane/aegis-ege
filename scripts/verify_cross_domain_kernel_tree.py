"""Verify frozen files and an explicitly registered reference-runtime addition."""

import json
import argparse
import subprocess
import sys
from pathlib import Path


def git(*args):
    return subprocess.check_output(["git", *args])


def entries(tree):
    result = {}
    for record in git("ls-tree", "-r", "-z", tree).split(b"\0"):
        if record:
            metadata, path = record.split(b"\t", 1)
            mode, kind, sha = metadata.decode().split()
            result[path.decode()] = (mode, kind, sha)
    return result


def verify(frozen, current, extension, read_blob):
    expected = dict(frozen)
    seen = set()
    for item in extension:
        path = item["path"]
        if path in seen:
            raise ValueError(f"duplicate extension path: {path}")
        seen.add(path)
        if item["mode"] != "100644":
            raise ValueError(f"extension must be a regular file: {path}")
        prior = frozen.get(path)
        if path == "runtime/README.md":
            if prior != ("100644", "blob", item["frozen_blob"]):
                raise ValueError("runtime README baseline differs")
            if not read_blob(item["current_blob"]).startswith(read_blob(item["frozen_blob"])):
                raise ValueError("runtime README must preserve all frozen bytes")
        elif path in {
            "runtime/fenced.go", "runtime/fenced_test.go",
            "runtime/fenced_revalidation_test.go",
        }:
            if prior is not None or item["frozen_blob"] is not None:
                raise ValueError(f"extension cannot replace a frozen file: {path}")
        else:
            raise ValueError(f"unapproved extension path: {path}")
        expected[path] = (item["mode"], "blob", item["current_blob"])
    if current != expected:
        changed = sorted(path for path in set(current) | set(expected)
                         if current.get(path) != expected.get(path))
        raise ValueError("unregistered tree delta: " + ", ".join(changed))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--registration", default=
                        "testdata/governed-action/cross-domain/registration-v1.json")
    args = parser.parse_args()
    registration = json.loads(Path(args.registration).read_text())
    extension = registration.get("reference_runtime_extension", {})
    if extension and extension.get("native_proof_claimed") is not False:
        raise ValueError("registered extension is outside the native proof claim")
    verify(
        entries(registration["pins"]["governedaction_tree"]),
        entries("HEAD:governedaction"),
        extension.get("files", []),
        lambda sha: git("cat-file", "blob", sha),
    )
    print("PASS: frozen source files unchanged; registered extension exact")
    print("Native cross-domain result covers the frozen contract only.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, subprocess.CalledProcessError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
