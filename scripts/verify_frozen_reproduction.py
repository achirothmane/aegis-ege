"""Compare complete replay evidence after the frozen producers have finished.

Cycle 8's original runner compares reachable projections. This additional gate
checks every byte of both reports, the event analysis/witnesses, and the SQLite
result. Only SQLite's two explicit runtime-version fields may differ, and that
case is reported separately rather than called byte-identical reproduction.
"""
import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REGISTRATION = "testdata/governed-action/kernel-shrink/independent-reproduction-v1.json"
REGISTRATION_SHA256 = "43561aa582c51878fe9152a1baaaff9612b83af8f655a1cd4b75a798dfc3701f"
ARTIFACTS = (
    ("sqlite/results.json", "experiments/precedence_repro/sqlite/evidence/results.json"),
    ("sqlite/report.md", "experiments/precedence_repro/sqlite/evidence/report.md"),
    ("event_model/analysis.json", "experiments/precedence_repro/event_model/results/analysis.json"),
    ("event_model/trace-witnesses.json", "experiments/precedence_repro/event_model/results/trace-witnesses.json"),
    ("event_model/report.md", "experiments/precedence_repro/event_model/results/report.md"),
)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def sqlite_runtime_difference(frozen, replay):
    """Require identical serialization after replacing only two version values."""
    expected = json.loads(frozen, object_pairs_hook=unique_object, parse_constant=reject_constant)
    actual = json.loads(replay, object_pairs_hook=unique_object, parse_constant=reject_constant)
    encoded = (json.dumps(actual, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    if encoded != replay:
        return None
    changes = {}
    for field in ("python", "sqlite"):
        before, after = expected["provenance"][field], actual["provenance"][field]
        if not isinstance(before, str) or not isinstance(after, str) or not before or not after:
            raise ValueError("invalid runtime version: " + field)
        if before != after:
            changes["provenance." + field] = {"frozen": before, "replay": after}
        actual["provenance"][field] = before
    normalized = (json.dumps(actual, indent=2, sort_keys=True, allow_nan=False) + "\n").encode()
    # With no version change, even a formatting-only difference is rejected.
    return changes if changes and normalized == frozen else None


def verify_replay(evidence_dir, root=ROOT):
    report = {"schema": "aegis.frozen-reproduction-evidence/v1",
              "registration_sha256": REGISTRATION_SHA256,
              "runtime_exception": ["sqlite/results.json:provenance.python",
                                    "sqlite/results.json:provenance.sqlite"],
              "artifacts": [], "passed": False, "all_byte_identical": False}
    try:
        raw = (root / REGISTRATION).read_bytes()
        if sha256(raw) != REGISTRATION_SHA256:
            raise ValueError("Cycle 8 registration differs from its frozen bytes")
        pins = json.loads(raw)["source_sha256"]
    except (OSError, ValueError, KeyError) as error:
        report["error"] = str(error)
        return report
    for emitted, original in ARTIFACTS:
        row = {"replay_file": emitted, "frozen_file": original, "status": "MISMATCH"}
        report["artifacts"].append(row)
        try:
            frozen = (root / original).read_bytes()
            row["frozen_sha256"] = sha256(frozen)
            if row["frozen_sha256"] != pins[original]:
                raise ValueError("original artifact does not match its frozen pin")
            replay = (evidence_dir / emitted).read_bytes()
            row["replay_sha256"] = sha256(replay)
            row["byte_identical"] = frozen == replay
            if frozen == replay:
                row["status"] = "EXACT_BYTES"
            elif emitted == "sqlite/results.json":
                changes = sqlite_runtime_difference(frozen, replay)
                if changes:
                    row["status"] = "RUNTIME_PROVENANCE_ONLY"
                    row["runtime_differences"] = changes
        except (OSError, ValueError, KeyError, TypeError) as error:
            row["error"] = str(error)
    report["passed"] = all(row["status"] != "MISMATCH" for row in report["artifacts"])
    report["all_byte_identical"] = all(row["status"] == "EXACT_BYTES"
                                       for row in report["artifacts"])
    return report


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", type=Path, required=True)
    args = parser.parse_args()
    evidence = args.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    report = verify_replay(evidence)
    (evidence / "frozen-evidence-replay.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
