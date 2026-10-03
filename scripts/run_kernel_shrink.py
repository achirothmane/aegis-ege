"""Replay the immutable implementation and falsify deleted binding relations.

This harness changes source temporarily and always restores exact bytes. It is
not runtime logic, a replacement verifier, or a formal/native assurance claim.
"""

import argparse
import json
import subprocess
from pathlib import Path

from verify_kernel_shrink import registration


ROOT = Path(__file__).resolve().parents[1]


def run(args, log, cwd=ROOT, success=True):
    result = subprocess.run(args, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    if success and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}); see {log}: {args}")
    return result


def traces(raw):
    rows = []
    outputs = []
    for line in raw.decode().splitlines():
        if not line.startswith("{"):
            continue  # Go may emit an informational telemetry diagnostic.
        event = json.loads(line)
        if event["Action"] == "skip":
            raise RuntimeError("reduction experiment skipped")
        outputs.append(event.get("Output", ""))
    # test2json may split a long stdout line into several Output events.
    for output in "".join(outputs).splitlines():
        if output.startswith("KERNEL_SHRINK_TRACE "):
            rows.append(json.loads(output.removeprefix("KERNEL_SHRINK_TRACE ")))
    if len(rows) != 176:
        raise RuntimeError(f"incomplete differential corpus: {len(rows)} traces, expected 176")
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    data, _ = registration()
    paths = ["governedaction/" + item["path"] for item in data["replacements"]]
    current = {p: (ROOT / p).read_bytes() for p in paths}
    command = ["go", "test", "-mod=readonly", "-count=1", "-json", "./experiments/kernelshrink"]
    reduced = run(command, out / "reduced-traces.jsonl")
    run(["go", "test", "-race", "-mod=readonly", "-count=1", "./..."], out / "reduced-runtime.log", ROOT / "governedaction")
    try:
        for p in paths:
            old = subprocess.check_output(["git", "show", data["baseline_source_head"] + ":" + p], cwd=ROOT)
            (ROOT / p).write_bytes(old)
        baseline = run(command, out / "baseline-traces.jsonl")
        run(["go", "test", "-race", "-mod=readonly", "-count=1", "./..."], out / "baseline-runtime.log", ROOT / "governedaction")
    finally:
        for p, raw in current.items():
            (ROOT / p).write_bytes(raw)
    if traces(reduced.stdout) != traces(baseline.stdout):
        raise RuntimeError("reduced runtime differs from pinned #236 outputs/call order")

    run(["go", "test", "-race", "-mod=readonly", "-count=1", "./evidenceverify"], out / "verifier.log")
    verifier = "evidenceverify/verify.go"
    # Each trial retains every other mechanism. Killing a mutation establishes
    # a required join, not irreducibility of a separate core object. The report
    # also considers stronger derived/merged alternatives for all nine families.
    mutations = [
        ("binding-domains", "governedaction/runtime/runtime.go", [(b'return requestBinding(req, "effect-v0")', b'return requestBinding(req, "admission-v0")')], "./experiments/kernelshrink", "^TestKernelShrinkBindingProjectionEquivalence$"),
        ("retention", "governedaction/runtime/runtime.go", [(b"return adapter.RetainCustody(retainCtx, custody)", b"return nil")], "./experiments/kernelshrink", "^TestKernelShrinkCustodyCannotDisappearAfterLostAcknowledgement$"),
        ("effect", verifier, [(b" || c.EffectID != e.EffectID", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/effect$"),
        ("attempt", verifier, [(b" || c.AttemptID != q.AttemptID", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/attempt$"),
        ("custody", verifier, [(b" || c.CustodyGeneration != e.CustodyGeneration", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/custody$"),
        ("owner", verifier, [(b" || c.Owner != q.Executor", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/owner$"),
        ("authority", verifier, [(b"!c.AuthorityActive || ", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/authority$"),
        ("basis", verifier, [(b" && admission.PolicyHash == a.p.AdmissionPolicyHash", b"")], "./evidenceverify", "^TestKernelShrinkSignedCommitRequiresBoundRelations/basis$"),
        ("history", "evidenceverify/history.go", [(b" || last.PayloadDigest != BundleHistoryBinding(b)", b"")], "./evidenceverify", "^TestKernelShrinkHistoryCannotBindForeignBundle$"),
        ("claim-standard", verifier, [(b"if e.ClaimType != a.p.RequiredClaimType {", b"if false {"), (b'if a.p.RequiredClaimType == "POSTCONDITION" {', b'if e.ClaimType == "POSTCONDITION" {')], "./evidenceverify", "^TestIndependentPolicyRejectsBundleClaimDowngrade$"),
    ]
    killed = []
    for name, path, edits, package, test in mutations:
        target = ROOT / path
        original = target.read_bytes()
        changed = original
        for before, after in edits:
            if changed.count(before) != 1:
                raise RuntimeError(f"mutation {name} no longer addresses exactly one relation")
            changed = changed.replace(before, after)
        try:
            target.write_bytes(changed)
            result = run(["go", "test", "-mod=readonly", "-count=1", "-json", "-run", test, package], out / (name + "-counterexample.jsonl"), success=False)
            events = [json.loads(line) for line in result.stdout.decode().splitlines() if line.startswith("{")]
            failures = [e["Test"] for e in events if e["Action"] == "fail" and "Test" in e]
            if result.returncode == 0 or not failures or any(e["Action"] == "skip" for e in events):
                raise RuntimeError(f"mutation {name} survived or failed outside a regression assertion")
            killed.append({"relation": name, "failing_tests": failures})
        finally:
            target.write_bytes(original)
    for p, raw in current.items():
        if (ROOT / p).read_bytes() != raw:
            raise RuntimeError(f"source restoration failed: {p}")
    summary = {"schema_version": "aegis.kernel-shrink-result/v1", "baseline_source_head": data["baseline_source_head"], "equivalent_traces": len(traces(reduced.stdout)), "baseline_runtime_passed": True, "reduced_runtime_passed": True, "independent_verifier_passed": True, "killed_mutations": killed, "measurements": data["measurements"], "native_assurance": "separate constitutional CI corpus required", "irreducible_core_objects_proven": False}
    (out / "result.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(f"PASS: {summary['equivalent_traces']} identical baseline/reduced traces; {len(killed)} binding counterexamples retained; exact source restored")


if __name__ == "__main__":
    main()
