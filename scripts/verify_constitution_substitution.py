"""Additive research invariance and native-result checks, outside the kernel."""

import argparse
import hashlib
import json
import re
import subprocess
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASE = "04434db12fa0c85d3497faf6ebb40df937092c5d"
ALLOWED = (
    "experiments/constitutional-substitution/",
    "experiments/gosmig-simulation/constitution_",
    "scripts/verify_constitution_substitution.py",
    ".github/workflows/constitutional-substitution.yml",
    "docs/governed-action/constitutional-substitution-v1.md",
)
VOCABULARY = re.compile(
    r"\b(?:Taqwa|Amana|Sidq|Huda|Maslaha|La[ _-]+darar|Maqasid|"
    r"Hifz[ _-]+al[ _-]+(?:Nafs|Aql|Mal|Nasl|Din)|Sharia|Orionech)\b", re.I
)
ACP = {
    "A": "Governed authority for the exact subject, action/effect, target, generation/epoch and enforcing boundary was valid at the actual physical commitment point.",
    "C": "The actual physical effect was caused by the exact evaluated attempt and executor.",
    "P": "The independently selected fixed current required predicate is true at the observation point.",
    "no_effect": "A-at-commit is undefined; denied/no-effect worlds are outside the committed-effect cube.",
}


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT)


def tree(ref):
    result = {}
    for raw in git("ls-tree", "-r", "-z", ref).split(b"\0"):
        if raw:
            metadata, path = raw.split(b"\t", 1)
            mode, kind, blob = metadata.decode().split()
            result[path.decode()] = (mode, kind, blob)
    return result


def canonical(paths):
    h = hashlib.sha256()
    for name in sorted(paths):
        raw = (ROOT / name).read_bytes()
        h.update(name.encode() + b"\0" + len(raw).to_bytes(8, "big") + raw)
    return h.hexdigest()


def component(prefix, paths):
    selected = sorted(p for p in paths if p.startswith(prefix + "/")
                      and p.endswith(".go") and not p.endswith("_test.go"))
    types, public, files = [], [], []
    for name in selected:
        raw = (ROOT / name).read_bytes()
        text = raw.decode()
        types.extend({"path": name, "name": m} for m in re.findall(r"^type (\w+)\s", text, re.M))
        public.extend({"path": name, "declaration": m} for m in re.findall(
            r"^(?:type [A-Z].*|func (?:\([^\n]*\) )?[A-Z][^\n]*)", text, re.M))
        files.append({"path": name, "sha256": hashlib.sha256(raw).hexdigest(),
                      "git_blob": git("hash-object", name).decode().strip(),
                      "bytes": len(raw), "lines": len(raw.splitlines())})
    return {"tree": git("rev-parse", "HEAD:" + prefix).decode().strip(),
            "production_sha256": canonical(selected), "production_files": len(files),
            "source_lines": sum(f["lines"] for f in files),
            "source_bytes": sum(f["bytes"] for f in files),
            "lexical_type_count": len(types), "types": types,
            "public_declaration_headers": public, "production_inventory": files,
            "public_api_pin": "Exact complete production bytes pin all API fields/constants/imports; lexical inventory is supplemental, not an AST/type proof."}


def snapshot(stage):
    baseline, current = tree(BASE), tree("HEAD")
    for name, (mode, kind, original) in baseline.items():
        path = ROOT / name
        if kind != "blob" or not path.is_file():
            raise AssertionError("baseline file missing: " + name)
        actual = git("hash-object", name).decode().strip()
        actual_mode = "100755" if path.stat().st_mode & 0o111 else "100644"
        if actual != original or mode != actual_mode:
            raise AssertionError("preexisting source/fixture/API changed: " + name)
    for name in set(current) - set(baseline):
        if not any(name.startswith(prefix) for prefix in ALLOWED):
            raise AssertionError("unexpected addition: " + name)
        if name.startswith("experiments/gosmig-simulation/constitution_") and not name.endswith("_test.go"):
            raise AssertionError("normative code must stay in test-only research: " + name)
    production = [p for p in current if (p.endswith(".go") and not p.endswith("_test.go")
                  and not p.startswith("experiments/")) or
                  (p.startswith("kernel/bpf/") and p.endswith((".c", ".h")))]
    leaks = [{"path": p, "line": i, "text": line}
             for p in production for i, line in enumerate((ROOT / p).read_text().splitlines(), 1)
             if VOCABULARY.search(line)]
    if leaks:
        raise AssertionError("constitution vocabulary in production: " + json.dumps(leaks))
    source_dir = ROOT / "experiments/constitutional-substitution"
    return {"schema": "aegis.constitution-invariance/v1", "stage": stage,
            "baseline_main": BASE, "experiment_head": git("rev-parse", "HEAD").decode().strip(),
            "all_baseline_files_preserved": len(baseline),
            "kernel": component("governedaction", current),
            "verifier": component("evidenceverify", current),
            "semantic_primitive_types": ["Identity", "State", "Attestation", "Transition"],
            "acp": ACP, "supported_claim_types": ["EXACT_EFFECT", "POSTCONDITION"],
            "runtime_dispositions": ["REJECTED", "UNKNOWN", "CLOSED"],
            "custody_phases": ["RESERVED", "CROSSING", "UNKNOWN", "CLOSED"],
            "retry": "No automatic retry; UNKNOWN never authorizes retry; exact retained native effect key excludes replay.",
            "custody": "Existing unified native effect/origin row and exact identity/cardinality contract; no added custody representation.",
            "normative_production_files_scanned": len(production), "normative_lexical_leaks": leaks,
            "production_semantic_delta": 0,
            "sources": {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in sorted(source_dir.iterdir()) if p.is_file()}}


def verify_results(directory):
    trial_root = directory / "constitutional-substitution"
    trials = json.loads((trial_root / "native-trials.json").read_text())
    assert len(trials) == 51, "native matrix incomplete"
    groups = defaultdict(list)
    for trial in trials:
        groups[trial["case"]].append(trial)
        assert trial["technical_capability"] is True
        allowed = trial["evaluation"]["decision"] == "ALLOW"
        assert trial["physical_effects"] == int(allowed)
        assert trial["dispatch_entered"] is allowed
        if allowed:
            r = trial["verifier_report"]
            assert r["required_claim_type"] == "EXACT_EFFECT" and r["claims_supported"] is True
            assert r["authority_at_commit"] == "VALID_AT_COMMIT" and r["causality"] == "EXACT_COMMIT_RECORD" and r["closure"] == "CLOSED"
        else:
            assert trial["commit_coordinates"] == "UNDEFINED_NO_COMMITTED_EFFECT"
        base = trial_root / trial["case"] / trial["constitution"]
        assert json.loads((base / "evaluation.json").read_text()) == json.loads((base / "independent-policy-replay.json").read_text())
        if trial["case"] == "same-effect-identifiable-with-consent":
            public_input = json.loads((base / "normative-input-public.json").read_text())
            assert any(e["payload"]["kind"] == "consent"
                       and e["payload"]["statement"] == "CONSENTED"
                       for e in public_input["evidence"]["events"]), "synthetic privacy control lacks actual consent evidence"
    disagreements = []
    for name, rows in sorted(groups.items()):
        assert {r["constitution"] for r in rows} == {"A", "B", "T"}
        for field in ("effect_id", "request_digest", "destination", "available_evidence_digest"):
            assert len({r[field] for r in rows}) == 1, (name, field)
        decisions = {r["constitution"]: r["evaluation"]["decision"] for r in rows}
        if len(set(decisions.values())) > 1:
            disagreements.append({"case": name, "decisions": decisions,
                                  "same_effect": True, "same_request": True,
                                  "same_destination": True, "same_evidence_substrate": True})
    assert len(groups) == 17
    decisive = {r["case"]: r["decisions"] for r in disagreements}
    assert decisive["same-effect-safety-one-approval"] == {"A": "ALLOW", "B": "REQUIRE_HUMAN_APPROVAL", "T": "ALLOW"}
    assert decisive["same-effect-identifiable-with-consent"] == {"A": "ALLOW", "B": "ALLOW", "T": "DENY"}
    fingerprints = []
    for path in sorted(trial_root.rglob("fingerprint-before.json")):
        before = json.loads(path.read_text())
        after = json.loads(path.with_name("fingerprint-after.json").read_text())
        for key in before:
            if key != "stage":
                assert before[key] == after[key], (path, key)
        fingerprints.append({"case": before["stage"], "kernel": before["kernel"]["production_sha256"], "verifier": before["verifier"]["production_sha256"], "identical": True})
    assert len(fingerprints) >= 55, "missing per-constitution fingerprints"
    for policy in ("A", "B", "T"):
        drift = json.loads((trial_root / "current-truth" / policy / "drift.json").read_text())
        assert drift["coordinates"] == "110" and drift["physical_effects"] == 1
        assert drift["report"]["closure"] == "UNKNOWN" and drift["report"]["causality"] == "EXACT_COMMIT_RECORD"
    controls = trial_root / "anti-cheating"
    assert json.loads((controls / "self-authorization.json").read_text())["physical_effects"] == 0
    assert json.loads((controls / "revoked-at-native-boundary.json").read_text())["physical_effects"] == 0
    limit = json.loads((controls / "trusted-issuer-limit.json").read_text())
    assert limit["external_policy_satisfied"] is False and limit["effect_finality_supported"] is True and limit["physical_effects"] == 1
    return {"schema": "aegis.constitution-native-results/v1", "native_matrix_trials": len(trials),
            "counterfactual_scenarios": len(groups),
            "native_matrix_committed_worlds": sum(r["physical_effects"] for r in trials),
            "native_matrix_blocked_worlds": sum(not r["dispatch_entered"] for r in trials),
            "identical_input_disagreements": disagreements,
            "per_trial_invariance_pairs": fingerprints, "current_truth_controls": 3,
            "adapter_self_authorization_rejected": True, "native_revocation_rejected": True,
            "trusted_admission_issuer_limit_exposed": True,
            "source_coverage": "User-provided authoritative operational extracts, not original PDF page-level audit",
            "classification_candidate": "U4",
            "classification_scope": "Bounded operative-fragment substitution with truthful independently provisioned evidence/admission authorities; not universal proof or normative certification."}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage")
    parser.add_argument("--verify-results", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = verify_results(args.verify_results) if args.verify_results else snapshot(args.stage or "baseline")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"passed": True, "stage": args.stage,
                      "output": str(args.out), "classification_candidate": result.get("classification_candidate")}))


if __name__ == "__main__":
    main()
