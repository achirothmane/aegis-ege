"""Native paired corpus driver; not counted as customer integration code."""

import argparse
import base64
import concurrent.futures
import copy
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import aegis
import ordinary
from collector import observe
from durable import Journal
from integration import PREFIX, current_image, open_evidence, signed
from native import Kube, deployment, frozen_patch, namespace, question
from recover import reconcile, recover

HERE = Path(__file__).resolve().parent
IMAGE = "registry.k8s.io/pause:3.9"
SCENARIOS = [
    "crash_before_effect", "commit_lost_ack", "executor_death_after_commit",
    "successor_recovery", "duplicate_delivery", "recovery_owner_race",
    "authority_revoked", "current_state_drift", "foreign_attempt",
    "evidence_unavailable", "evidence_available_later", "stale_signed_observation",
    "executor_false_success",
]


def save(path, data):
    path.write_text(json.dumps(data, indent=2))


def clone_journal(original, path):
    journal = Journal(path)
    original.db.backup(journal.db)
    return journal


def child(args):
    retained = Journal(args.journal).load(args.effect)
    if args.before:
        save(args.marker, {"accepted": False, "failure_ns": time.monotonic_ns()})
        os._exit(17)
    q = retained["question"]
    result = Kube(args.worker, q["namespace"]).patch(q["name"], retained["patch"])
    save(args.marker, {"accepted": result["accepted"], "error": result["error"],
                       "failure_ns": time.monotonic_ns()})
    # No result is retained or returned to the durable executor/successor.
    os._exit(17)


def die(journal_path, q, worker, folder, before=False):
    marker = folder / "failure.json"
    args = [sys.executable, "-B", str(HERE / "run.py"), "--child", "--journal",
            str(journal_path), "--effect", q["logical_id"], "--worker", worker,
            "--marker", str(marker)]
    if before:
        args.append("--before")
    result = subprocess.run(args, capture_output=True, timeout=90)
    assert result.returncode == 17, result.stderr.decode()
    data = json.loads(marker.read_text())
    assert data["accepted"] == (not before), data
    return data["failure_ns"]


def pair(envelope, q, root, challenge, key, binary):
    package = aegis.prepare(envelope, q, root, challenge, key, binary)
    return {
        "ordinary": ordinary.assess(envelope, q, root, challenge),
        "aegis": aegis.assess(envelope, q, root, challenge, package, binary),
    }, package


def corpus(args):
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    private = args.private.resolve()
    private.mkdir(parents=True, exist_ok=True)
    ns = "compression-corpus"
    accounts = namespace(args.admin, ns, private)
    admin, reader = Kube(args.admin, ns), Kube(accounts["observer"], ns)
    worker = Kube(accounts["worker-1"], ns)
    key = Ed25519PrivateKey.generate()
    root = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    results = []
    for ordinal, scenario in enumerate(SCENARIOS):
        folder = out / f"{ordinal+1:02d}-{scenario}"
        folder.mkdir()
        name = f"release-{ordinal+1}"
        obj = deployment(admin, name)
        q = question(obj, ns, IMAGE, "worker-1")
        patch = frozen_patch(q)
        original_path = folder / "issued.sqlite"
        original = Journal(original_path)
        original.issue(q, patch)
        save(folder / "question.json", q)
        save(folder / "retained-patch.json", patch)
        if scenario in ("crash_before_effect", "executor_false_success"):
            failure = die(original_path, q, accounts["worker-1"], folder, before=True)
        elif scenario == "authority_revoked":
            admin.patch(name, [
                {"op": "replace", "path": PREFIX + "active", "value": "false"},
                {"op": "replace", "path": PREFIX + "generation", "value": "2"},
            ], required=True)
            assert not worker.patch(name, patch)["accepted"]
            # A worker also cannot turn the destination-local grant back on.
            assert not worker.patch(name, [
                {"op": "replace", "path": PREFIX + "active", "value": "true"},
            ])["accepted"]
            failure = time.monotonic_ns()
        elif scenario == "foreign_attempt":
            foreign = dict(q, attempt="foreign-authorized-attempt",
                           executor="system:serviceaccount:" + ns + ":worker-2")
            other = Kube(accounts["worker-2"], ns)
            assert other.patch(name, frozen_patch(foreign))["accepted"]
            failure = time.monotonic_ns()
        elif scenario == "commit_lost_ack":
            assert worker.patch(name, patch)["accepted"]
            failure = time.monotonic_ns()
        else:
            failure = die(original_path, q, accounts["worker-1"], folder)
        old_envelope, old_challenge = None, str(uuid.uuid4())
        if scenario == "stale_signed_observation":
            old_envelope = observe(reader, args.audit, q, old_challenge, key)
        if scenario in ("current_state_drift", "stale_signed_observation"):
            admin.patch(name, [{"op": "replace", "path": "/spec/template/spec/containers/0/image",
                                "value": "registry.k8s.io/pause:3.8"}], required=True)
            failure = time.monotonic_ns()
        deliveries = []
        if scenario == "duplicate_delivery":
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                deliveries = list(pool.map(lambda _: worker.patch(name, patch), range(8)))
            assert not any(d["accepted"] for d in deliveries)
        outcomes, timing = {}, {}
        order = ("ordinary", "aegis") if ordinal % 2 == 0 else ("aegis", "ordinary")
        for variant in order:
            path = folder / (variant + ".sqlite")
            local = clone_journal(original, path)
            if scenario == "recovery_owner_race":
                def contender(owner):
                    return recover(Journal(path), q["logical_id"], owner, reader,
                                   args.audit, key, root, variant, args.binary)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    contenders = list(pool.map(contender, ["successor-a", "successor-b"]))
                winners = [r for r in contenders if r[1]["owner_won"]]
                assert len(winners) == 1
                outcome, data = winners[0]
                data["owner_results"] = [r[0]["closure"] for r in contenders]
            elif scenario == "stale_signed_observation":
                challenge = str(uuid.uuid4())
                started = time.monotonic_ns()
                package = aegis.prepare(old_envelope, q, root, old_challenge, key, args.binary)
                outcome = (ordinary.assess(old_envelope, q, root, challenge)
                           if variant == "ordinary" else
                           aegis.assess(old_envelope, q, root, challenge, package, args.binary))
                data = {"owner_won": True, "total_ms": (time.monotonic_ns()-started)/1e6,
                        "envelope": old_envelope, "question": q, "challenge": challenge,
                        "package": package}
            else:
                outcome, data = recover(
                    local, q["logical_id"], "successor", reader, args.audit, key, root,
                    variant, args.binary,
                    unavailable=scenario in ("evidence_unavailable", "evidence_available_later"),
                    claim={"closure": "CLOSED", "attempt": q["attempt"]}
                    if scenario == "executor_false_success" else None,
                )
            data["since_failure_ms"] = (time.monotonic_ns() - failure) / 1e6
            if scenario == "evidence_available_later":
                assert outcome["closure"] == "UNKNOWN"
                data["initial_unknown_ms"] = data["since_failure_ms"]
                wait_start = time.monotonic_ns()
                time.sleep(0.25)
                later, later_data = reconcile(local, q["logical_id"], reader, args.audit,
                                              key, root, variant, args.binary)
                assert later["closure"] == "CLOSED", later
                data["injected_wait_ms"] = (time.monotonic_ns() - wait_start)/1e6 - later_data["total_ms"]
                data["later_resolution_ms"] = later_data["total_ms"]
                data["later_result"] = later
            outcomes[variant], timing[variant] = outcome, data
            save(folder / (variant + "-result.json"), outcome)
            save(folder / (variant + "-evidence.json"), data)
        closed = scenario in (
            "commit_lost_ack", "executor_death_after_commit", "successor_recovery",
            "duplicate_delivery", "recovery_owner_race",
        )
        assert all(r["closure"] == ("CLOSED" if closed else "UNKNOWN")
                   for r in outcomes.values()), outcomes
        fresh = observe(reader, args.audit, q, "native-count", key)
        physical = open_evidence(fresh, q, root, "native-count")
        count = len(physical["records"])
        expected_count = 0 if scenario in ("crash_before_effect", "authority_revoked",
                                         "executor_false_success") else 1
        assert count == expected_count, (scenario, count)
        for result in outcomes.values():
            if result["retry"] == "REPLAY_FROZEN_CAS":
                assert not closed and count == 0
                assert current_image(physical["snapshot"], q) == q["before_image"]
        # Actually validate permitted redelivery; never rebase the retained patch.
        retry_check = None
        if any(r["retry"] == "REPLAY_FROZEN_CAS" for r in outcomes.values()):
            replay = worker.patch(name, patch)
            delivered = observe(reader, args.audit, q, "retry-count", key)
            after = open_evidence(delivered, q, root, "retry-count")
            assert len(after["records"]) <= 1
            retry_check = {"accepted": replay["accepted"], "logical_effects_after": len(after["records"])}
        results.append({
            "scenario": scenario, "physical_effects_before_recovery": count,
            "results": outcomes,
            "timing": {v: {k: x for k, x in data.items()
                            if k not in ("envelope", "package", "question", "challenge")}
                       for v, data in timing.items()},
            "duplicate_redeliveries": len(deliveries), "safe_retry_validation": retry_check,
        })
    controls = []
    obj = deployment(admin, "controls")
    q = question(obj, ns, IMAGE, "worker-1")
    assert worker.patch("controls", frozen_patch(q))["accepted"]
    challenge = "independent-controls"
    envelope = observe(reader, args.audit, q, challenge, key)
    initial, package = pair(envelope, q, root, challenge, key, args.binary)
    assert all(r["closure"] == "CLOSED" for r in initial.values())
    bad = copy.deepcopy(envelope)
    bad["signature"] = base64.b64encode(b"x" * 64).decode()
    wrong = dict(q, image="unrequested-image")
    for label, frame, expected in (("altered_signature", bad, q), ("wrong_question", envelope, wrong)):
        a = ordinary.assess(frame, expected, root, challenge)
        b = aegis.assess(frame, expected, root, challenge, package, args.binary)
        assert a["closure"] == b["closure"] == "UNKNOWN"
        controls.append({"control": label, "ordinary": a, "aegis": b})
    admin.run("delete", "deployment", "controls", "--wait=true")
    deployment(admin, "controls")
    replaced = observe(reader, args.audit, q, "new-uid", key)
    a = ordinary.assess(replaced, q, root, "new-uid")
    b = aegis.assess(replaced, q, root, "new-uid", package, args.binary)
    assert a["closure"] == b["closure"] == "UNKNOWN"
    controls.append({"control": "uid_replacement", "ordinary": a, "aegis": b})
    compatibility = []
    for label in ("wrong_root", "claim_downgrade", "wrong_request", "altered_bundle"):
        altered = copy.deepcopy(package)
        if label == "wrong_root":
            altered["policy"]["public_keys"]["observer"] = base64.b64encode(b"z"*32).decode()
        elif label == "claim_downgrade":
            altered["policy"]["required_claim_type"] = "POSTCONDITION"
        elif label == "wrong_request":
            altered["bundle"]["execution"]["payload"]["request"]["attempt_id"] = "other"
        else:
            altered["bundle"]["destination"]["payload"]["effect_count"] = 0
        result = aegis.assess(envelope, q, root, challenge, altered, args.binary)
        assert result["closure"] == "UNKNOWN"
        compatibility.append({"control": label, "result": result})
    # Marginal second operation: rollback, same native adapter and checker.
    second = deployment(admin, "second-operation")
    first_q = question(second, ns, IMAGE, "worker-1")
    assert worker.patch(first_q["name"], frozen_patch(first_q))["accepted"]
    second_q = question(admin.get(first_q["name"]), ns, first_q["before_image"], "worker-1", "rollback")
    second_path = out / "rollback-issued.sqlite"
    journal = Journal(second_path)
    journal.issue(second_q, frozen_patch(second_q))
    folder = out / "rollback"
    folder.mkdir()
    die(second_path, second_q, accounts["worker-1"], folder)
    rollback = {}
    for variant in ("ordinary", "aegis"):
        local = clone_journal(journal, out / ("rollback-"+variant+".sqlite"))
        result, data = recover(local, second_q["logical_id"], "rollback-successor", reader,
                               args.audit, key, root, variant, args.binary)
        assert result["closure"] == "CLOSED", result
        rollback[variant] = {"result": result, "total_ms": data["total_ms"]}
    save(out / "root.json", {"observer_root": root})
    summary = {
        "main": aegis.BASE, "scenarios": results, "shared_controls": controls,
        "aegis_compatibility_controls": compatibility, "second_operation": rollback,
        "invariants": {"false_closed": 0, "unsafe_retry": 0,
                       "recovery_duplicate_logical_effect": 0,
                       "unauthorized_governed_image_effect": 0},
        "native": True, "aegis_projection_grade": "simulation",
        "executor_ack_loss": "result not retained or returned; API response itself may have arrived",
    }
    save(out / "results.json", summary)
    print(json.dumps({"cases": len(results), "controls": len(controls),
                      "compatibility_controls": len(compatibility),
                      "invariants": summary["invariants"]}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--child", action="store_true")
    p.add_argument("--before", action="store_true")
    p.add_argument("--journal", type=Path)
    p.add_argument("--effect")
    p.add_argument("--worker")
    p.add_argument("--marker", type=Path)
    p.add_argument("--admin", type=Path)
    p.add_argument("--audit", type=Path)
    p.add_argument("--private", type=Path)
    p.add_argument("--binary", type=Path)
    p.add_argument("--out", type=Path)
    args = p.parse_args()
    if args.child:
        child(args)
    else:
        corpus(args)


if __name__ == "__main__":
    main()
