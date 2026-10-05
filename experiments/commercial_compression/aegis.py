"""Smallest existing consumer integration; fixed wire projection is SIMULATION."""

import base64
import copy
import hashlib
import json
import struct
import subprocess
import tempfile
from pathlib import Path

from integration import continuation, current_image, digest, open_evidence, rejected

BASE = "04434db12fa0c85d3497faf6ebb40df937092c5d"
SCHEMA = "aegis/composite-evidence/v1"
PROFILE = "postgresql/native-fence/v1"


def relation(*parts):
    h = hashlib.sha256()
    for part in parts:
        value = part.encode()
        h.update(struct.pack(">Q", len(value)))
        h.update(value)
    return "sha256:" + h.hexdigest()


def wire(value):
    return json.dumps(value, separators=(",", ":")).encode()


def seal(role, body, key):
    return {
        "key_id": "observer",
        "payload": body,
        "signature": base64.b64encode(
            key.sign((SCHEMA + "\0" + role + "\0").encode() + wire(body))
        ).decode(),
    }


def request(question):
    target = question["uid"] + "/" + question["container"]
    before = {
        "target": target,
        "revision": question["before_rv"],
        "digest": digest({"image": question["before_image"]}),
    }
    after = {
        "target": target,
        "revision": "image-predicate/v1",
        "digest": digest({"image": question["image"]}),
    }
    operation = "deployment-image:" + question["logical_id"]
    parts = [
        question["subject"], "release-controller", target, before["revision"],
        before["digest"], operation, after["revision"], after["digest"],
    ]
    return {
        "subject": {"id": question["subject"], "kind": "release-controller"},
        "executor": {"id": question["executor"], "kind": "service-account"},
        "before": before, "after": after, "operation": operation,
        "attempt_id": question["attempt"],
        "admission_binding": relation("admission-v0", *parts),
    }, relation("effect-v0", *parts)


def inspect(bundle, policy, binary):
    with tempfile.TemporaryDirectory() as folder:
        b, p = Path(folder) / "bundle.json", Path(folder) / "policy.json"
        b.write_bytes(wire(bundle))
        p.write_bytes(wire(policy))
        result = subprocess.run(
            [str(binary), "-bundle", str(b), "-policy", str(p), "-format", "json"],
            capture_output=True, timeout=15,
        )
        if result.returncode not in (0, 1):
            raise ValueError("Aegis consumer failed: " + result.stderr.decode())
        return json.loads(result.stdout)


def prepare(envelope, question, root, challenge, key, binary):
    facts = open_evidence(envelope, question, root, challenge)
    req, effect = request(question)
    policy_hash = digest({"question": question, "profile": "kubernetes-image-cas/v1"})
    admission = {
        "build_sha": BASE, "case_id": challenge, "policy_hash": policy_hash,
        "request_binding": req["admission_binding"], "observed_before": req["before"],
        "allowed_operation": req["operation"], "authority_epoch": question["epoch"],
        "authority_generation": question["generation"], "authority_active": True,
    }
    execution = {
        "build_sha": BASE, "case_id": challenge, "grade": "simulation",
        "claim_type": "EXACT_EFFECT", "intent_id": question["logical_id"],
        "request": req, "effect_id": effect, "custody_generation": 1,
        "authority_epoch": question["epoch"],
        "authority_generation": question["generation"], "admitted": True,
        "acknowledgement_lost": True,
        "recovered_by": {"id": "native-observer", "kind": "observer"},
        "claimed_closure": "UNKNOWN", "claimed_causality": "UNPROVEN",
        "claimed_history": "UNTRUSTED_HISTORY",
    }
    obj = facts["snapshot"]
    grant = obj["metadata"]["annotations"] if obj else {}
    destination = {
        "build_sha": BASE, "case_id": challenge, "profile": PROFILE,
        "observed": {}, "effect_count": len(facts["records"]),
        "authority_currently_active": grant.get("compression.example/active") == "true",
        "current_authority_generation": int(
            grant.get("compression.example/generation", question["generation"])
        ),
    }
    if obj is None:
        destination["observation_error"] = "destination evidence unavailable"
    else:
        destination["observed"] = {
            "target": req["after"]["target"], "revision": "image-predicate/v1",
            "digest": digest({"image": current_image(obj, question)}),
        }
        if len(facts["records"]) == 1:
            row = facts["records"][0]
            before = dict(req["before"], revision=row["before_rv"],
                          digest=digest({"image": row["before_image"]}))
            after = dict(req["after"], digest=digest({"image": row["image"]}))
            destination["commit"] = {
                "effect_id": effect, "attempt_id": row["attempt"],
                "owner": {"id": row["executor"], "kind": "service-account"},
                "custody_generation": 1, "admission_binding": req["admission_binding"],
                "authority_epoch": row["epoch"],
                "authority_generation": row["generation"],
                "authority_active": row["active"], "operation": req["operation"],
                "before": before, "after": after, "committed_at": row["committed_at"],
            }
    bundle = {
        "schema": SCHEMA, "admission": seal("admission", admission, key),
        "execution": seal("execution", execution, key),
        "destination": seal("destination", destination, key),
    }
    policy = {
        "schema": SCHEMA, "build_sha": BASE, "case_id": challenge,
        "destination_profile": PROFILE, "admission_policy_hash": policy_hash,
        "required_claim_type": "EXACT_EFFECT", "maximum_grade": "simulation",
        "public_keys": {"observer": root},
        "role_keys": {role: "observer" for role in ("admission", "execution", "destination")},
        "history_id": "",
    }
    # Ask the existing library to derive the declaration fields. Do not implement
    # a second custom A/C/P checker just to prepare the library's required claims.
    derived = inspect(bundle, policy, binary)
    execution["claimed_closure"] = derived["closure"]
    execution["claimed_causality"] = derived["causality"]
    bundle["execution"] = seal("execution", execution, key)
    return {"bundle": bundle, "policy": policy}


def assess(envelope, question, root, challenge, package, binary):
    try:
        facts = open_evidence(envelope, question, root, challenge)
        req, _ = request(question)
        bundle, policy = copy.deepcopy(package["bundle"]), copy.deepcopy(package["policy"])
        expected_hash = digest({"question": question, "profile": "kubernetes-image-cas/v1"})
        if (
            bundle["execution"]["payload"]["request"] != req
            or policy["case_id"] != challenge
            or policy["admission_policy_hash"] != expected_hash
            or policy["public_keys"] != {"observer": root}
            or policy["required_claim_type"] != "EXACT_EFFECT"
            or policy["maximum_grade"] != "simulation"
            or policy["destination_profile"] != PROFILE
            or policy["build_sha"] != BASE
        ):
            raise ValueError("Aegis package does not match independent question/roots/profile")
        result = inspect(bundle, policy, binary)
        closed = result["closure"] == "CLOSED" and result["claims_supported"]
        predicate = current_image(facts["snapshot"], question)
        return {
            "closure": "CLOSED" if closed else "UNKNOWN",
            "winner": facts["records"][0] if len(facts["records"]) == 1 else None,
            "authority_at_commit": result["authority_at_commit"],
            "current_truth": None if predicate is None else predicate == question["image"],
            "retry": continuation(question, facts, closed),
            "reason": result["errors"] + result["uncertainty"],
            "aegis_report": result,
        }
    except Exception as error:
        return rejected(str(error) or type(error).__name__)
