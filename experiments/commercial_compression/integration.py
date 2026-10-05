"""Shared customer-owned evidence, binding and continuation work."""

import base64
import hashlib
import json

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

DOMAIN = b"commercial-kubernetes-evidence/v1\0"
PREFIX = "/metadata/annotations/compression.example~1"


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest(value):
    return "sha256:" + hashlib.sha256(encoded(value)).hexdigest()


def signed(body, key):
    return {
        "body": body,
        "signature": base64.b64encode(key.sign(DOMAIN + encoded(body))).decode(),
    }


def rejected(reason):
    return {
        "closure": "UNKNOWN",
        "winner": None,
        "authority_at_commit": "UNPROVEN",
        "current_truth": None,
        "retry": "HOLD",
        "reason": reason,
    }


def open_evidence(envelope, question, root, challenge):
    body = envelope["body"]
    Ed25519PublicKey.from_public_bytes(base64.b64decode(root)).verify(
        base64.b64decode(envelope["signature"]), DOMAIN + encoded(body)
    )
    if body["question_digest"] != digest(question) or body["challenge"] != challenge:
        raise ValueError("wrong independent question or stale observation challenge")
    snapshot = body["snapshot"]
    if snapshot and snapshot["metadata"]["uid"] != question["uid"]:
        raise ValueError("target UID replaced; name reuse is not the same target")
    records = {}
    for event in body["audit"] or []:
        if (
            event["stage"] != "ResponseComplete"
            or event["verb"] != "patch"
            or event.get("responseStatus", {}).get("code") != 200
        ):
            continue
        response = event.get("responseObject", {})
        if response.get("metadata", {}).get("uid") != question["uid"]:
            continue
        patch = event.get("requestObject", [])
        if not isinstance(patch, list):
            continue
        tests = {p["path"]: p["value"] for p in patch if p["op"] == "test"}
        writes = {
            p["path"]: p["value"] for p in patch if p["op"] in ("add", "replace")
        }
        if writes.get(PREFIX + "effect") != question["logical_id"]:
            continue
        image_path = "/spec/template/spec/containers/0/image"
        executor = event["user"]["username"]
        metadata = response["metadata"]
        annotations = metadata["annotations"]
        required = (
            "/metadata/uid",
            "/metadata/resourceVersion",
            image_path,
            PREFIX + "active",
            PREFIX + "epoch",
            PREFIX + "generation",
        )
        if not all(p in tests for p in required):
            raise ValueError("audit mutation lacks the declared native CAS/fence")
        if (
            writes.get(PREFIX + "executor") != executor
            or annotations["compression.example/executor"] != executor
            or annotations["compression.example/attempt"]
            != writes.get(PREFIX + "attempt")
            or response["spec"]["template"]["spec"]["containers"][0]["image"]
            != writes.get(image_path)
        ):
            raise ValueError("audit authenticated winner and physical response disagree")
        records[event["auditID"]] = {
            "effect": writes[PREFIX + "effect"],
            "attempt": writes[PREFIX + "attempt"],
            "executor": executor,
            "uid": tests["/metadata/uid"],
            "before_rv": tests["/metadata/resourceVersion"],
            "before_image": tests[image_path],
            "image": writes[image_path],
            "active": tests[PREFIX + "active"] == "true",
            "epoch": int(tests[PREFIX + "epoch"]),
            "generation": int(tests[PREFIX + "generation"]),
            "committed_at": event["stageTimestamp"],
            "audit_id": event["auditID"],
            "resource_version": metadata["resourceVersion"],
        }
    return {
        "snapshot": snapshot,
        "records": list(records.values()),
        "audit_available": body["audit"] is not None,
        "executor_claim": body.get("executor_claim"),
    }


def current_image(snapshot, question):
    if snapshot is None:
        return None
    containers = snapshot["spec"]["template"]["spec"]["containers"]
    return next(c["image"] for c in containers if c["name"] == question["container"])


def continuation(question, facts, closed):
    if closed:
        return "NOT_NEEDED"
    obj = facts["snapshot"]
    if obj is None or facts["records"]:
        return "HOLD"
    meta = obj["metadata"]
    grant = meta["annotations"]
    if (
        meta["uid"] == question["uid"]
        and meta["resourceVersion"] == question["before_rv"]
        and current_image(obj, question) == question["before_image"]
        and grant["compression.example/active"] == "true"
        and int(grant["compression.example/epoch"]) == question["epoch"]
        and int(grant["compression.example/generation"]) == question["generation"]
    ):
        return "REPLAY_FROZEN_CAS"
    return "HOLD"
