"""Independent observer integration; raw native events are retained unchanged."""

import json
import time

from integration import digest, signed


def observe(reader, audit_path, question, challenge, key, unavailable=False, claim=None):
    if unavailable:
        snapshot, audit = None, None
    else:
        snapshot = reader.get(question["name"])
        audit = []
        with open(audit_path) as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ref = event.get("objectRef", {})
                if ref.get("namespace") == question["namespace"] and ref.get("name") == question["name"]:
                    audit.append(event)
    return signed({
        "question_digest": digest(question), "challenge": challenge,
        "observed_at": time.time(), "snapshot": snapshot, "audit": audit,
        "executor_claim": claim,
    }, key)
