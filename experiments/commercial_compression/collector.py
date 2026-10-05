"""Independent observer integration; raw native events are retained unchanged."""

import json
import subprocess
import time

from integration import digest, signed


def observe(
    reader, audit_path, question, challenge, key, unavailable=False, claim=None
):
    errors = []
    try:
        if unavailable:
            raise OSError("injected native observer source unavailable")
        snapshot = reader.get(question["name"])
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        snapshot = None
        errors.append(str(error))
    try:
        if unavailable:
            raise OSError("injected native audit source unavailable")
        audit = []
        with open(audit_path) as stream:
            for line in stream:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ref = event.get("objectRef", {})
                if (
                    ref.get("namespace") == question["namespace"]
                    and ref.get("name") == question["name"]
                ):
                    audit.append(event)
    except OSError as error:
        audit = None
        errors.append(str(error))
    return signed(
        {
            "question_digest": digest(question),
            "challenge": challenge,
            "observed_at": time.time(),
            "snapshot": snapshot,
            "audit": audit,
            "executor_claim": claim,
            "observation_errors": errors,
        },
        key,
    )
