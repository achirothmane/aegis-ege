"""Customer recovery contract; Aegis does not supply the native recovery driver."""

import time
import uuid

import ordinary
from collector import observe
from integration import rejected


def recover(journal, logical_id, owner, reader, audit_path, key, root, variant,
            binary=None, unavailable=False, claim=None):
    if not journal.takeover(logical_id, owner):
        return rejected("another recovery owner won the durable CAS"), {"owner_won": False}
    return reconcile(journal, logical_id, reader, audit_path, key, root, variant,
                     binary, unavailable, claim)


def reconcile(journal, logical_id, reader, audit_path, key, root, variant,
              binary=None, unavailable=False, claim=None):
    started = time.monotonic_ns()
    retained = journal.load(logical_id)
    question = retained["question"]
    challenge = str(uuid.uuid4())
    envelope = observe(reader, audit_path, question, challenge, key, unavailable, claim)
    collected = time.monotonic_ns()
    package = None
    if variant == "aegis":
        import aegis

        package = aegis.prepare(envelope, question, root, challenge, key, binary)
        result = aegis.assess(envelope, question, root, challenge, package, binary)
    else:
        result = ordinary.assess(envelope, question, root, challenge)
    finished = time.monotonic_ns()
    # A justified UNKNOWN is retained as knowledge, never a workflow success.
    journal.complete(logical_id, result)
    return result, {
        "owner_won": True, "collection_ms": (collected - started) / 1e6,
        "judgment_ms": (finished - collected) / 1e6,
        "total_ms": (finished - started) / 1e6,
        "envelope": envelope, "question": question, "challenge": challenge,
        "package": package,
    }
