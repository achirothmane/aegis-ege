"""Purpose-specific ordinary independent checker. No Aegis dependency."""

from integration import continuation, current_image, open_evidence, rejected


def assess(envelope, question, root, challenge):
    try:
        facts = open_evidence(envelope, question, root, challenge)
        records = facts["records"]
        record = records[0] if len(records) == 1 else None
        predicate = current_image(facts["snapshot"], question)
        predicate = None if predicate is None else predicate == question["image"]
        authority = bool(
            record
            and record["active"]
            and record["epoch"] == question["epoch"]
            and record["generation"] == question["generation"]
        )
        exact = bool(
            record
            and record["effect"] == question["logical_id"]
            and record["attempt"] == question["attempt"]
            and record["executor"] == question["executor"]
            and record["uid"] == question["uid"]
            and record["before_rv"] == question["before_rv"]
            and record["before_image"] == question["before_image"]
            and record["image"] == question["image"]
        )
        closed = bool(authority and exact and predicate)
        reason = (
            "exact authorized native commit and fresh required image"
            if closed
            else "no single winning audit commit"
            if record is None
            else "a different attempt/executor won"
            if not exact
            else "authority at commit is unsupported"
            if not authority
            else "current required image is false or unavailable"
        )
        return {
            "closure": "CLOSED" if closed else "UNKNOWN",
            "winner": record,
            "authority_at_commit": "VALID_FOR_WINNER" if authority else "UNPROVEN",
            "current_truth": predicate,
            "retry": continuation(question, facts, closed),
            "reason": reason,
        }
    except Exception as error:
        return rejected(str(error) or type(error).__name__)
