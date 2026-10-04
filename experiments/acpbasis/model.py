"""Finite operational model; predicates are derived, never nondeterministically assigned.

Two possible attempts, one physical effect, two authority generations, two
target values. Authorization may be revoked/restored. The model explores all
reachable states to a fixed point and checks every Boolean function of each
two-coordinate projection. It is not a universal or probabilistic theorem.
"""

from collections import deque
from dataclasses import dataclass, replace
from itertools import product
import json


@dataclass(frozen=True)
class Profile:
    fence: bool = False
    sole_origin: bool = False
    predicate: str = "current-state"
    allow_erasure: bool = False


@dataclass(frozen=True)
class State:
    active: bool = True
    generation: int = 1
    # Authority facts at the actual event remain historical after revocation.
    cause: str = ""
    commit_active: bool = False
    commit_generation: int = 0
    present: bool = False
    target: int = 1
    expired: bool = False


def coordinates(s, profile):
    if not s.cause:
        return None  # No actual effect: do not fabricate A=0/C=0 cube corners.
    a = s.commit_active and s.commit_generation == 1
    c = s.cause == "claimed"
    if profile.predicate == "current-state":
        p = s.target == 1
    elif profile.predicate == "event-exists":
        p = s.present
    elif profile.predicate == "unexpired-event":
        p = s.present and not s.expired
    else:
        raise ValueError(profile.predicate)
    return (int(a), int(c), int(p))


def successors(s, profile):
    yield "revoke", replace(s, active=False)
    yield "restore", replace(s, active=True)
    yield "successor-generation", replace(s, generation=2)
    if profile.predicate == "current-state":
        yield "later-mutation", replace(s, target=0)
        yield "later-restoration", replace(s, target=1)
    if profile.predicate == "unexpired-event":
        yield "expiry", replace(s, expired=True)
    if s.cause and profile.allow_erasure:
        yield "erase-event", replace(s, present=False)
    if not s.cause and (not profile.fence or (s.active and s.generation == 1)):
        for cause in ("claimed", "other"):
            if profile.sole_origin and cause != "claimed":
                continue
            yield "commit-" + cause, replace(
                s, cause=cause, commit_active=s.active,
                commit_generation=s.generation, present=True, target=1,
            )


def explore(profile):
    initial = State()
    traces = {initial: []}
    queue = deque([initial])
    while queue:
        current = queue.popleft()
        for event, new in successors(current, profile):
            if new not in traces:
                traces[new] = traces[current] + [event]
                queue.append(new)
    return traces


def functions_for(rows, axis):
    """Return all total Boolean functions agreeing on reachable projections.

    Functions have four outputs, indexed by the two retained bits. There are
    exactly 16 candidates. Unreachable input projections may have either output.
    """
    kept = [i for i in range(3) if i != axis]
    return [list(f) for f in product((0, 1), repeat=4)
            if all(f[2 * row[kept[0]] + row[kept[1]]] == row[axis] for row in rows)]


def summarize(profile):
    traces = explore(profile)
    witnesses = {}
    for state, trace in traces.items():
        row = coordinates(state, profile)
        if row is not None and row not in witnesses:
            witnesses[row] = trace
    pairs = {}
    for axis, name in enumerate("ACP"):
        kept = [i for i in range(3) if i != axis]
        candidates = [{
            "left": list(left), "left_trace": witnesses[left],
            "right": list(right), "right_trace": witnesses[right],
        } for left in sorted(witnesses) for right in sorted(witnesses)
            if left[axis] != right[axis] and
            tuple(left[i] for i in kept) == tuple(right[i] for i in kept)]
        pairs[name] = min(candidates, key=lambda pair:
                          len(pair["left_trace"]) + len(pair["right_trace"]), default=None)
    return {
        "states": len(traces),
        "cube": {"".join(map(str, row)): witnesses[row] for row in sorted(witnesses)},
        "functions": {name: functions_for(witnesses, axis) for axis, name in enumerate("ACP")},
        "separating_pairs": pairs,
    }


PROFILES = {
    "mutable-open-boundary": Profile(),
    "mutable-atomic-fence": Profile(fence=True),
    "mutable-sole-origin": Profile(sole_origin=True),
    "immutable-event": Profile(predicate="event-exists"),
    "immutable-fenced-sole-origin": Profile(True, True, "event-exists"),
    "immutable-event-erasure-enabled": Profile(predicate="event-exists", allow_erasure=True),
    "immutable-expiring-predicate": Profile(predicate="unexpired-event"),
}


if __name__ == "__main__":
    print(json.dumps({name: summarize(profile) for name, profile in PROFILES.items()}, indent=2, sort_keys=True))
