"""Independent, storage-free replay oracle.

This module deliberately imports neither the SQLite implementation nor its constants.
It interprets requested operations, not a producer's returned status or receipt.
"""
from __future__ import annotations

from copy import deepcopy


class ReplayOracle:
    def __init__(self, kind="mutable", guard=False, sole_attempt=False):
        self.kind, self.guard, self.sole = kind, guard, sole_attempt
        self.epoch, self.time, self.order = 0, 0, 0
        self.permissions = {
            principal: {"executor": principal, "subject": "subject-7", "action": "set-approved",
                        "target": "target-7", "generation": 0, "boundary": "destination-writer", "active": 1}
            for principal in ("executor-a", "executor-b")}
        self.history = []
        self.live_events = {}
        self.live_value = "absent"
        self.last = None

    def clone(self):
        return deepcopy(self)

    def step(self, command):
        action = command[0]
        args = command[1:]
        self.order += 1
        answer = "ok"
        if action == "revoke":
            self.permissions[args[0]]["active"] = 0
        elif action == "restore":
            self.permissions[args[0]]["active"] = 1
        elif action == "epoch":
            self.epoch = 1
        elif action == "tick":
            if self.time < 3:
                self.time += 1
        elif action == "mutate":
            self.live_value, self.last = "changed", None
        elif action == "restore_target":
            self.live_value, self.last = "approved", None
        elif action == "erase":
            if self.kind in ("retained", "expiring"):
                answer = "denied:retention"
            else:
                self.live_events = {}
        elif action == "rescope_grant":
            for permission in self.permissions.values():
                permission[args[0]] = args[1]
        elif action in ("write", "write_again"):
            attempt, principal = args
            if self.history and action == "write":
                return "duplicate:1"
            if self.sole and not (attempt == "attempt-q" and principal == "executor-a"):
                return "denied:creator"
            permission = self.permissions[principal]
            scope = ("subject-7", "set-approved", "target-7", 0, "destination-writer")
            applicable = permission["active"] == 1 and self.epoch == 0
            for column, expected in zip(("subject", "action", "target", "generation", "boundary"), scope):
                applicable = applicable and permission[column] == expected
            if self.guard and not applicable:
                return "denied:authority"
            eid = len(self.history) + 1
            event = {"id": eid, "operation": "operation-7", "subject": scope[0], "action": scope[1],
                     "target": scope[2], "generation": scope[3], "boundary": scope[4], "value": "approved",
                     "attempt": attempt, "executor": principal, "committed_at": self.time,
                     "grant_active": permission["active"], "grant_generation": permission["generation"],
                     "epoch_at_commit": self.epoch, "grant_subject": permission["subject"],
                     "grant_action": permission["action"], "grant_target": permission["target"],
                     "grant_boundary": permission["boundary"]}
            self.history.append(event)
            self.live_events[eid] = {"effect_id": eid, "value": "approved", "valid_before": 3}
            self.live_value, self.last = "approved", eid
            answer = f"created:{eid}"
        else:
            raise ValueError(command)
        return answer

    def state(self):
        return {"runtime": {"epoch": self.epoch, "now": self.time},
                "grants": [dict(self.permissions[p]) for p in sorted(self.permissions)],
                "commits": deepcopy(self.history),
                "events": [dict(self.live_events[k]) for k in sorted(self.live_events)],
                "target": {"target": "target-7", "value": self.live_value, "last_effect_id": self.last}}

    def observation(self, evaluated=("attempt-q", "executor-a"), effect_id=1):
        if not (1 <= effect_id <= len(self.history)):
            return None
        event = self.history[effect_id - 1]
        authority_pairs = [("grant_subject", "subject"), ("grant_action", "action"),
                           ("grant_target", "target"), ("grant_generation", "generation"),
                           ("grant_boundary", "boundary"), ("epoch_at_commit", "generation")]
        authorized = event["grant_active"] == 1
        for previous, actual in authority_pairs:
            if event[previous] != event[actual]:
                authorized = False
        caused = all(x == y for x, y in zip((event["attempt"], event["executor"]), evaluated))
        if self.kind == "mutable":
            predicate = self.live_value == "approved"
        elif self.kind == "expiring":
            predicate = effect_id in self.live_events and self.time < 3
        else:
            predicate = effect_id in self.live_events
        return {"A": int(authorized), "C": int(caused), "P": int(predicate),
                "EXACT_EFFECT": all((authorized, caused, predicate))}
