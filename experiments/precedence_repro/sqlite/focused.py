"""Focused native adversarial evidence; operational facts remain separate from claims."""
from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

from oracle import ReplayOracle
from sqlite_model import Profile, Q, Store


def run_trace(profile, commands, evaluated=Q):
    store = Store(profile)
    replay = ReplayOracle(profile.kind, profile.guard, profile.sole_attempt)
    trace = []
    for command in commands:
        actual = store.apply(command)
        expected = replay.step(command)
        if actual != expected or store.physical_state() != replay.state():
            raise AssertionError((command, actual, expected, store.physical_state(), replay.state()))
        observation = store.observe(evaluated)
        reference = replay.observation(evaluated)
        if observation is None:
            if reference is not None:
                raise AssertionError("native no-effect disagrees with oracle")
        elif {k: observation[k] for k in ("A", "C", "P", "EXACT_EFFECT")} != reference:
            raise AssertionError((observation, reference))
        trace.append({"operation": list(command), "outcome": actual, "observation": observation})
    facts = store.physical_state()
    receipts = [dict(r) for r in store.db.execute("SELECT * FROM receipts ORDER BY id")]
    store.close()
    return {"profile": {"kind": profile.kind, "guard": profile.guard, "sole_attempt": profile.sole_attempt},
            "evaluated_attempt_executor": list(evaluated), "trace": trace,
            "physical_facts": facts, "producer_claims": receipts}


def lost_ack_evidence(before_commit=False):
    with tempfile.TemporaryDirectory(prefix="independent-sqlite-") as temporary:
        database = str(Path(temporary) / "effects.sqlite")
        profile = Profile("mutable", True, False)
        store = Store(profile, database)
        store.close()
        command = [sys.executable, str(Path(__file__).with_name("crash_worker.py")), database]
        if before_commit:
            command.append("before-commit")
        child = subprocess.run(command, capture_output=True, timeout=20)
        reopened = Store(profile, database, initialize=False)
        before = reopened.observe()
        receipts_before = reopened.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        traces = []
        for actor in (Q, ("attempt-r", "executor-a"), ("attempt-q", "executor-b")):
            outcome = reopened.apply(("write", *actor))
            traces.append({"operation": ["write", *actor], "outcome": outcome,
                           "observed_for_original_q": reopened.observe(Q),
                           "observed_for_request": reopened.observe(actor)})
        effect_count = reopened.db.execute("SELECT COUNT(*) FROM commits").fetchone()[0]
        final_facts = reopened.physical_state()
        claims = [dict(r) for r in reopened.db.execute("SELECT * FROM receipts ORDER BY id")]
        reopened.close()
        expected_exit = 74 if before_commit else 73
        if child.returncode != expected_exit or child.stdout or child.stderr:
            raise AssertionError({"exit": child.returncode, "stdout": child.stdout.decode(), "stderr": child.stderr.decode()})
        if before_commit:
            if before is not None or traces[0]["outcome"] != "created:1":
                raise AssertionError("uncommitted crash persisted an effect")
        else:
            if before is None or before["creator"] != list(Q) or traces[0]["outcome"] != "duplicate:1":
                raise AssertionError("lost-ACK committed effect did not survive")
        if receipts_before != 0 or effect_count != 1:
            raise AssertionError("ACK or cardinality mismatch")
        return {"crash_point": "inside transaction before COMMIT" if before_commit else "after COMMIT before ACK",
                "child_exit_code": child.returncode, "child_stdout": child.stdout.decode(),
                "child_stderr": child.stderr.decode(), "orderly_child_connection_close": False,
                "native_journal_mode": "WAL", "native_synchronous": "FULL",
                "reopened_observation_before_retry": before, "receipts_before_retry": receipts_before,
                "retry_trace": traces, "physical_effect_count_after_retries": effect_count,
                "final_physical_facts": final_facts, "producer_claims": claims}


def serialized_commit_revoke():
    with tempfile.TemporaryDirectory(prefix="sqlite-serialization-") as temporary:
        path = str(Path(temporary) / "serial.sqlite")
        profile = Profile("mutable", True, False)
        writer = Store(profile, path)
        revoker = Store(profile, path, initialize=False)
        block = []

        def try_revoke():
            try:
                revoker.apply(("revoke", "executor-a"))
            except sqlite3.OperationalError as error:
                block.append(str(error))
            else:
                raise AssertionError("revocation interleaved with writer commit")

        outcome = writer.apply(("write", *Q), precommit=try_revoke)
        revoker.apply(("revoke", "executor-a"))
        historical = writer.observe()
        live_grant = writer.db.execute("SELECT active FROM grants WHERE executor='executor-a'").fetchone()[0]
        writer.close()
        revoker.close()
        if not block or historical["A"] != 1 or live_grant != 0:
            raise AssertionError("serialization or historical authority failed")
        return {"writer_outcome": outcome, "revocation_attempt_before_commit": "blocked by native SQLite write lock",
                "sqlite_error": block[0], "revocation_after_commit": "committed",
                "current_grant_active": live_grant, "historical_observation": historical,
                "reverse_order": run_trace(profile, [("revoke", "executor-a"), ("write", *Q)])}


def surrounding_obligation_probes():
    # The underlying physical experiment is real. The envelope changes are explicit,
    # fixed-domain violations, rather than newly invented truth coordinates.
    base = run_trace(Profile(), [("write", *Q)])
    physical = base["trace"][-1]["observation"]
    obligation_names = ("fixed_scope", "exact_physical_selection", "cardinality", "trusted_evidence",
                        "current_observer_truthfulness_and_freshness", "history_continuity", "independent_claim_policy")
    baseline = {name: True for name in obligation_names}
    probes = []
    classifications = {
        "fixed_scope": "fixed-domain violation",
        "exact_physical_selection": "identity/cardinality ambiguity",
        "cardinality": "identity/cardinality ambiguity",
        "trusted_evidence": "trust",
        "current_observer_truthfulness_and_freshness": "freshness",
        "history_continuity": "history",
        "independent_claim_policy": "claim-policy dependency"}
    for obligation in obligation_names:
        envelope = dict(baseline)
        envelope[obligation] = False
        accepted = physical["EXACT_EFFECT"] and all(envelope.values())
        probes.append({"classification": classifications[obligation], "changed_surrounding_obligation": obligation,
                       "unchanged_actual_physical_semantics": {k: physical[k] for k in ("A", "C", "P")},
                       "baseline_fixed_contract_decision": physical["EXACT_EFFECT"],
                       "decision_with_violated_obligation": accepted, "envelope": envelope,
                       "comparable_within_fixed_contract": False,
                       "proposes_new_axis": False})
    duplicate_physical = run_trace(Profile(), [("write", *Q), ("write_again", "attempt-r", "executor-a")])
    stale = run_trace(Profile(), [("write", *Q), ("tick",), ("mutate",)])
    foreign_receipt = run_trace(Profile(), [("write", "attempt-r", "executor-a"), ("write", *Q)])
    return {"base_native_evidence": base, "explicit_envelope_probes": probes,
            "outside_contract_two_effects_for_same_operation": duplicate_physical,
            "old_observation_with_changed_present_state": stale,
            "request_named_in_duplicate_receipt_is_not_creator": foreign_receipt,
            "interpretation": "No equal truthful semantic ACP had different EXACT_EFFECT under the fixed contract. Envelope failures are classified before considering additional axes. Stale claimed ACP is not equal present semantic ACP."}


def run_focused():
    evidence = {
        "lost_ack_after_commit": lost_ack_evidence(),
        "process_exit_before_commit": lost_ack_evidence(before_commit=True),
        "adjacent_serialized_commit_revoke": serialized_commit_revoke(),
        "sole_writer_multiple_attempts": run_trace(Profile(), [("write", "attempt-r", "executor-a"), ("write", *Q)]),
        "same_attempt_different_executor": run_trace(Profile(), [("write", "attempt-q", "executor-b"), ("write", *Q)]),
        "revocation_then_restoration": run_trace(Profile("mutable", True, False),
                                                  [("revoke", "executor-a"), ("restore", "executor-a"), ("write", *Q)]),
        "epoch_changes_before_unguarded_commit": run_trace(Profile(), [("epoch",), ("write", *Q)]),
        "epoch_changes_before_guarded_commit": run_trace(Profile("mutable", True), [("epoch",), ("write", *Q)]),
        "epoch_changes_after_commit": run_trace(Profile("mutable", True), [("write", *Q), ("epoch",)]),
        "mutation_and_restoration": run_trace(Profile(), [("write", *Q), ("mutate",), ("restore_target",)]),
        "erasure_preserves_historical_origin": run_trace(Profile("erasable"), [("write", *Q), ("erase",), ("write", *Q)]),
        "expiry_preserves_bytes_and_historical_origin": run_trace(Profile("expiring"),
                                                                  [("write", *Q), ("tick",), ("tick",), ("tick",)])}
    exact_scope = {}
    for field, wrong in (("subject", "different-subject"), ("action", "different-action"),
                         ("target", "different-target"), ("boundary", "different-boundary"), ("generation", 1)):
        exact_scope[field] = {
            "unchecked": run_trace(Profile(), [("rescope_grant", field, wrong), ("write", *Q)]),
            "guarded": run_trace(Profile("mutable", True), [("rescope_grant", field, wrong), ("write", *Q)])}
    evidence["scope_mismatch_checks"] = exact_scope
    evidence["same_semantics_disagreement_search"] = surrounding_obligation_probes()
    return evidence
