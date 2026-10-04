import sqlite3
import unittest

from explore import explore_profile
from focused import lost_ack_evidence, run_focused, run_trace, serialized_commit_revoke
from sqlite_model import Profile, Q, Store, all_profiles


class NativeSQLiteTests(unittest.TestCase):
    def test_process_exit_lost_ack_and_reopen_retries(self):
        evidence = lost_ack_evidence()
        self.assertEqual(evidence["child_exit_code"], 73)
        self.assertEqual(evidence["physical_effect_count_after_retries"], 1)
        self.assertEqual(evidence["receipts_before_retry"], 0)
        for retry in evidence["retry_trace"]:
            self.assertEqual(retry["outcome"], "duplicate:1")
            self.assertEqual(retry["observed_for_original_q"]["C"], 1)
        self.assertEqual(evidence["retry_trace"][1]["observed_for_request"]["C"], 0)
        self.assertEqual(evidence["retry_trace"][2]["observed_for_request"]["C"], 0)

    def test_process_exit_before_commit_is_not_an_effect(self):
        evidence = lost_ack_evidence(before_commit=True)
        self.assertIsNone(evidence["reopened_observation_before_retry"])
        self.assertEqual(evidence["retry_trace"][0]["outcome"], "created:1")

    def test_revocation_serializes_and_commit_authority_is_historical(self):
        evidence = serialized_commit_revoke()
        self.assertEqual(evidence["current_grant_active"], 0)
        self.assertEqual(evidence["historical_observation"]["A"], 1)
        self.assertIsNone(evidence["reverse_order"]["trace"][-1]["observation"])

    def test_real_transaction_rollback_discards_effect_and_receipt(self):
        store = Store(Profile("mutable", True))
        def fail():
            raise RuntimeError("precommit failure")
        with self.assertRaises(RuntimeError):
            store.apply(("write", *Q), precommit=fail)
        self.assertIsNone(store.observe())
        self.assertEqual(store.db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0], 0)
        self.assertEqual(store.db.execute("SELECT COUNT(*) FROM journal").fetchone()[0], 0)
        self.assertEqual(store.db.execute("SELECT value FROM targets").fetchone()[0], "absent")
        store.close()

    def test_native_trigger_prevents_unchecked_authority_insert(self):
        store = Store(Profile("mutable", True))
        store.apply(("write", *Q))
        store.apply(("revoke", "executor-a"))
        columns = [row[1] for row in store.db.execute("PRAGMA table_info(commits)")]
        expressions = ["id+1" if c == "id" else c for c in columns]
        with self.assertRaisesRegex(sqlite3.IntegrityError, "authority restriction"):
            store.db.execute(f"INSERT INTO commits ({','.join(columns)}) SELECT {','.join(expressions)} FROM commits WHERE id=1")
        self.assertEqual(store.db.execute("SELECT COUNT(*) FROM commits").fetchone()[0], 1)
        store.close()

    def test_commit_history_and_event_immutability_are_native(self):
        store = Store(Profile("retained"))
        store.apply(("write", *Q))
        for sql in ("DELETE FROM commits", "UPDATE commits SET attempt='forged'", "UPDATE events SET value='forged'", "DELETE FROM events"):
            with self.assertRaises(sqlite3.IntegrityError):
                store.db.execute(sql)
        self.assertEqual(store.observe()["P"], 1)
        store.close()

    def test_origin_is_not_deduced_from_same_operation_or_same_attempt(self):
        for foreign in (("attempt-r", "executor-a"), ("attempt-q", "executor-b")):
            evidence = run_trace(Profile(), [("write", *foreign), ("write", *Q)])
            self.assertEqual(evidence["trace"][-1]["outcome"], "duplicate:1")
            self.assertEqual(evidence["trace"][-1]["observation"]["C"], 0)
            self.assertEqual(evidence["producer_claims"][-1]["requesting_attempt"], "attempt-q")
            self.assertEqual(evidence["producer_claims"][-1]["requesting_executor"], "executor-a")
            self.assertEqual(evidence["physical_facts"]["commits"][0]["executor"], foreign[1])

    def test_generation_authority_and_current_predicate_are_separate(self):
        before = run_trace(Profile(), [("epoch",), ("write", *Q)])
        after = run_trace(Profile(), [("write", *Q), ("epoch",), ("mutate",)])
        self.assertEqual(before["trace"][-1]["observation"]["A"], 0)
        self.assertEqual(after["trace"][-1]["observation"]["A"], 1)
        self.assertEqual(after["trace"][-1]["observation"]["C"], 1)
        self.assertEqual(after["trace"][-1]["observation"]["P"], 0)

    def test_fixed_predicates_erase_expire_and_restore(self):
        mutable = run_trace(Profile(), [("write", *Q), ("mutate",), ("restore_target",)])
        self.assertEqual([r["observation"]["P"] for r in mutable["trace"]], [1, 0, 1])
        erased = run_trace(Profile("erasable"), [("write", *Q), ("erase",), ("write", *Q)])
        self.assertEqual(erased["trace"][-1]["observation"]["P"], 0)
        self.assertEqual(erased["trace"][-1]["observation"]["C"], 1)
        expiry = run_trace(Profile("expiring"), [("write", *Q), ("tick",), ("tick",), ("tick",)])
        self.assertEqual(expiry["trace"][-1]["observation"]["P"], 0)
        self.assertTrue(expiry["trace"][-1]["observation"]["evidence_facts"]["event_retained"])

    def test_all_scope_fields_are_checked(self):
        for field, wrong in (("subject", "other"), ("action", "other"), ("target", "other"), ("boundary", "other"), ("generation", 1)):
            with self.subTest(field=field):
                commands = [("rescope_grant", field, wrong), ("write", *Q)]
                unguarded = run_trace(Profile(), commands)
                guarded = run_trace(Profile("mutable", True), commands)
                self.assertEqual(unguarded["trace"][-1]["observation"]["A"], 0)
                self.assertIsNone(guarded["trace"][-1]["observation"])


class ExplorationTests(unittest.TestCase):
    def test_independent_bounded_native_replay_all_profiles(self):
        for profile in all_profiles():
            with self.subTest(profile=profile.name):
                evidence = explore_profile(profile, max_depth=3)
                self.assertGreater(evidence["native_transitions_compared_to_oracle"], 0)
                self.assertGreater(evidence["excluded_no_effect_states"], 0)
                self.assertEqual(evidence["fixed_contract_decision_disagreements"], [])
                for corner in evidence["reachable_committed_corners_discovered"]:
                    if profile.guard:
                        self.assertEqual(corner[0], "1")
                    if profile.sole_attempt:
                        self.assertEqual(corner[1], "1")
                    if profile.kind == "retained":
                        self.assertEqual(corner[2], "1")

    def test_projection_witnesses_and_all_boolean_functions(self):
        evidence = explore_profile(Profile(), max_depth=3)
        for omitted, analysis in evidence["coordinate_function_tests"].items():
            functions = analysis["all_total_boolean_functions"]
            self.assertEqual([f["mask"] for f in functions], list(range(16)))
            self.assertTrue(analysis["conflict_witnesses"])
            self.assertEqual(analysis["surviving_masks"], [])
            for witness in analysis["conflict_witnesses"]:
                first, second = witness["pair"]
                for retained in analysis["retained_coordinates"]:
                    self.assertEqual(first["observation"][retained], second["observation"][retained])
                self.assertNotEqual(first["observation"][omitted], second["observation"][omitted])
            self.assertTrue(all(f["counterexample"] is not None for f in functions))

    def test_candidate_counts_follow_observed_restricted_domain(self):
        evidence = explore_profile(Profile("retained", True, True), max_depth=3)
        for analysis in evidence["coordinate_function_tests"].values():
            conflicting = any(len(group["omitted_values"]) > 1 for group in analysis["projection_groups"])
            expected_count = 0 if conflicting else 2 ** (4 - len(analysis["projection_groups"]))
            self.assertEqual(len(analysis["surviving_masks"]), expected_count)

    def test_surrounding_failures_are_classified_before_new_axes(self):
        from focused import surrounding_obligation_probes
        evidence = surrounding_obligation_probes()
        for probe in evidence["explicit_envelope_probes"]:
            self.assertFalse(probe["comparable_within_fixed_contract"])
            self.assertFalse(probe["proposes_new_axis"])
            self.assertTrue(probe["baseline_fixed_contract_decision"])
            self.assertFalse(probe["decision_with_violated_obligation"])
            self.assertIn(probe["classification"], {"fixed-domain violation", "identity/cardinality ambiguity", "trust", "freshness", "history", "claim-policy dependency"})


if __name__ == "__main__":
    unittest.main()
