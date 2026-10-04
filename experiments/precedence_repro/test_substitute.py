"""Representative known-mechanism replacement controls, without Aegis imports."""
from dataclasses import replace
import copy
import unittest

from substitute import (Destination, Question, independently_check,
                        fixture_bundle, sign, signing_key, trial)


class SubstituteChecks(unittest.TestCase):
    def test_positive_retained_separators(self):
        outcomes = trial()
        self.assertEqual({tuple(x["truth"]) for x in outcomes.values()},
                         {(0, 1, 1), (1, 0, 1), (1, 1, 0), (1, 1, 1)})
        for result in outcomes.values():
            self.assertEqual(result["consumer"]["closure"] == "CLOSED",
                             result["truth"] == [1, 1, 1])

    def test_atomic_scope_validation_rejects_stale_authority(self):
        for stale in ("revoke", "advance_generation"):
            d = Destination(fenced=True)
            getattr(d, stale)()
            self.assertEqual(d.commit(Question())[0], "DENIED_AUTHORITY")
            self.assertEqual(d.db.execute("SELECT count(*) FROM business").fetchone()[0], 0)
            d.db.close()

    def test_sole_attempt_excludes_other_executor_with_same_attempt(self):
        d, q = Destination(sole_origin=True), Question()
        self.assertEqual(d.commit(q, q.attempt, "worker-2")[0], "DENIED_ORIGIN")
        self.assertEqual(d.commit(q)[0], "COMMITTED")
        d.db.close()

    def test_permanent_exists_versus_expiring_validity(self):
        q = Question()
        for expires in (False, True):
            d = Destination(immutable=True, expiring=expires)
            d.commit(q)
            self.assertTrue(d.observe(q, 1)["predicate"])
            self.assertEqual(d.observe(q, 2)["predicate"], not expires)
            d.erase_outside_boundary()
            self.assertFalse(d.observe(q, 2)["predicate"])
            self.assertEqual(len(d.history()), 1)
            d.db.close()

    def test_dedup_result_preserves_first_actual_writer(self):
        d, q = Destination(), Question()
        d.commit(q, "request-2", "worker-2")
        status, row = d.commit(q)
        self.assertEqual(status, "REPLAY")
        self.assertEqual(row["executor"], "worker-2")
        self.assertEqual(d.db.execute("SELECT count(*) FROM business").fetchone()[0], 1)
        self.assertEqual(independently_check(q, *fixture_bundle(d, q))["closure"], "UNKNOWN")
        d.db.close()

    def test_policy_and_roots_are_consumer_inputs(self):
        d, q = Destination(), Question()
        d.commit(q, "request-2", "worker-2")
        args = list(fixture_bundle(d, q))
        self.assertEqual(independently_check(q, *args)["closure"], "UNKNOWN")
        self.assertEqual(independently_check(replace(q, claim_type="POSTCONDITION"), *args)["closure"], "CLOSED")
        args[1] = signing_key("untrusted").public_key()
        self.assertEqual(independently_check(q, *args)["reason"], "observation-root")
        d.db.close()

    def test_authentic_snapshot_does_not_follow_later_world(self):
        d, q = Destination(), Question()
        d.commit(q)
        old = fixture_bundle(d, q)
        d.mutate()
        self.assertEqual(independently_check(q, *old)["closure"], "CLOSED")
        self.assertEqual(independently_check(q, *fixture_bundle(d, q))["closure"], "UNKNOWN")
        changed_time = list(old)
        changed_time[-1] = 2
        self.assertEqual(independently_check(q, *changed_time)["closure"], "UNKNOWN")
        d.db.close()

    def test_authenticated_history_is_separate_from_closure(self):
        d, q = Destination(), Question()
        d.commit(q)
        args = list(fixture_bundle(d, q))
        self.assertEqual(independently_check(q, *args)["history"], "TRUSTED")
        # A forged or unprovisioned custodian cannot adopt the trusted head.
        args[3] = sign(args[3]["body"], signing_key("unapproved-successor"))
        report = independently_check(q, *args)
        self.assertEqual((report["closure"], report["history"]), ("CLOSED", "UNTRUSTED"))
        tampered = list(fixture_bundle(d, q))
        tampered[2] = copy.deepcopy(tampered[2])
        tampered[2][0]["body"]["row"]["executor"] = "falsified"
        self.assertEqual(independently_check(q, *tampered)["reason"], "history-chain")
        d.db.close()


if __name__ == "__main__":
    unittest.main()
