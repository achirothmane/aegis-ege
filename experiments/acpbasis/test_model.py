import unittest

from model import PROFILES, Profile, coordinates, explore, summarize


class BoundedNonDerivability(unittest.TestCase):
    def test_reachable_cube_and_all_sixteen_function_candidates(self):
        result = summarize(PROFILES["mutable-open-boundary"])
        self.assertEqual(set(result["cube"]), {format(i, "03b") for i in range(8)})
        for name in "ACP":
            self.assertEqual(result["functions"][name], [])
            self.assertIsNotNone(result["separating_pairs"][name])

    def test_atomic_authority_fence_is_substrate_discharge(self):
        result = summarize(PROFILES["mutable-atomic-fence"])
        self.assertEqual(set(result["cube"]), {"100", "101", "110", "111"})
        self.assertEqual(result["functions"]["A"], [[1, 1, 1, 1]])
        self.assertEqual(result["functions"]["C"], [])
        self.assertEqual(result["functions"]["P"], [])

    def test_sole_origin_is_not_single_writer_process(self):
        result = summarize(PROFILES["mutable-sole-origin"])
        self.assertEqual(set(result["cube"]), {"010", "011", "110", "111"})
        self.assertEqual(result["functions"]["C"], [[1, 1, 1, 1]])
        self.assertEqual(result["functions"]["A"], [])
        self.assertEqual(result["functions"]["P"], [])

    def test_immutable_existence_profile_and_assumption_removal(self):
        profile = PROFILES["immutable-event"]
        self.assertEqual(set(summarize(profile)["cube"]), {"001", "011", "101", "111"})
        self.assertEqual(summarize(profile)["functions"]["P"], [[1, 1, 1, 1]])
        for removed in (PROFILES["immutable-event-erasure-enabled"],
                        PROFILES["immutable-expiring-predicate"]):
            rows = [coordinates(s, removed) for s in explore(removed) if s.cause]
            self.assertIn((1, 1, 0), rows)
            self.assertEqual(summarize(removed)["functions"]["P"], [])

    def test_strongest_composed_profile_has_only_one_committed_corner(self):
        result = summarize(PROFILES["immutable-fenced-sole-origin"])
        self.assertEqual(set(result["cube"]), {"111"})

    def test_no_effect_has_no_commit_authority_truth_coordinate(self):
        for state in explore(Profile()):
            if not state.cause:
                self.assertIsNone(coordinates(state, Profile()))


if __name__ == "__main__":
    unittest.main()
