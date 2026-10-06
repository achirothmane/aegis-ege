#!/usr/bin/env python3
import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / 'scripts/verify_native_effect_boundary_profile.py'
SPEC = importlib.util.spec_from_file_location('native_boundary_verify', MODULE_PATH)
VERIFY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY)


class NativeEffectBoundaryProfileTest(unittest.TestCase):
    def profile(self):
        return json.loads(VERIFY.DEFAULT_PROFILE.read_text(encoding='utf-8'))

    def verify_modified(self, mutate):
        profile = copy.deepcopy(self.profile())
        mutate(profile)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / 'profile.json'
            path.write_text(json.dumps(profile), encoding='utf-8')
            return VERIFY.verify(path)

    def test_registered_profile_passes(self):
        result = VERIFY.verify()
        self.assertEqual(result['classification'], 'BOUNDED_GENERALIZATION_EVIDENCE')
        self.assertEqual(result['obligation_count'], 10)
        self.assertEqual(len(result['positive_realizations']), 2)
        self.assertEqual(len(result['negative_realizations']), 1)

    def test_missing_obligation_fails(self):
        with self.assertRaisesRegex(ValueError, 'obligation set changed'):
            self.verify_modified(lambda p: p['obligations'].pop())

    def test_split_lease_cannot_be_promoted(self):
        def mutate(profile):
            for item in profile['realizations']:
                if item['id'] == 'kubernetes-split-lease-counterexample-v1':
                    item['result'] = 'SURVIVES_V1'
        with self.assertRaisesRegex(ValueError, 'counterexample'):
            self.verify_modified(mutate)

    def test_registration_blob_drift_fails(self):
        def mutate(profile):
            profile['realizations'][0]['registration_blob'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'registration blob drift'):
            self.verify_modified(mutate)


if __name__ == '__main__':
    unittest.main()
