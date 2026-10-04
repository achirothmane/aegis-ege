import unittest
from copy import deepcopy

from verify_kernel_shrink import production_size, verify_fixture_demotion, verify_reduction


class ReductionTreeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {"boundary.go": ("100644", "blob", "core")}
        self.current = dict(self.baseline)
        self.blobs = {}
        self.replacements = []
        for path in ("runtime/runtime.go", "runtime/recovery.go", "runtime/fenced.go"):
            old, new = path + "-old", path + "-new"
            self.baseline[path] = ("100644", "blob", old)
            self.current[path] = ("100644", "blob", new)
            self.blobs[old] = b"package runtime\n\nfunc Run() {\n duplicated(); duplicated()\n}\n"
            self.blobs[new] = b"package runtime\nfunc Run() {\n once()\n}\n"
            self.replacements.append({"path": path, "baseline_blob": old, "reduced_blob": new})

    def check(self):
        return verify_reduction(self.baseline, self.current, self.replacements, self.blobs.__getitem__)

    def test_exact_registered_reduction_passes(self):
        self.assertLess(self.check()["source_bytes_after"], self.check()["source_bytes_before"])

    def test_unregistered_change_addition_deletion_and_mode_change_fail(self):
        for current in (dict(self.current, **{"boundary.go": ("100644", "blob", "changed")}),
                        dict(self.current, extra=("100644", "blob", "added")),
                        {p: v for p, v in self.current.items() if p != "boundary.go"},
                        dict(self.current, **{"runtime/runtime.go": ("100755", "blob", "runtime/runtime.go-new")})):
            with self.subTest(current=current), self.assertRaises(ValueError):
                verify_reduction(self.baseline, current, self.replacements, self.blobs.__getitem__)

    def test_core_cannot_be_reclassified_as_runtime_reduction(self):
        self.replacements.append({"path": "boundary.go", "baseline_blob": "core", "reduced_blob": "changed"})
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_or_missing_registration_fails(self):
        for items in (self.replacements + self.replacements[:1], self.replacements[1:]):
            with self.subTest(items=items), self.assertRaises(ValueError):
                verify_reduction(self.baseline, self.current, items, self.blobs.__getitem__)

    def test_baseline_repin_and_registered_source_mutation_fail(self):
        for field in ("baseline_blob", "reduced_blob"):
            original = self.replacements[0][field]
            self.replacements[0][field] = "different"
            self.blobs["different"] = self.blobs[original]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.check()
            self.replacements[0][field] = original

    def test_new_public_object_or_dependency_fails(self):
        path = "runtime/runtime.go-new"
        original = self.blobs[path]
        for addition in (b"type Authority struct {}\n", b'import "external/policy"\n'):
            self.blobs[path] = original + addition
            with self.subTest(addition=addition), self.assertRaises(ValueError):
                self.check()
        self.blobs[path] = original

    def test_growth_disguised_as_reduction_fails(self):
        for path in list(self.blobs):
            if path.endswith("-new"):
                self.blobs[path] += b"// relocated hidden complexity\n" * 10
        with self.assertRaises(ValueError):
            self.check()

    def test_existing_public_record_cannot_gain_an_independent_field(self):
        from verify_kernel_shrink import surface
        before = b"package runtime\ntype Request struct {\n Subject string\n}\n"
        after = b"package runtime\ntype Request struct {\n Subject string\n Authority string\n}\n"
        self.assertNotEqual(surface(before), surface(after))

    def test_gofmt_columns_do_not_change_the_record_surface(self):
        from verify_kernel_shrink import surface
        before = b"package runtime\ntype Request struct {\n Subject     string\n}\n"
        after = b"package runtime\ntype Request struct {\n\tSubject string\n}\n"
        self.assertEqual(surface(before), surface(after))


class FixtureDemotionVerificationTests(unittest.TestCase):
    def setUp(self):
        self.blobs = {
            "model": b"package taintflow\nfunc New() {\n keepAllLabels()\n}\n",
            "checks": b"package taintflow\nfunc TestPropagation() {\n tracker := New()\n assertAllLabels(tracker)\n}\n",
            "caller": b'package governedaction_test\nimport (\n\t"github.com/achirothmane/aegis-ege/governedaction/taintflow"\n)\nfunc corpus() { taintflow.New(); assertOriginalCorpus() }\n',
            "readme": b"Historical model scope.\n",
        }
        self.tree = {path: ("100644", "blob", blob) for path, blob in
                     (("taintflow/tracker.go", "model"), ("taintflow/tracker_test.go", "checks"),
                      ("origin_corpus_test.go", "caller"), ("README.md", "readme"))}
        self.blobs["model-test"] = self.blobs["model"].replace(b"package taintflow", b"package governedaction_test").replace(b"func New(", b"func newTaintTracker(")
        self.blobs["checks-test"] = self.blobs["checks"].replace(b"package taintflow", b"package governedaction_test").replace(b" := New(", b" := newTaintTracker(")
        self.blobs["caller-new"] = self.blobs["caller"].replace(b'\t"github.com/achirothmane/aegis-ege/governedaction/taintflow"\n', b"").replace(b"taintflow.New(", b"newTaintTracker(")
        self.blobs["readme-new"] = self.blobs["readme"] + b"Now test-only.\n"
        self.data = {"schema_version": "aegis.kernel-fixture-demotion/v1", "moves": [
            {"baseline_path": "taintflow/tracker.go", "baseline_blob": "model", "test_only_path": "taint_fixture_test.go", "test_only_blob": "model-test"},
            {"baseline_path": "taintflow/tracker_test.go", "baseline_blob": "checks", "test_only_path": "taint_fixture_checks_test.go", "test_only_blob": "checks-test"}],
            "corpus_caller": {"path": "origin_corpus_test.go", "baseline_blob": "caller", "current_blob": "caller-new"},
            "documentation": {"path": "README.md", "baseline_blob": "readme", "current_blob": "readme-new"}}
        self.expected = {"taint_fixture_test.go": ("100644", "blob", "model-test"),
                         "taint_fixture_checks_test.go": ("100644", "blob", "checks-test"),
                         "origin_corpus_test.go": ("100644", "blob", "caller-new"), "README.md": ("100644", "blob", "readme-new")}
        self.data["production_measurements"] = {"before": production_size(self.tree, self.blobs.__getitem__),
                                                "after": production_size(self.expected, self.blobs.__getitem__)}

    def check(self, data=None):
        return verify_fixture_demotion(self.tree, data or self.data, self.blobs.__getitem__)

    def test_only_exact_model_and_test_moves_pass(self):
        self.assertEqual(self.check(), self.expected)
        self.assertEqual(self.data["production_measurements"]["after"]["files"], 0)

    def test_model_or_original_test_edit_fails_even_when_registered(self):
        for key in ("model-test", "checks-test"):
            raw = self.blobs[key]
            self.blobs[key] = raw + b"// changed fixture\n"
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.check()
            self.blobs[key] = raw

    def test_production_destination_unknown_move_and_missing_tests_fail(self):
        for change in ("production", "unknown", "missing"):
            data = deepcopy(self.data)
            if change == "production":
                data["moves"][0]["test_only_path"] = "taint_fixture.go"
            elif change == "unknown":
                data["moves"][0]["baseline_path"] = "taint.go"
            else:
                data["moves"].pop()
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(data)

    def test_corpus_assertions_cannot_be_rewritten(self):
        self.blobs["caller-new"] = self.blobs["caller-new"].replace(b"assertOriginalCorpus()", b"acceptEverything()")
        with self.assertRaises(ValueError):
            self.check()

    def test_historical_documentation_cannot_be_replaced(self):
        self.blobs["readme-new"] = b"New scope replaces old evidence.\n"
        with self.assertRaises(ValueError):
            self.check()

    def test_baseline_repin_and_false_measurement_fail(self):
        for change in ("baseline", "measurement"):
            data = deepcopy(self.data)
            if change == "baseline":
                data["moves"][0]["baseline_blob"] = "checks"
            else:
                data["production_measurements"]["after"]["files"] = 1
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(data)


if __name__ == "__main__":
    unittest.main()
