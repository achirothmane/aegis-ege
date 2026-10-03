import unittest

from verify_kernel_shrink import verify_reduction


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


if __name__ == "__main__":
    unittest.main()
