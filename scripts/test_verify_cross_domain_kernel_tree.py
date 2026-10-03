import unittest

from verify_cross_domain_kernel_tree import verify


class FrozenTreeVerificationTests(unittest.TestCase):
    def setUp(self):
        self.frozen = {
            "boundary.go": ("100644", "blob", "core"),
            "runtime/runtime.go": ("100644", "blob", "runtime"),
            "runtime/README.md": ("100644", "blob", "old-doc"),
        }
        self.extension = [
            {"path": "runtime/fenced.go", "mode": "100644",
             "frozen_blob": None, "current_blob": "fenced"},
            {"path": "runtime/README.md", "mode": "100644",
             "frozen_blob": "old-doc", "current_blob": "new-doc"},
        ]
        self.current = dict(self.frozen)
        self.current["runtime/fenced.go"] = ("100644", "blob", "fenced")
        self.current["runtime/README.md"] = ("100644", "blob", "new-doc")
        self.blobs = {"old-doc": b"frozen documentation\n",
                      "new-doc": b"frozen documentation\nappendix\n"}

    def check(self):
        verify(self.frozen, self.current, self.extension, self.blobs.__getitem__)

    def test_exact_registered_extension_passes(self):
        self.check()

    def test_frozen_core_and_existing_runtime_changes_fail(self):
        for path in ("boundary.go", "runtime/runtime.go"):
            with self.subTest(path=path):
                saved = self.current[path]
                self.current[path] = ("100644", "blob", "changed")
                with self.assertRaises(ValueError):
                    self.check()
                self.current[path] = saved

    def test_deletion_unregistered_addition_and_mode_change_fail(self):
        for changed in ({k: v for k, v in self.current.items() if k != "boundary.go"},
                        dict(self.current, unexpected=("100644", "blob", "new")),
                        dict(self.current, **{"boundary.go": ("100755", "blob", "core")})):
            with self.subTest(tree=changed):
                with self.assertRaises(ValueError):
                    verify(self.frozen, changed, self.extension, self.blobs.__getitem__)

    def test_registered_extension_mutation_fails(self):
        self.current["runtime/fenced.go"] = ("100644", "blob", "changed")
        with self.assertRaises(ValueError):
            self.check()

    def test_frozen_file_cannot_be_registered_as_extension(self):
        self.extension.append({"path": "boundary.go", "mode": "100644",
                               "frozen_blob": "core", "current_blob": "changed"})
        with self.assertRaises(ValueError):
            self.check()

    def test_documentation_rewrite_fails(self):
        self.blobs["new-doc"] = b"replacement documentation\n"
        with self.assertRaises(ValueError):
            self.check()

    def test_duplicate_registration_fails(self):
        self.extension.append(self.extension[0])
        with self.assertRaises(ValueError):
            self.check()

    def test_no_extension_requires_exact_frozen_tree(self):
        verify(self.frozen, self.frozen, [], self.blobs.__getitem__)
        with self.assertRaises(ValueError):
            verify(self.frozen, self.current, [], self.blobs.__getitem__)


if __name__ == "__main__":
    unittest.main()
