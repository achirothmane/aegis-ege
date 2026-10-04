"""Fourth-domain POSIX publish-only object store. Native I/O; fixture TCB.

The object IS the event. The trusted publish-only interface and durable
filesystem, not file chmod or a hash, carry permanent retention. An explicit
outside-interface deletion is the negative control. This is not hardware WORM.
"""

import json
import os
from pathlib import Path
import tempfile
import unittest


class PublishOnlyStore:
    def __init__(self, root):
        self.root = Path(root)

    def publish(self, effect, attempt):
        # Tests use fixed identities. No path supplied by an external caller.
        if effect != "event" or attempt not in ("claimed", "other"):
            raise ValueError("fixture identity")
        final = self.root / effect
        with tempfile.NamedTemporaryFile(dir=self.root, delete=False) as pending:
            temporary = Path(pending.name)
            pending.write(json.dumps({"effect": effect, "attempt": attempt}).encode())
            pending.flush()
            os.fsync(pending.fileno())
        try:
            os.link(temporary, final)  # Atomic no-replace publication.
            directory = os.open(self.root, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return True
        except FileExistsError:
            return False
        finally:
            temporary.unlink()


class NativeLedgerProjection(unittest.TestCase):
    def test_commit_loss_reopen_and_unique_effect_do_not_transfer_cause(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertTrue(PublishOnlyStore(root).publish("event", "other"))
            # Discard the publisher and its result, retain no caller receipt.
            self.assertFalse(PublishOnlyStore(root).publish("event", "claimed"))
            data = json.loads((Path(root) / "event").read_bytes())
            self.assertEqual(data["attempt"], "other")
            self.assertEqual(len(list(Path(root).iterdir())), 1)

    def test_cause_discharges_permanent_existence_only_under_retention(self):
        with tempfile.TemporaryDirectory() as root:
            store = PublishOnlyStore(root)
            self.assertTrue(store.publish("event", "claimed"))
            historical = (Path(root) / "event").read_bytes()
            self.assertTrue((Path(root) / "event").exists())
            # Remove the explicitly declared publish-only boundary assumption.
            (Path(root) / "event").unlink()
            self.assertEqual(json.loads(historical)["attempt"], "claimed")
            self.assertFalse((Path(root) / "event").exists())

    def test_immutable_event_is_not_immutable_temporal_validity(self):
        with tempfile.TemporaryDirectory() as root:
            store = PublishOnlyStore(root)
            self.assertTrue(store.publish("event", "claimed"))
            path = Path(root) / "event"
            before = path.read_bytes()
            # The relying party selects this fixed predicate before evaluation.
            valid_until = 2
            required_truth = lambda now: path.exists() and now < valid_until
            self.assertTrue(required_truth(1))
            self.assertFalse(required_truth(2))
            self.assertEqual(before, path.read_bytes())


if __name__ == "__main__":
    unittest.main()
