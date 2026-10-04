"""Child process deliberately exits after native COMMIT and before any acknowledgement."""
import os
import sys

from sqlite_model import Profile, Store


store = Store(Profile("mutable", True, False), path=sys.argv[1], initialize=False)
if len(sys.argv) > 2 and sys.argv[2] == "before-commit":
    store.apply(("write", "attempt-q", "executor-a"), ack=False, precommit=lambda: os._exit(74))
else:
    store.apply(("write", "attempt-q", "executor-a"), ack=False)
# No orderly Python/SQLite close and no user-visible success acknowledgement.
os._exit(73)
