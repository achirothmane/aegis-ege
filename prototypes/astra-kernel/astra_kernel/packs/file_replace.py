from __future__ import annotations

import dataclasses
import fcntl
import os
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

from ..boundary import Profile, implementation_digest
from ..model import (Denied, Destination, Knowledge, Observation, Proposal, StateWitness,
                     byte_digest, exact)


@dataclasses.dataclass(frozen=True)
class FileChange:
    filename: str
    expected_sha256: str
    content_utf8: str

    @classmethod
    def parse(cls, data: dict) -> FileChange:
        exact(data, {"filename", "expected_sha256", "content_utf8"})
        if data["filename"] != "settings.txt":
            raise Denied("FILE_SCOPE", "only the deployment-owned settings.txt is writable")
        if type(data["content_utf8"]) is not str or len(data["content_utf8"].encode("utf-8")) > 4096:
            raise Denied("FILE_CONTENT_LIMIT")
        if type(data["expected_sha256"]) is not str or len(data["expected_sha256"]) != 64:
            raise Denied("INVALID_FILE_BINDING")
        return cls(**data)


def root_identity(path: Path) -> str:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        return f"dev:{info.st_dev}:ino:{info.st_ino}"
    finally:
        os.close(fd)


class FileReplace:
    def __init__(self, root: Path, expected_identity: str):
        self.root = root
        self.expected_identity = expected_identity
        self.profile = Profile(
            "file.replace", "1", "fixed-name; <=4096 UTF-8 bytes; unchanged old hash under cooperative lock",
            "desired content observed, staging absent; bounded postcondition, not causal attribution",
            "cooperating writers serialized by destination flock; OS owner/admin writes outside scope",
            implementation_digest(type(self)))

    @contextmanager
    def locked_root(self):
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        lock_fd = None
        try:
            info = os.fstat(fd)
            if f"dev:{info.st_dev}:ino:{info.st_ino}" != self.expected_identity:
                raise Denied("DESTINATION_CHANGED")
            lock_fd = os.open(".astra-writer.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise Denied("DESTINATION_BUSY", "no unbounded lock wait or implicit retry") from error
            yield fd
        finally:
            if lock_fd is not None:
                os.close(lock_fd)
            os.close(fd)

    @staticmethod
    def read(fd: int) -> bytes:
        file_fd = os.open("settings.txt", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            info = os.fstat(file_fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > 4096 or info.st_nlink != 1:
                raise Denied("UNSAFE_FILE_TARGET")
            content = os.read(file_fd, 4097)
            if len(content) > 4096:
                raise Denied("FILE_CONTENT_LIMIT")
            return content
        finally:
            os.close(file_fd)

    def propose(self, requested: dict) -> dict:
        exact(requested, {"filename", "content_utf8"})
        FileChange.parse({**requested, "expected_sha256": "0" * 64})
        with self.locked_root() as fd:
            before = self.read(fd)
        if before == requested["content_utf8"].encode("utf-8"):
            raise Denied("NO_CHANGE", "a pure no-op is not an effect in this profile")
        return {**requested, "expected_sha256": byte_digest(before)}

    def destination(self, parameters: dict) -> Destination:
        plan = FileChange.parse(parameters)
        return Destination("local-file", str(self.root), plan.filename, self.expected_identity)

    @contextmanager
    def session(self, proposal: Proposal, clock: Callable[[], int]):
        plan = FileChange.parse(proposal.parameters)
        with self.locked_root() as fd:
            before_hash = byte_digest(self.read(fd))
            if before_hash != plan.expected_sha256:
                raise Denied("STALE_STATE", "file content changed since preparation")
            now = clock()
            witness = StateWitness(self.destination(proposal.parameters), before_hash, now,
                                   now + 1_000_000_000, self.profile.consistency)
            yield FileSession(fd, plan, witness)

    def observe(self, proposal: Proposal, attempt_id: str, now_ns: int) -> Observation:
        plan = FileChange.parse(proposal.parameters)
        expected = byte_digest(plan.content_utf8.encode("utf-8"))
        knowledge = Knowledge.UNKNOWN
        details: dict = {"expected_content_sha256": expected, "attribution": "postcondition-only"}
        try:
            with self.locked_root() as fd:
                observed = byte_digest(self.read(fd))
                try:
                    os.stat(".astra-stage-" + proposal.effect.logical_id, dir_fd=fd, follow_symlinks=False)
                    stage_present = True
                except FileNotFoundError:
                    stage_present = False
                details.update(observed_content_sha256=observed, staging_present=stage_present)
                if stage_present:
                    knowledge, details["result"] = Knowledge.PARTIAL, "STAGING_REMAINS"
                elif observed == expected:
                    knowledge, details["result"] = Knowledge.VERIFIED, "DESIRED_CONTENT_OBSERVED"
                else:
                    details["result"] = "CONTENT_DIFFERS_EFFECT_UNCERTAIN"
        except (OSError, Denied) as error:
            details.update(result="OBSERVATION_UNAVAILABLE", error_type=type(error).__name__)
        return Observation(proposal.effect.logical_id, attempt_id, "local-file-observer-v1", now_ns,
                           knowledge, "file.replace.outcome.v1", details)


@dataclasses.dataclass
class FileSession:
    root_fd: int
    plan: FileChange
    witness: StateWitness

    def apply(self, effect_id: str, attempt_id: str, admission_gate: Callable[[], None],
              fault: Callable[[str], None]) -> None:
        # Re-read inside the same destination lock, immediately before mutation.
        if byte_digest(FileReplace.read(self.root_fd)) != self.plan.expected_sha256:
            raise Denied("STALE_STATE_AT_WRITE")
        stage = ".astra-stage-" + effect_id
        admission_gate()
        fd = os.open(stage, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.root_fd)
        try:
            content = self.plan.content_utf8.encode("utf-8")
            with os.fdopen(fd, "wb") as output:
                output.write(content)
                output.flush()
                os.fsync(output.fileno())
            os.fsync(self.root_fd)
            fault("file_after_stage_sync")
            os.replace(stage, self.plan.filename, src_dir_fd=self.root_fd, dst_dir_fd=self.root_fd)
            os.fsync(self.root_fd)
        except BaseException:
            # A process death bypasses this; the derived stage name remains owned by the obligation.
            try:
                os.unlink(stage, dir_fd=self.root_fd)
                os.fsync(self.root_fd)
            except FileNotFoundError:
                pass
            raise
