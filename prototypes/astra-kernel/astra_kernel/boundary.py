from __future__ import annotations

import dataclasses
import inspect
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Callable, Protocol

from .model import Destination, Observation, Proposal, StateWitness, byte_digest, digest


@dataclasses.dataclass(frozen=True)
class Profile:
    kind: str
    version: str
    admission_contract: str
    closure_contract: str
    consistency: str
    implementation_digest: str
    review_record: str = "local-experiment-2026-09-30"
    horizon_seconds: int = 30  # Local profile policy, never a universal kernel deadline.

    def __post_init__(self) -> None:
        for name in ("kind", "version", "admission_contract", "closure_contract", "consistency",
                     "implementation_digest", "review_record"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"missing trusted profile field: {name}")
        if type(self.horizon_seconds) is not int or self.horizon_seconds < 1:
            raise ValueError("a profile must define a positive finite observation horizon")

    @property
    def hash(self) -> str:
        return digest(self)


def implementation_digest(cls: type) -> str:
    # Pin local source bytes used in the reviewed pack, including the core boundary/model contract.
    package = Path(__file__).parent
    sources = [Path(inspect.getfile(cls))] + [package / name for name in
               ("__init__.py", "model.py", "boundary.py", "authority.py", "store.py", "kernel.py")]
    return digest([{"name": path.name, "sha256": byte_digest(path.read_bytes())} for path in sources])


class Session(Protocol):
    witness: StateWitness

    def apply(self, effect_id: str, attempt_id: str, admission_gate: Callable[[], None],
              fault: Callable[[str], None]) -> None: ...


class DomainPack(Protocol):
    profile: Profile

    def propose(self, requested: dict) -> dict: ...
    def destination(self, parameters: dict) -> Destination: ...
    def session(self, proposal: Proposal, clock: Callable[[], int]) -> AbstractContextManager[Session]: ...
    def observe(self, proposal: Proposal, attempt_id: str, now_ns: int) -> Observation: ...
