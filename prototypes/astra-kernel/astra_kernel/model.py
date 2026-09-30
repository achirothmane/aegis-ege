from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import re
from typing import Any


class Denied(Exception):
    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}" if detail else code)


class CorruptStore(Exception):
    pass


class Busy(Exception):
    pass


class Knowledge(str, enum.Enum):
    UNKNOWN = "UNKNOWN"
    VERIFIED = "VERIFIED"
    NOT_APPLIED = "NOT_APPLIED"
    PARTIAL = "PARTIAL"


class Disposition(str, enum.Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    RETIRED_UNKNOWN = "RETIRED_UNKNOWN"


def primitive(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {f.name: primitive(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, enum.Enum):
        return value.value
    if type(value) in (str, int, bool) or value is None:
        return value
    if isinstance(value, (tuple, list)):
        return [primitive(x) for x in value]
    if type(value) is dict and all(type(k) is str for k in value):
        return {k: primitive(v) for k, v in value.items()}
    raise ValueError(f"unsupported canonical value: {type(value).__name__}")


def canonical(value: Any) -> bytes:
    # This prototype's own versioned encoding, not a universal JSON canonicalization claim.
    return json.dumps(primitive(value), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def byte_digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def loads(data: str | bytes) -> Any:
    def pairs(values: list[tuple[str, Any]]) -> dict:
        result: dict[str, Any] = {}
        for k, v in values:
            if k in result:
                raise ValueError(f"duplicate JSON key: {k}")
            result[k] = v
        return result

    def invalid_number(value: str) -> None:
        raise ValueError(f"unsupported JSON number: {value}")

    result = json.loads(data, object_pairs_hook=pairs, parse_float=invalid_number,
                        parse_constant=invalid_number)
    canonical(result)
    return result


def exact(data: dict, keys: set[str]) -> None:
    if type(data) is not dict or set(data) != keys:
        raise Denied("INVALID_RECORD", "missing or unknown fields")


def text(value: Any, maximum: int = 200) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > maximum:
        raise Denied("INVALID_TEXT")
    return value


def integer(value: Any, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        raise Denied("INVALID_INTEGER")
    return value


def identifier(value: Any) -> str:
    value = text(value, 96)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,95}", value):
        raise Denied("INVALID_IDENTIFIER")
    return value


@dataclasses.dataclass(frozen=True)
class Actor:
    tenant: str
    principal: str


@dataclasses.dataclass(frozen=True)
class ActionRef:
    tenant: str
    identity: str
    revision: str

    @property
    def key(self) -> str:
        return digest(self)


@dataclasses.dataclass(frozen=True)
class Destination:
    kind: str
    account: str
    resource: str
    identity: str


@dataclasses.dataclass(frozen=True)
class EffectIdentity:
    logical_id: str
    destination: Destination


@dataclasses.dataclass(frozen=True)
class Proposal:
    store_id: str
    ref: ActionRef
    actor: Actor
    kind: str
    profile_hash: str
    effect: EffectIdentity
    parameters: dict
    prepared_ns: int

    @classmethod
    def parse(cls, data: dict) -> Proposal:
        exact(data, {f.name for f in dataclasses.fields(cls)})
        exact(data["ref"], {"tenant", "identity", "revision"})
        exact(data["actor"], {"tenant", "principal"})
        exact(data["effect"], {"logical_id", "destination"})
        exact(data["effect"]["destination"], {"kind", "account", "resource", "identity"})
        return cls(data["store_id"], ActionRef(**data["ref"]), Actor(**data["actor"]),
                   data["kind"], data["profile_hash"],
                   EffectIdentity(data["effect"]["logical_id"],
                                  Destination(**data["effect"]["destination"])),
                   data["parameters"], data["prepared_ns"])

    def revision_body(self) -> dict:
        body = primitive(self)
        body["ref"].pop("revision")
        return body

    def validate_binding(self) -> None:
        if self.ref.tenant != self.actor.tenant or self.ref.revision != digest(self.revision_body()):
            raise Denied("REVISION_INTEGRITY")


@dataclasses.dataclass(frozen=True)
class StateWitness:
    subject: Destination
    observed_digest: str
    observed_ns: int
    valid_until_ns: int
    consistency: str


@dataclasses.dataclass(frozen=True)
class DecisionBasis:
    action: ActionRef
    effect: EffectIdentity
    profile_hash: str
    authority_grant_id: str
    authority_digest: str
    state: StateWitness
    admitted_ns: int
    actor: Actor


@dataclasses.dataclass(frozen=True)
class ExecutionAttempt:
    attempt_id: str
    action: ActionRef
    effect: EffectIdentity
    basis: DecisionBasis
    boundary: str


@dataclasses.dataclass(frozen=True)
class Observation:
    # Projection plus a domain-validated payload, not a universal outcome ontology.
    effect_id: str
    attempt_id: str
    observer: str
    observed_ns: int
    knowledge: Knowledge
    domain_type: str
    domain_payload: dict


@dataclasses.dataclass(frozen=True)
class ClosureObligation:
    effect_id: str
    attempt_id: str
    action_key: str
    profile_hash: str
    custodian: Actor
    horizon_ns: int
    knowledge: Knowledge = Knowledge.UNKNOWN
    disposition: Disposition = Disposition.OPEN
    observation: Observation | None = None
    retirement_reason: str = ""


def local_actor(tenant: str = "local-demo") -> Actor:
    import os
    return Actor(tenant, f"uid:{os.getuid()}")
