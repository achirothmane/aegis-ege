from __future__ import annotations

import base64
import dataclasses
import time
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .model import Denied, Proposal, canonical, exact, integer, primitive, text


@dataclasses.dataclass(frozen=True)
class Grant:
    version: int
    grant_id: str
    purpose: str
    store_id: str
    action_key: str
    action_revision: str
    tenant: str
    principal: str
    effect_id: str
    destination_digest: str
    profile_hash: str
    not_before_ns: int
    expires_ns: int
    custodian: str = ""
    reason: str = ""


@dataclasses.dataclass(frozen=True)
class Signed:
    payload: dict
    signature: str

    @classmethod
    def parse(cls, data: dict) -> Signed:
        exact(data, {"payload", "signature"})
        if type(data["payload"]) is not dict:
            raise Denied("INVALID_SIGNATURE_ENVELOPE")
        return cls(data["payload"], text(data["signature"], 200))


class OwnerAuthority:
    """Owner-side signer. The Kernel receives only the public verifier, never this object."""

    def __init__(self, key: Ed25519PrivateKey):
        self._key = key

    @classmethod
    def generate(cls) -> OwnerAuthority:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def load(cls, path: Path) -> OwnerAuthority:
        import os
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            if os.fstat(fd).st_mode & 0o077:
                raise Denied("UNSAFE_OWNER_KEY_PERMISSIONS")
            return cls(Ed25519PrivateKey.from_private_bytes(os.read(fd, 33)))
        finally:
            os.close(fd)

    def public_bytes(self) -> bytes:
        return self._key.public_key().public_bytes_raw()

    def private_bytes(self) -> bytes:
        return self._key.private_bytes_raw()

    def sign(self, payload: dict) -> Signed:
        return Signed(payload, base64.b64encode(self._key.sign(canonical(payload))).decode("ascii"))

    def issue(self, proposal: Proposal, *, purpose: str = "execute", ttl_seconds: int = 60,
              now_ns: int | None = None, custodian: str = "", reason: str = "") -> Signed:
        from .model import digest
        integer(ttl_seconds, 1)
        if ttl_seconds > 300 or purpose not in {"execute", "retire_unknown"}:
            raise Denied("INVALID_GRANT_LIMIT")
        proposal.validate_binding()
        now = time.time_ns() if now_ns is None else integer(now_ns, 1)
        grant = Grant(1, str(uuid.uuid4()), purpose, proposal.store_id, proposal.ref.key,
                      proposal.ref.revision, proposal.actor.tenant, proposal.actor.principal,
                      proposal.effect.logical_id, digest(proposal.effect.destination),
                      proposal.profile_hash, now, now + ttl_seconds * 1_000_000_000,
                      custodian, reason)
        return self.sign(primitive(grant))

    def revoke(self, store_id: str, grant_id: str, reason: str) -> Signed:
        return self.sign({"version": 1, "purpose": "revoke", "store_id": store_id,
                          "grant_id": text(grant_id), "reason": text(reason, 1000)})


class Verifier:
    def __init__(self, public_key: bytes):
        self._key = Ed25519PublicKey.from_public_bytes(public_key)

    def payload(self, signed: Signed) -> dict:
        try:
            signature = base64.b64decode(signed.signature, validate=True)
            self._key.verify(signature, canonical(signed.payload))
        except (InvalidSignature, ValueError, TypeError) as error:
            raise Denied("BAD_SIGNATURE") from error
        return signed.payload

    def grant(self, signed: Signed) -> Grant:
        payload = self.payload(signed)
        exact(payload, {f.name for f in dataclasses.fields(Grant)})
        grant = Grant(**payload)
        if type(grant.version) is not int or grant.version != 1:
            raise Denied("AUTHORITY_VERSION")
        integer(grant.not_before_ns, 1)
        integer(grant.expires_ns, 1)
        if not grant.not_before_ns < grant.expires_ns <= grant.not_before_ns + 300_000_000_000:
            raise Denied("INVALID_AUTHORITY_INTERVAL")
        return grant
