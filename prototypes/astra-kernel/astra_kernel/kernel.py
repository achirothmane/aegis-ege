from __future__ import annotations

import base64
import copy
import os
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Callable

from .authority import OwnerAuthority, Signed, Verifier
from .model import (Actor, ActionRef, ClosureObligation, DecisionBasis, Denied, EffectIdentity,
                    ExecutionAttempt, Knowledge, Observation, Proposal, canonical, digest,
                    exact, identifier, integer, local_actor, loads, primitive, text)
from .packs.file_replace import FileReplace, root_identity
from .packs.sqlite_migration import SQLiteMigration, database_identity
from .store import Journal


def write_private(path: Path, content: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as file:
        file.write(content)
        file.flush()
        os.fsync(file.fileno())
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def initialize(home: Path) -> dict:
    """Create a NEW isolated fixture only. Never attach arbitrary production files or databases."""
    home = home.absolute()
    home.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name in ("state", "owner", "files", "database"):
        (home / name).mkdir(mode=0o700)
    owner = OwnerAuthority.generate()
    write_private(home / "owner" / "issuer.key", owner.private_bytes())
    write_private(home / "files" / "settings.txt", b"mode=initial\n")
    db = home / "database" / "people.sqlite"
    fd = os.open(db, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fd)
    with sqlite3.connect(db) as conn:
        conn.execute("PRAGMA synchronous=EXTRA")
        conn.execute("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT NOT NULL)")
        conn.executemany("INSERT INTO people VALUES (?,?)", [(1, "Example A"), (2, "Example B")])
        conn.execute("CREATE TABLE astra_effects (effect_id TEXT PRIMARY KEY, attempt_id TEXT NOT NULL, revision TEXT NOT NULL)")
        conn.execute("CREATE TABLE astra_metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute("INSERT INTO astra_metadata VALUES ('namespace',?)", (str(uuid.uuid4()),))
    actor = local_actor()
    config = {"version": 1, "store_id": str(uuid.uuid4()), "tenant": actor.tenant,
              "principal": actor.principal, "public_key": base64.b64encode(owner.public_bytes()).decode("ascii"),
              "file_root": str(home / "files"), "file_identity": root_identity(home / "files"),
              "database_path": str(db), "database_identity": database_identity(db)}
    write_private(home / "state" / "config.json", canonical(config))
    journal = Journal(home / "state", config["store_id"], digest(config), create=True)
    journal.close()
    return {"home": str(home), "state": str(home / "state"), "actor": primitive(actor),
            "authority": "owner-only local signing key; runtime interface receives public key only"}


class Kernel:
    """Submit / execute / observe / retire / inspect: bounded local effect syscalls.

    Trusted application supplies Actor; the CLI derives it from the OS UID.
    No general shell, SQL, transport, arbitrary plugin or retry syscall exists.
    """

    def __init__(self, home: Path, *, clock: Callable[[], int] = time.time_ns,
                 fault: Callable[[str], None] | None = None):
        home = home.absolute()
        self.home, self.clock = home, clock
        self._closed = False
        self.fault = fault or (lambda point: None)
        config = loads((home / "state" / "config.json").read_bytes())
        exact(config, {"version", "store_id", "tenant", "principal", "public_key", "file_root",
                       "file_identity", "database_path", "database_identity"})
        if type(config["version"]) is not int or config["version"] != 1:
            raise Denied("CONFIGURATION_VERSION")
        self.config = config
        self.actor = Actor(config["tenant"], config["principal"])
        self.verifier = Verifier(base64.b64decode(config["public_key"], validate=True))
        self.packs = {"file.replace": FileReplace(Path(config["file_root"]), config["file_identity"]),
                      "sqlite.add-column": SQLiteMigration(Path(config["database_path"]), config["database_identity"])}
        self.journal = Journal(home / "state", config["store_id"], digest(config), verifier=self.verifier)

    def __enter__(self) -> Kernel:
        return self

    def __exit__(self, *args) -> None:
        self.close()

    def close(self) -> None:
        self.journal.close()
        self._closed = True

    def _actor(self, actor: Actor) -> None:
        if self._closed:
            raise Denied("RUNTIME_CLOSED", "a released runtime cannot resume mutation")
        if actor != self.actor:
            raise Denied("ACTOR_SCOPE", "local deployment principal and tenant must match")

    def _now(self) -> int:
        now = integer(self.clock(), 1)
        if now < self.journal.state["last_clock_ns"]:
            raise Denied("CLOCK_REGRESSION", "fix the clock; no silent reset or expiry bypass")
        self.journal.append("CLOCK", {"now_ns": now})
        return now

    def _pack(self, proposal: Proposal):
        pack = self.packs.get(proposal.kind)
        if pack is None or proposal.profile_hash != pack.profile.hash:
            raise Denied("TRUSTED_PROFILE_CHANGED")
        if proposal.effect.destination != pack.destination(proposal.parameters):
            raise Denied("DESTINATION_BINDING")
        return pack

    def propose(self, actor: Actor, identity: str, kind: str, requested: dict) -> Proposal:
        self._actor(actor)
        self.journal.verify()
        identity = identifier(identity)
        if kind not in self.packs:
            raise Denied("UNTRUSTED_ACTION_KIND", "profiles are selected by reviewed deployment code")
        pack = self.packs[kind]
        parameters = pack.propose(copy.deepcopy(requested))
        destination = pack.destination(parameters)
        now = self._now()
        effect_id = digest({"store_id": self.config["store_id"], "tenant": actor.tenant, "action_id": identity})
        if effect_id in self.journal.state["attempts"]:
            raise Denied("EFFECT_ALREADY_ADMITTED", "a new revision cannot authorize replay or provider substitution")
        proposal = Proposal(self.config["store_id"], ActionRef(actor.tenant, identity, ""), actor,
                            kind, pack.profile.hash, EffectIdentity(effect_id, destination), parameters, now)
        proposal = Proposal(**{**proposal.__dict__, "ref": ActionRef(actor.tenant, identity, digest(proposal.revision_body()))})
        self.journal.append("ACTION", primitive(proposal))
        return proposal

    def action(self, key: str) -> Proposal:
        body = self.journal.state["actions"].get(key)
        if body is None:
            raise Denied("UNKNOWN_ACTION_REVISION")
        proposal = Proposal.parse(copy.deepcopy(body))
        proposal.validate_binding()
        return proposal

    def _grant(self, actor: Actor, proposal: Proposal, signed: Signed, purpose: str, now: int):
        self._actor(actor)
        grant = self.verifier.grant(signed)
        expected = {"purpose": purpose, "store_id": proposal.store_id, "action_key": proposal.ref.key,
                    "action_revision": proposal.ref.revision, "tenant": actor.tenant, "principal": actor.principal,
                    "effect_id": proposal.effect.logical_id, "destination_digest": digest(proposal.effect.destination),
                    "profile_hash": proposal.profile_hash}
        if any(getattr(grant, key) != value for key, value in expected.items()):
            raise Denied("AUTHORITY_BINDING", "exact revision, actor, destination, effect and profile required")
        if not grant.not_before_ns <= now < grant.expires_ns:
            raise Denied("AUTHORITY_TIME", "not yet valid or expired")
        if grant.grant_id in self.journal.state["revoked"]:
            raise Denied("AUTHORITY_REVOKED")
        return grant

    def execute(self, actor: Actor, action_key: str, signed: Signed) -> dict:
        self._actor(actor)
        self.journal.verify()
        proposal = self.action(action_key)
        pack = self._pack(proposal)
        effect_id = proposal.effect.logical_id
        if effect_id in self.journal.state["attempts"]:
            raise Denied("EFFECT_ALREADY_ADMITTED", "observe/reconcile; no automatic repeat")
        self._grant(actor, proposal, signed, "execute", self._now())
        admitted = False
        adapter_called = False
        attempt_id = str(uuid.uuid4())
        try:
            with pack.session(proposal, self.clock) as session:
                now = self._now()
                grant = self._grant(actor, proposal, signed, "execute", now)
                witness = session.witness
                if (witness.subject != proposal.effect.destination or
                    not witness.observed_ns <= now < witness.valid_until_ns):
                    raise Denied("STATE_WITNESS_INVALID")
                basis = DecisionBasis(proposal.ref, proposal.effect, proposal.profile_hash, grant.grant_id,
                                      digest(signed.payload), witness, now, actor)
                attempt = ExecutionAttempt(attempt_id, proposal.ref, proposal.effect, basis,
                                           "owner-controlled-local-domain-boundary-v1")
                closure = ClosureObligation(effect_id, attempt_id, proposal.ref.key, proposal.profile_hash,
                                            actor, now + pack.profile.horizon_seconds * 1_000_000_000)
                # SQLite commit completes before any domain apply() call.
                self.journal.append("ADMITTED", {"attempt": primitive(attempt), "closure": primitive(closure),
                                                "authority": primitive(signed)})
                admitted = True
                self.fault("after_claim_before_effect")
                now = self._now()
                self._pack(proposal)
                self._grant(actor, proposal, signed, "execute", now)
                if not witness.observed_ns <= now < witness.valid_until_ns:
                    raise Denied("STATE_WITNESS_EXPIRED")
                gate_calls = 0

                def admission_gate() -> None:
                    nonlocal gate_calls
                    if gate_calls:
                        raise Denied("EFFECT_GATE_REPLAY", "a new effect requires a new admission")
                    self._pack(proposal)
                    # Sample after preparatory IO and journal fsync, at the domain's first effect call.
                    boundary_now = integer(self.clock(), 1)
                    if boundary_now < self.journal.state["last_clock_ns"]:
                        raise Denied("CLOCK_REGRESSION")
                    self._grant(actor, proposal, signed, "execute", boundary_now)
                    if not witness.observed_ns <= boundary_now < witness.valid_until_ns:
                        raise Denied("STATE_WITNESS_EXPIRED")
                    gate_calls += 1
                adapter_called = True
                session.apply(effect_id, attempt_id, admission_gate, self.fault)
                if gate_calls != 1:
                    raise Denied("ADAPTER_EFFECT_GATE_OMITTED", "adapter completion is not mediated execution proof")
                self.fault("after_effect_before_observation")
        except Exception as error:
            if not admitted:
                raise
            # A called adapter may have mutated even if it raised. Never infer rollback from an exception.
            observation = Observation(effect_id, attempt_id, "local-boundary-v1", self._now(),
                                      Knowledge.UNKNOWN if adapter_called else Knowledge.NOT_APPLIED,
                                      "kernel.boundary-disposition.v1",
                                      {"result": "EFFECT_MAY_HAVE_OCCURRED" if adapter_called else "NO_EFFECT_CALL_STARTED",
                                       "error_type": type(error).__name__,
                                       "reason_code": error.code if isinstance(error, Denied) else "ADAPTER_ERROR"})
            self.journal.append("OBSERVED", {"observation": primitive(observation)})
            return self.closure(effect_id)
        return self.observe(actor, effect_id)

    def observe(self, actor: Actor, effect_id: str) -> dict:
        self._actor(actor)
        self.journal.verify()
        closure = self.journal.state["closures"].get(effect_id)
        if closure is None:
            raise Denied("UNKNOWN_EFFECT")
        proposal = self.action(closure["action_key"])
        now = self._now()
        try:
            pack = self._pack(proposal)
            observation = pack.observe(proposal, closure["attempt_id"], now)
        except (OSError, sqlite3.Error, Denied) as error:
            observation = Observation(effect_id, closure["attempt_id"], "local-observation-boundary-v1", now,
                                      Knowledge.UNKNOWN, "kernel.observation-unavailable.v1",
                                      {"result": "OBSERVATION_UNAVAILABLE", "error_type": type(error).__name__})
        if (observation.effect_id != effect_id or observation.attempt_id != closure["attempt_id"] or
            observation.observed_ns != now or not isinstance(observation.knowledge, Knowledge)):
            raise Denied("OBSERVER_BINDING")
        self.journal.append("OBSERVED", {"observation": primitive(observation)})
        return self.closure(effect_id)

    def retire_unknown(self, actor: Actor, effect_id: str, signed: Signed) -> dict:
        self._actor(actor)
        self.journal.verify()
        closure = self.journal.state["closures"].get(effect_id)
        if closure is None:
            raise Denied("UNKNOWN_EFFECT")
        proposal = self.action(closure["action_key"])
        self._pack(proposal)
        now = self._now()
        grant = self._grant(actor, proposal, signed, "retire_unknown", now)
        if closure["knowledge"] != "UNKNOWN" or now < closure["horizon_ns"]:
            raise Denied("UNKNOWN_RETIREMENT_NOT_ADMISSIBLE")
        if grant.custodian != self.actor.principal or len(text(grant.reason, 1000)) < 8:
            raise Denied("UNKNOWN_CUSTODY_OR_REASON")
        self.journal.append("RETIRED", {"effect_id": effect_id, "reason": grant.reason,
                                        "custodian": primitive(self.actor), "authority_digest": digest(signed.payload),
                                        "authority": primitive(signed), "retired_ns": now})
        return self.closure(effect_id)

    def revoke(self, actor: Actor, signed: Signed) -> None:
        self._actor(actor)
        self.journal.verify()
        payload = self.verifier.payload(signed)
        exact(payload, {"version", "purpose", "store_id", "grant_id", "reason"})
        if payload["version"] != 1 or payload["purpose"] != "revoke" or payload["store_id"] != self.config["store_id"]:
            raise Denied("REVOCATION_BINDING")
        self.journal.append("REVOKED", {"grant_id": text(payload["grant_id"]), "reason": text(payload["reason"], 1000),
                                       "authority": primitive(signed)})

    def closure(self, effect_id: str) -> dict:
        if effect_id not in self.journal.state["closures"]:
            raise Denied("UNKNOWN_EFFECT")
        return copy.deepcopy(self.journal.state["closures"][effect_id])

    def inspect(self) -> dict:
        verification = self.journal.verify()
        return {"version": "candidate-executable-prototype-0.1", "store_id": self.config["store_id"],
                "journal": verification, "action_revisions": len(self.journal.state["actions"]),
                "attempts": len(self.journal.state["attempts"]),
                "closures": copy.deepcopy(list(self.journal.state["closures"].values())),
                "profiles": [primitive(pack.profile) | {"hash": pack.profile.hash} for pack in self.packs.values()]}
