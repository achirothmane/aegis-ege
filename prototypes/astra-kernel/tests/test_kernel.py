from __future__ import annotations

import copy
import dataclasses
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from astra_kernel.authority import OwnerAuthority, Signed
from astra_kernel.kernel import Kernel, initialize
from astra_kernel.model import Actor, Denied, canonical, local_actor, loads
from astra_kernel.packs.file_replace import FileSession
from astra_kernel.packs.sqlite_migration import MigrationSession


class Clock:
    def __init__(self):
        self.now = 1_800_000_000_000_000_000

    def __call__(self):
        return self.now

    def advance(self, seconds: int):
        self.now += seconds * 1_000_000_000


class KernelCases(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="astra-unit-", dir=Path.cwd())
        self.home = Path(self.temp.name) / "home"
        initialize(self.home)
        self.owner = OwnerAuthority.load(self.home / "owner" / "issuer.key")
        self.clock = Clock()
        self.actor = local_actor()
        self.kernel = Kernel(self.home, clock=self.clock)

    def tearDown(self):
        self.kernel.close()
        self.temp.cleanup()

    def proposal(self, identity="case", content="mode=approved\n"):
        return self.kernel.propose(self.actor, identity, "file.replace",
                                   {"filename": "settings.txt", "content_utf8": content})

    def grant(self, proposal, **kwargs):
        return self.owner.issue(proposal, now_ns=self.clock.now, **kwargs)

    def assert_denied(self, code, callable_, *args):
        with self.assertRaises(Denied) as raised:
            callable_(*args)
        self.assertEqual(raised.exception.code, code)

    def unchanged(self):
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_real_file_effect_and_observed_postcondition(self):
        action = self.proposal()
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=approved\n")
        self.assertEqual(result["knowledge"], "VERIFIED")
        self.assertEqual(result["disposition"], "CLOSED")
        self.assertEqual(result["observation"]["domain_type"], "file.replace.outcome.v1")
        self.assertEqual(result["observation"]["domain_payload"]["attribution"], "postcondition-only")
        self.assertEqual(self.kernel.inspect()["attempts"], 1)

    def test_real_database_transaction_preserves_rows_and_binds_marker(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": "new"})
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "VERIFIED")
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            self.assertEqual(conn.execute("SELECT id,name,status FROM people ORDER BY id").fetchall(),
                             [(1, "Example A", "new"), (2, "Example B", "new")])
            self.assertEqual(conn.execute("SELECT count(*) FROM astra_effects").fetchone()[0], 1)
            marker = conn.execute("SELECT effect_id,attempt_id,revision FROM astra_effects").fetchone()
            self.assertEqual(marker, (action.effect.logical_id, result["attempt_id"], action.ref.revision))

    def test_missing_and_forged_signature_never_begin_effect(self):
        action = self.proposal()
        self.assert_denied("BAD_SIGNATURE", self.kernel.execute, self.actor, action.ref.key, Signed({}, "bad"))
        signed = OwnerAuthority.generate().issue(action, now_ns=self.clock.now)
        self.assert_denied("BAD_SIGNATURE", self.kernel.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_every_authority_binding_is_checked_even_when_issuer_signed(self):
        action = self.proposal()
        original = self.grant(action)
        values = {"purpose": "retire_unknown", "store_id": "other-store", "action_key": "other-key",
                  "action_revision": "other-revision", "tenant": "other-tenant", "principal": "other-principal",
                  "effect_id": "other-effect", "destination_digest": "other-account", "profile_hash": "weak-profile"}
        for field, value in values.items():
            with self.subTest(field=field):
                payload = {**original.payload, field: value}
                self.assert_denied("AUTHORITY_BINDING", self.kernel.execute, self.actor, action.ref.key, self.owner.sign(payload))
                self.unchanged()

    def test_approval_cannot_follow_new_revision(self):
        first = self.proposal("same-request", "first revision")
        second = self.proposal("same-request", "second revision")
        self.assertEqual(first.effect.logical_id, second.effect.logical_id)
        self.assertNotEqual(first.ref.revision, second.ref.revision)
        self.assert_denied("AUTHORITY_BINDING", self.kernel.execute, self.actor, second.ref.key, self.grant(first))
        self.unchanged()

    def test_requester_cannot_select_vacuous_profile_or_validator(self):
        self.assert_denied("UNTRUSTED_ACTION_KIND", self.kernel.propose, self.actor, "weak", "allow-everything", {})
        self.assert_denied("INVALID_RECORD", self.kernel.propose, self.actor, "weak", "file.replace",
                           {"filename": "settings.txt", "content_utf8": "changed", "approved": True})
        self.unchanged()

    def test_actor_tenant_and_principal_cannot_be_impersonated(self):
        action = self.proposal()
        for actor in (Actor("foreign-tenant", self.actor.principal), Actor(self.actor.tenant, "foreign-principal")):
            with self.subTest(actor=actor):
                self.assert_denied("ACTOR_SCOPE", self.kernel.execute, actor, action.ref.key, self.grant(action))
        self.unchanged()

    def test_expiry_is_half_open_and_delayed_approval_does_not_authorize(self):
        action = self.proposal()
        signed = self.grant(action, ttl_seconds=1)
        self.clock.advance(1)
        self.assert_denied("AUTHORITY_TIME", self.kernel.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_future_authority_is_rejected(self):
        action = self.proposal()
        signed = self.owner.issue(action, now_ns=self.clock.now + 1_000_000_000)
        self.assert_denied("AUTHORITY_TIME", self.kernel.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_revocation_is_persistent_and_checked_at_execution(self):
        action = self.proposal()
        signed = self.grant(action)
        self.kernel.revoke(self.actor, self.owner.revoke(action.store_id, signed.payload["grant_id"], "owner revoked"))
        self.kernel.close()
        self.kernel = Kernel(self.home, clock=self.clock)
        self.assert_denied("AUTHORITY_REVOKED", self.kernel.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_clock_regression_is_not_an_expiry_reset(self):
        action = self.proposal()
        signed = self.grant(action)
        self.clock.now -= 1
        self.assert_denied("CLOCK_REGRESSION", self.kernel.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_profile_upgrade_invalidates_waiting_proposal(self):
        action = self.proposal()
        pack = self.kernel.packs["file.replace"]
        pack.profile = dataclasses.replace(pack.profile, version="2")
        self.assert_denied("TRUSTED_PROFILE_CHANGED", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.unchanged()

    def test_profile_change_after_claim_does_not_authorize_old_semantics(self):
        action = self.proposal()
        def fault(point):
            if point == "after_claim_before_effect":
                pack = self.kernel.packs["file.replace"]
                pack.profile = dataclasses.replace(pack.profile, version="2")
        self.kernel.fault = fault
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "NOT_APPLIED")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "TRUSTED_PROFILE_CHANGED")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_stale_file_read_is_rejected_at_write_boundary(self):
        action = self.proposal()
        (self.home / "files" / "settings.txt").write_text("operator changed current state")
        self.assert_denied("STALE_STATE", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "operator changed current state")
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_file_route_cannot_mutate_database_or_escape_root(self):
        for name in ("../database/people.sqlite", "/etc/passwd", "people.sqlite", "other.txt"):
            with self.subTest(name=name):
                self.assert_denied("FILE_SCOPE", self.kernel.propose, self.actor, "escape", "file.replace",
                                   {"filename": name, "content_utf8": "wrong destination"})
        self.unchanged()

    def test_file_symlink_target_is_refused(self):
        file = self.home / "files" / "settings.txt"
        outside = self.home / "outside.txt"
        outside.write_text("keep")
        file.unlink()
        file.symlink_to(outside)
        with self.assertRaises(OSError):
            self.proposal()
        self.assertEqual(outside.read_text(), "keep")
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_replaced_destination_cannot_inherit_authority(self):
        action = self.proposal()
        (self.home / "files").rename(self.home / "old-files")
        (self.home / "files").mkdir()
        (self.home / "files" / "settings.txt").write_text("mode=initial\n")
        self.assert_denied("DESTINATION_CHANGED", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_second_effect_attempt_is_refused_after_success(self):
        action = self.proposal()
        signed = self.grant(action)
        self.kernel.execute(self.actor, action.ref.key, signed)
        self.assert_denied("EFFECT_ALREADY_ADMITTED", self.kernel.execute, self.actor, action.ref.key, signed)
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 1)

    def test_new_revision_or_domain_cannot_amplify_existing_effect(self):
        action = self.proposal("stable-effect")
        self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assert_denied("EFFECT_ALREADY_ADMITTED", self.kernel.propose, self.actor, "stable-effect",
                           "sqlite.add-column", {"column": "new_provider", "default_text": ""})
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            self.assertNotIn("new_provider", {r[1] for r in conn.execute("PRAGMA table_info(people)")})

    def test_expiry_between_claim_and_effect_stops_without_mutation(self):
        action = self.proposal()
        signed = self.grant(action, ttl_seconds=1)
        self.kernel.fault = lambda point: self.clock.advance(1) if point == "after_claim_before_effect" else None
        result = self.kernel.execute(self.actor, action.ref.key, signed)
        self.assertEqual(result["knowledge"], "NOT_APPLIED")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "AUTHORITY_TIME")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_evidence_expiry_between_claim_and_effect_stops(self):
        action = self.proposal()
        self.kernel.fault = lambda point: self.clock.advance(2) if point == "after_claim_before_effect" else None
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "NOT_APPLIED")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "STATE_WITNESS_EXPIRED")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_revocation_between_claim_and_effect_is_rechecked(self):
        action = self.proposal()
        signed = self.grant(action)
        def fault(point):
            if point == "after_claim_before_effect":
                self.kernel.revoke(self.actor, self.owner.revoke(action.store_id, signed.payload["grant_id"], "stop before dispatch"))
        self.kernel.fault = fault
        result = self.kernel.execute(self.actor, action.ref.key, signed)
        self.assertEqual(result["knowledge"], "NOT_APPLIED")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "AUTHORITY_REVOKED")

    def test_adapter_return_is_not_outcome_proof(self):
        action = self.proposal()
        with patch.object(FileSession, "apply", lambda *args: None):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["disposition"], "OPEN")

    def test_effect_then_exception_remains_owned_unknown(self):
        action = self.proposal()
        native = FileSession.apply
        def lost_response(session, *args):
            native(session, *args)
            raise TimeoutError("response lost after mutation")
        with patch.object(FileSession, "apply", lost_response):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=approved\n")
        self.assert_denied("EFFECT_ALREADY_ADMITTED", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.assertEqual(self.kernel.observe(self.actor, action.effect.logical_id)["knowledge"], "VERIFIED")

    def test_broken_adapter_exception_is_never_negative_effect_proof(self):
        action = self.proposal()
        def broken_adapter(*args):
            (self.home / "files" / "settings.txt").write_text("mode=approved\n")
            raise TimeoutError("adapter broke its contract then lost response")
        with patch.object(FileSession, "apply", broken_adapter):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["disposition"], "OPEN")

    def test_authority_is_checked_again_at_native_domain_effect(self):
        action = self.proposal()
        signed = self.grant(action, ttl_seconds=1)
        real_read = self.kernel.packs["file.replace"].read
        reads = []
        def delayed_read(fd):
            value = real_read(fd)
            reads.append(True)
            if len(reads) == 2:  # session precondition first, native write precondition second
                self.clock.advance(1)
            return value
        with patch.object(self.kernel.packs["file.replace"], "read", delayed_read):
            # FileSession deliberately calls the class's read method; patch that method as well.
            with patch("astra_kernel.packs.file_replace.FileReplace.read", side_effect=delayed_read):
                result = self.kernel.execute(self.actor, action.ref.key, signed)
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "AUTHORITY_TIME")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=initial\n")

    def test_current_read_stale_write_race_is_refused_inside_file_boundary(self):
        action = self.proposal()
        def fault(point):
            if point == "after_claim_before_effect":
                (self.home / "files" / "settings.txt").write_text("intervening manual write")
        self.kernel.fault = fault
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "STALE_STATE_AT_WRITE")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "intervening manual write")

    def test_unknown_retirement_requires_horizon_custody_and_separate_authority(self):
        action = self.proposal()
        with patch.object(FileSession, "apply", lambda *args: None):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        early = self.grant(action, purpose="retire_unknown", custodian=self.actor.principal, reason="observer gap accepted")
        self.assert_denied("UNKNOWN_RETIREMENT_NOT_ADMISSIBLE", self.kernel.retire_unknown, self.actor, action.effect.logical_id, early)
        self.clock.advance(30)
        self.assert_denied("AUTHORITY_BINDING", self.kernel.retire_unknown, self.actor, action.effect.logical_id, self.grant(action))
        wrong = self.grant(action, purpose="retire_unknown", custodian="unaccountable", reason="observer gap accepted")
        self.assert_denied("UNKNOWN_CUSTODY_OR_REASON", self.kernel.retire_unknown, self.actor, action.effect.logical_id, wrong)
        final = self.grant(action, purpose="retire_unknown", custodian=self.actor.principal, reason="explicitly accept unresolved outcome")
        result = self.kernel.retire_unknown(self.actor, action.effect.logical_id, final)
        self.assertEqual((result["knowledge"], result["disposition"]), ("UNKNOWN", "RETIRED_UNKNOWN"))
        self.assert_denied("EFFECT_ALREADY_ADMITTED", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.kernel.close()
        self.kernel = Kernel(self.home, clock=self.clock)
        self.assertEqual(self.kernel.closure(action.effect.logical_id)["disposition"], "RETIRED_UNKNOWN")

    def test_late_observation_preserves_unknown_retirement_history(self):
        action = self.proposal()
        with patch.object(FileSession, "apply", lambda *args: None):
            self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.clock.advance(30)
        self.kernel.retire_unknown(self.actor, action.effect.logical_id,
                                   self.grant(action, purpose="retire_unknown", custodian=self.actor.principal,
                                              reason="limited observation horizon exhausted"))
        (self.home / "files" / "settings.txt").write_text("mode=approved\n")
        result = self.kernel.observe(self.actor, action.effect.logical_id)
        self.assertEqual(result["knowledge"], "VERIFIED")
        events = [r[0] for r in self.kernel.journal.connection.execute("SELECT kind FROM events ORDER BY seq")]
        self.assertIn("RETIRED", events)
        self.assertEqual(events[-1], "OBSERVED")
        self.assertTrue(result["retirement_reason"])

    def test_read_observation_has_no_execution_authority_and_does_not_repeat(self):
        action = self.proposal()
        self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        with patch.object(FileSession, "apply", side_effect=AssertionError("observer must not apply")):
            self.assertEqual(self.kernel.observe(self.actor, action.effect.logical_id)["knowledge"], "VERIFIED")

    def test_sqlite_stale_rows_are_rejected(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": ""})
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            conn.execute("UPDATE people SET name='changed' WHERE id=1")
        self.assert_denied("STALE_STATE", self.kernel.execute, self.actor, action.ref.key, self.grant(action))
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_sqlite_missing_marker_plus_state_change_is_unknown(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": ""})
        def incomplete(session, effect_id, attempt_id, admission_gate, fault):
            admission_gate()
            session.connection.execute("ALTER TABLE people ADD COLUMN wrong TEXT")
            session.connection.execute("COMMIT")
        with patch.object(MigrationSession, "apply", incomplete):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["observation"]["domain_payload"]["result"], "MISSING_MARKER_WITH_STATE_DRIFT")

    def test_adapter_cannot_reuse_effect_gate_for_second_mutation(self):
        action = self.proposal()
        native = FileSession.apply
        def duplicate(session, effect_id, attempt_id, admission_gate, fault):
            native(session, effect_id, attempt_id, admission_gate, fault)
            admission_gate()
            (self.home / "files" / "settings.txt").write_text("second unauthorized effect")
        with patch.object(FileSession, "apply", duplicate):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "EFFECT_GATE_REPLAY")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), "mode=approved\n")

    def test_omitted_native_effect_gate_is_a_detected_adapter_violation(self):
        action = self.proposal()
        with patch.object(FileSession, "apply", lambda *args: None):
            result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertEqual(result["observation"]["domain_payload"]["reason_code"], "ADAPTER_EFFECT_GATE_OMITTED")

    def test_sqlite_false_outcome_after_marker_is_not_verified(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": "new"})
        self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            conn.execute("UPDATE people SET status='wrong' WHERE id=1")
        result = self.kernel.observe(self.actor, action.effect.logical_id)
        self.assertEqual(result["knowledge"], "UNKNOWN")
        self.assertFalse(result["observation"]["domain_payload"]["default_rows_match"])

    def test_sqlite_marker_for_other_revision_is_not_proof(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": "new"})
        self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            conn.execute("UPDATE astra_effects SET revision='other'")
        self.assertEqual(self.kernel.observe(self.actor, action.effect.logical_id)["knowledge"], "UNKNOWN")

    def test_observer_does_not_silently_change_database_journal_mode(self):
        action = self.kernel.propose(self.actor, "migration", "sqlite.add-column", {"column": "status", "default_text": "new"})
        self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        path = self.home / "database" / "people.sqlite"
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        result = self.kernel.observe(self.actor, action.effect.logical_id)
        self.assertEqual(result["knowledge"], "UNKNOWN")
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0], "wal")

    def test_sqlite_column_injection_and_unbounded_default_are_rejected(self):
        for requested in ({"column": "status; DROP TABLE people;--", "default_text": ""},
                          {"column": "id", "default_text": ""},
                          {"column": "status", "default_text": "x" * 65}):
            with self.subTest(requested=requested), self.assertRaises(Denied):
                self.kernel.propose(self.actor, "bad-migration", "sqlite.add-column", requested)
        self.assertEqual(len(self.kernel.journal.state["attempts"]), 0)

    def test_sqlite_default_quotes_remain_data(self):
        action = self.kernel.propose(self.actor, "literal", "sqlite.add-column", {"column": "status", "default_text": "O'Reilly; --"})
        self.assertEqual(self.kernel.execute(self.actor, action.ref.key, self.grant(action))["knowledge"], "VERIFIED")
        with sqlite3.connect(self.home / "database" / "people.sqlite") as conn:
            self.assertEqual(conn.execute("SELECT status FROM people").fetchall(), [("O'Reilly; --",), ("O'Reilly; --",)])

    def test_stale_released_runtime_cannot_resume_effect(self):
        action = self.proposal()
        signed = self.grant(action)
        old = self.kernel
        old.close()
        self.kernel = Kernel(self.home, clock=self.clock)
        self.assert_denied("RUNTIME_CLOSED", old.execute, self.actor, action.ref.key, signed)
        self.unchanged()

    def test_noop_is_not_used_as_a_fake_governed_effect(self):
        self.assert_denied("NO_CHANGE", self.kernel.propose, self.actor, "noop", "file.replace",
                           {"filename": "settings.txt", "content_utf8": "mode=initial\n"})
        self.unchanged()

    def test_duplicate_keys_nonfinite_and_floats_are_not_canonical_inputs(self):
        for data in ('{"tenant":"a","tenant":"b"}', '{"value":NaN}', '{"value":1.1}', '{"value":Infinity}'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                loads(data)

    def test_unicode_and_metacharacters_preserve_exact_content(self):
        value = "حالة آمنة <>&\u2028\u2029\n"
        action = self.proposal(content=value)
        result = self.kernel.execute(self.actor, action.ref.key, self.grant(action))
        self.assertEqual(result["knowledge"], "VERIFIED")
        self.assertEqual((self.home / "files" / "settings.txt").read_text(), value)

    def test_proposal_mutation_is_detected_before_owner_signs(self):
        action = self.proposal()
        action.parameters["content_utf8"] = "mutated after revision binding"
        self.assert_denied("REVISION_INTEGRITY", self.grant, action)
        self.unchanged()
