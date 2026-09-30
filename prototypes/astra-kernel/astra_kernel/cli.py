from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from pathlib import Path

from .authority import OwnerAuthority, Signed
from .kernel import Kernel, initialize, write_private
from .model import Busy, CorruptStore, Denied, canonical, local_actor, loads, primitive


CRASH_POINTS = ("after_claim_before_effect", "after_effect_before_observation",
                "sqlite_after_ddl_before_commit", "file_after_stage_sync")


def output(value) -> None:
    print(canonical(value).decode("utf-8"))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="astra-kernel", description="Local governed-action kernel prototype")
    sub = result.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init", help="create a NEW isolated demo home")
    init.add_argument("home", type=Path)
    demo = sub.add_parser("demo", help="run effects, denials and real process-crash recovery in a temporary home")
    demo.add_argument("--out", type=Path)
    for name in ("propose-file", "propose-db", "authorize", "execute", "observe", "inspect", "revoke", "retire-unknown"):
        command = sub.add_parser(name)
        command.add_argument("--home", required=True, type=Path)
        if name == "propose-file":
            command.add_argument("--action", required=True)
            command.add_argument("--content", required=True)
        elif name == "propose-db":
            command.add_argument("--action", required=True)
            command.add_argument("--column", required=True)
            command.add_argument("--default", default="")
        elif name in {"authorize", "execute"}:
            command.add_argument("--action-key", required=True)
            if name == "authorize":
                command.add_argument("--ttl", type=int, default=60)
                command.add_argument("--out", required=True, type=Path)
            else:
                command.add_argument("--grant", required=True, type=Path)
                command.add_argument("--crash-at", choices=CRASH_POINTS, help="explicit fault-injection only")
        elif name in {"observe", "retire-unknown"}:
            command.add_argument("--effect-id", required=True)
            if name == "retire-unknown":
                command.add_argument("--reason", required=True)
        elif name == "revoke":
            command.add_argument("--grant", required=True, type=Path)
            command.add_argument("--reason", required=True)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "init":
            output(initialize(args.home))
            return 0
        if args.command == "demo":
            from .demo import run_demo
            trace = run_demo()
            if args.out:
                write_private(args.out, canonical(trace) + b"\n")
            output(trace)
            return 0
        actor = local_actor()

        def fault(point: str) -> None:
            if point == getattr(args, "crash_at", None):
                os._exit(86)

        with Kernel(args.home, fault=fault) as kernel:
            command = args.command
            if command == "propose-file":
                proposal = kernel.propose(actor, args.action, "file.replace",
                                          {"filename": "settings.txt", "content_utf8": args.content})
                output({"action_key": proposal.ref.key, "proposal": primitive(proposal)})
            elif command == "propose-db":
                proposal = kernel.propose(actor, args.action, "sqlite.add-column",
                                          {"column": args.column, "default_text": args.default})
                output({"action_key": proposal.ref.key, "proposal": primitive(proposal)})
            elif command == "authorize":
                owner = OwnerAuthority.load(args.home / "owner" / "issuer.key")
                signed = owner.issue(kernel.action(args.action_key), ttl_seconds=args.ttl)
                write_private(args.out, canonical(signed))
                output({"grant_file": str(args.out), "grant_id": signed.payload["grant_id"],
                        "scope": "one exact action revision and logical effect"})
            elif command == "execute":
                signed = Signed.parse(loads(args.grant.read_bytes()))
                result = kernel.execute(actor, args.action_key, signed)
                output(result)
                return 0 if result["knowledge"] == "VERIFIED" else 3
            elif command == "observe":
                result = kernel.observe(actor, args.effect_id)
                output(result)
                return 0 if result["knowledge"] in {"VERIFIED", "NOT_APPLIED"} else 3
            elif command == "inspect":
                output(kernel.inspect())
            elif command == "revoke":
                signed = Signed.parse(loads(args.grant.read_bytes()))
                grant = kernel.verifier.grant(signed)
                owner = OwnerAuthority.load(args.home / "owner" / "issuer.key")
                kernel.revoke(actor, owner.revoke(kernel.config["store_id"], grant.grant_id, args.reason))
                output({"revoked_grant": grant.grant_id})
            elif command == "retire-unknown":
                closure = kernel.closure(args.effect_id)
                owner = OwnerAuthority.load(args.home / "owner" / "issuer.key")
                signed = owner.issue(kernel.action(closure["action_key"]), purpose="retire_unknown",
                                     custodian=actor.principal, reason=args.reason)
                output(kernel.retire_unknown(actor, args.effect_id, signed))
        return 0
    except Denied as error:
        output({"decision": "DENY", "reason": error.code, "detail": error.detail})
        return 2
    except Busy as error:
        output({"decision": "BUSY", "detail": str(error)})
        return 4
    except (CorruptStore, OSError, ValueError, sqlite3.Error) as error:
        output({"decision": "LOCKED", "error_type": type(error).__name__, "detail": str(error)})
        return 5


if __name__ == "__main__":
    sys.exit(main())
