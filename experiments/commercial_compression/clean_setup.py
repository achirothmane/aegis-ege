"""Documentation-only clean workspace runner; author state is not imported."""

import argparse
import base64
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


def execute(args, env=None, cwd=None):
    result = subprocess.run(
        args, env=env, cwd=cwd, capture_output=True, text=True, timeout=180
    )
    if result.returncode:
        raise RuntimeError(result.stderr)
    return result.stdout


def worker(args):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from collector import observe
    from durable import Journal
    from native import Kube, deployment, frozen_patch, namespace, question
    from recover import recover

    started = time.monotonic()
    private = args.workspace / "private"
    private.mkdir()
    accounts = namespace(args.admin, args.namespace, private)
    admin = Kube(args.admin, args.namespace)
    writer = Kube(accounts["worker-1"], args.namespace)
    reader = Kube(accounts["observer"], args.namespace)
    obj = deployment(admin, "application")
    key = Ed25519PrivateKey.generate()
    root = base64.b64encode(key.public_key().public_bytes_raw()).decode()
    q = question(obj, args.namespace, "registry.k8s.io/pause:3.9", "worker-1")
    journal = Journal(args.workspace / "operation1.sqlite")
    journal.issue(q, frozen_patch(q))
    emitted = writer.patch(q["name"], frozen_patch(q))
    assert emitted["accepted"], emitted
    first, first_data = recover(
        journal,
        q["logical_id"],
        "successor",
        reader,
        args.audit,
        key,
        root,
        args.variant,
        args.binary,
    )
    assert first["closure"] == "CLOSED", first
    first_finished = time.monotonic()
    first_seconds = first_finished - started
    second_start = time.monotonic()
    # No new checker, recovery function, destination settings, root or permissions.
    second_q = question(
        admin.get(q["name"]), args.namespace, q["before_image"], "worker-1", "rollback"
    )
    second_journal = Journal(args.workspace / "operation2.sqlite")
    second_journal.issue(second_q, frozen_patch(second_q))
    emitted = writer.patch(q["name"], frozen_patch(second_q))
    assert emitted["accepted"], emitted
    second, second_data = recover(
        second_journal,
        second_q["logical_id"],
        "successor",
        reader,
        args.audit,
        key,
        root,
        args.variant,
        args.binary,
    )
    assert second["closure"] == "CLOSED", second
    data = {
        "variant": args.variant,
        "namespace": args.namespace,
        "first_effect_setup_and_execution_seconds": first_seconds,
        "first_effect_finished_monotonic": first_finished,
        "second_operation_seconds": time.monotonic() - second_start,
        "first_result": first,
        "second_result": second,
        "first_recovery_ms": first_data["total_ms"],
        "second_recovery_ms": second_data["total_ms"],
        "second_new_custom_loc": 0,
        "second_new_destination_settings": 0,
        "second_changed_operator_inputs": ["image", "operation_label"],
        "python_prefix": sys.prefix,
        "ambiguities": [],
    }
    (args.workspace / "measurements.json").write_text(json.dumps(data, indent=2))
    public = args.out / args.namespace
    public.mkdir()
    for number, captured in ((1, first_data), (2, second_data)):
        for field in ("envelope", "question", "challenge", "package"):
            (public / f"operation{number}-{field}.json").write_text(
                json.dumps(captured[field], indent=2)
            )
    (public / "root.json").write_text(json.dumps({"observer_root": root}))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--worker-stage", action="store_true")
    p.add_argument("--variant", choices=["ordinary", "aegis"])
    p.add_argument("--namespace")
    p.add_argument("--workspace", type=Path)
    p.add_argument("--base", type=Path)
    p.add_argument("--admin", type=Path, required=True)
    p.add_argument("--audit", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--binary", type=Path)
    args = p.parse_args()
    if args.worker_stage:
        worker(args)
        return
    args.out.mkdir(parents=True, exist_ok=True)
    samples = []
    for variant, label in (
        ("ordinary", "a1"),
        ("aegis", "b1"),
        ("aegis", "b2"),
        ("ordinary", "a2"),
    ):
        start = time.monotonic()
        private_setups = args.out.parent.parent / "compression-clean-private"
        private_setups.mkdir(exist_ok=True)
        workspace = private_setups / ("clean-workspace-" + label)
        assert not workspace.exists(), "clean workspace already exists"
        workspace.mkdir()
        kit = workspace / "kit"
        kit.mkdir()
        for source in Path(__file__).parent.glob("*.py"):
            shutil.copyfile(source, kit / source.name)
        env = dict(os.environ)
        env.pop("PYTHONPATH", None)
        env.pop("PYTHONHOME", None)
        venv = workspace / "venv"
        execute([sys.executable, "-m", "venv", str(venv)], env)
        python = venv / "bin/python"
        dependency_start = time.monotonic()
        execute(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "cryptography==46.0.0",
            ],
            env,
        )
        dependency_seconds = time.monotonic() - dependency_start
        build_seconds = 0.0
        binary = workspace / "aegis-evidence-inspect"
        if variant == "aegis":
            actual = execute(["git", "-C", str(args.base), "rev-parse", "HEAD"]).strip()
            assert actual == "04434db12fa0c85d3497faf6ebb40df937092c5d"
            env["GOCACHE"] = str(workspace / "fresh-go-cache")
            env["CGO_ENABLED"] = "0"
            build_start = time.monotonic()
            execute(
                [
                    "go",
                    "build",
                    "-mod=readonly",
                    "-trimpath",
                    "-o",
                    str(binary),
                    "./cmd/aegis-evidence-inspect",
                ],
                env,
                str(args.base),
            )
            build_seconds = time.monotonic() - build_start
        command = [
            str(python),
            "-B",
            str(kit / "clean_setup.py"),
            "--worker-stage",
            "--variant",
            variant,
            "--namespace",
            "compression-" + label,
            "--workspace",
            str(workspace),
            "--admin",
            str(args.admin.resolve()),
            "--audit",
            str(args.audit.resolve()),
            "--out",
            str(args.out.resolve()),
        ]
        if variant == "aegis":
            command.extend(["--binary", str(binary)])
        execute(command, env, str(kit))
        data = json.loads((workspace / "measurements.json").read_text())
        data.update(
            {
                "label": label,
                "total_clean_setup_seconds": time.monotonic() - start,
                "total_clean_setup_to_first_effect_seconds": data[
                    "first_effect_finished_monotonic"
                ]
                - start,
                "dependency_install_seconds": dependency_seconds,
                "fresh_go_build_seconds": build_seconds,
                "source_copy": "fresh kit; new venv, namespace, journal, observer key and challenge",
                "shared_prerequisites": "CI Python/Docker/kubectl/KinD; shared fresh control plane; Go for B",
                "go_module_download_cache": "shared hosted-runner cache after initial pinned build",
                "author_local_state_used": False,
            }
        )
        samples.append(data)
    (args.out / "setup-results.json").write_text(json.dumps(samples, indent=2))
    print(
        json.dumps(
            [
                {
                    k: d[k]
                    for k in (
                        "label",
                        "total_clean_setup_seconds",
                        "second_operation_seconds",
                    )
                }
                for d in samples
            ]
        )
    )


if __name__ == "__main__":
    main()
