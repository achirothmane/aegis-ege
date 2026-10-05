"""Disposable infrastructure setup, shared and outside the measured checker LOC."""

import argparse
import json
import subprocess
import time
from pathlib import Path


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--state", type=Path, required=True)
    p.add_argument("--name", default="compression-test")
    args = p.parse_args()
    state = args.state.resolve()
    state.mkdir(parents=True, exist_ok=True)
    audit = state / "audit"
    audit.mkdir(exist_ok=True)
    audit.chmod(0o777)
    policy = state / "audit-policy.yaml"
    policy.write_text(
        "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n"
        "- level: RequestResponse\n  verbs: [patch]\n  resources:\n"
        "  - group: apps\n    resources: [deployments]\n- level: None\n"
    )
    config = state / "kind.yaml"
    config.write_text(
        "kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n"
        "- role: control-plane\n  kubeadmConfigPatches:\n  - |\n"
        "    kind: ClusterConfiguration\n    apiServer:\n      extraArgs:\n"
        "        audit-policy-file: /etc/kubernetes/policies/audit-policy.yaml\n"
        "        audit-log-path: /var/log/compression/audit.log\n"
        "        audit-log-mode: blocking\n      extraVolumes:\n"
        "      - name: audit-policy\n        hostPath: /etc/kubernetes/policies\n"
        "        mountPath: /etc/kubernetes/policies\n        readOnly: true\n"
        "        pathType: DirectoryOrCreate\n"
        "      - name: audit-log\n        hostPath: /var/log/compression\n"
        "        mountPath: /var/log/compression\n        readOnly: false\n"
        "        pathType: DirectoryOrCreate\n  extraMounts:\n"
        f"  - hostPath: {policy}\n"
        "    containerPath: /etc/kubernetes/policies/audit-policy.yaml\n"
        "    readOnly: true\n"
        f"  - hostPath: {audit}\n    containerPath: /var/log/compression\n"
    )
    admin = state / "admin-kubeconfig.yaml"
    start = time.monotonic()
    subprocess.run(
        ["kind", "create", "cluster", "--name", args.name, "--config", str(config),
         "--kubeconfig", str(admin), "--wait", "60s"], check=True,
    )
    subprocess.run(
        ["docker", "exec", args.name + "-control-plane", "chmod", "0644",
         "/var/log/compression/audit.log"], check=True,
    )
    for name in ("admission.json", "admission-binding.json"):
        subprocess.run(
            ["kubectl", "--kubeconfig", str(admin), "apply", "-f",
             str(Path(__file__).parent / name)], check=True,
        )
    status = subprocess.run(
        ["kubectl", "--kubeconfig", str(admin), "get", "validatingadmissionpolicy",
         "commercial-compression-image-fence", "-o", "json"],
        capture_output=True, text=True, check=True,
    )
    data = json.loads(status.stdout)
    warnings = data.get("status", {}).get("typeChecking", {}).get("expressionWarnings", [])
    if warnings:
        raise RuntimeError("admission policy warnings: " + json.dumps(warnings))
    metadata = {
        "cluster": args.name, "provision_seconds": time.monotonic() - start,
        "audit_mode": "blocking", "audit_level": "RequestResponse",
        "audit_file": str(audit / "audit.log"),
        "kubectl_version": json.loads(subprocess.run(
            ["kubectl", "--kubeconfig", str(admin), "version", "-o", "json"],
            check=True, capture_output=True, text=True,
        ).stdout),
    }
    (state / "provision.json").write_text(json.dumps(metadata, indent=2))


if __name__ == "__main__":
    main()
