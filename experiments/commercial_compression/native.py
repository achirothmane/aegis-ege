"""Shared upstream Kubernetes transport and native frozen-CAS executor."""

import copy
import json
import subprocess
import time
import uuid
from pathlib import Path

from integration import PREFIX


class Kube:
    def __init__(self, config, namespace):
        self.config, self.namespace = str(config), namespace

    def run(self, *args, body=None, required=True):
        result = subprocess.run(
            ["kubectl", "--kubeconfig", self.config, "-n", self.namespace, *args],
            input=json.dumps(body) if body is not None else None,
            text=True,
            capture_output=True,
            timeout=90,
        )
        if required and result.returncode:
            raise RuntimeError(result.stderr)
        return result

    def get(self, name):
        return json.loads(self.run("get", "deployment", name, "-o", "json").stdout)

    def patch(self, name, patch, required=False):
        result = self.run(
            "patch",
            "deployment",
            name,
            "--type=json",
            "-p",
            json.dumps(patch),
            "-o",
            "json",
            required=required,
        )
        return {
            "accepted": result.returncode == 0,
            "response": json.loads(result.stdout) if result.returncode == 0 else None,
            "error": result.stderr if result.returncode else None,
        }


def namespace(admin_config, namespace, private):
    admin = Kube(admin_config, namespace)
    admin.run("create", "namespace", namespace)
    admin.run("label", "namespace", namespace, "compression.example/benchmark=true")
    for name in ("worker-1", "worker-2", "observer"):
        admin.run("create", "serviceaccount", name)
    for name, verbs in (("writer", ["get", "patch"]), ("reader", ["get"])):
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": name, "namespace": namespace},
            "rules": [
                {"apiGroups": ["apps"], "resources": ["deployments"], "verbs": verbs}
            ],
        }
        admin.run("apply", "-f", "-", body=role)
        subjects = ["worker-1", "worker-2"] if name == "writer" else ["observer"]
        admin.run(
            "apply",
            "-f",
            "-",
            body={
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": name, "namespace": namespace},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": name,
                },
                "subjects": [
                    {"kind": "ServiceAccount", "name": x, "namespace": namespace}
                    for x in subjects
                ],
            },
        )
    config = json.loads(
        admin.run("config", "view", "--raw", "--minify", "-o", "json").stdout
    )
    result = {}
    for name in ("worker-1", "worker-2", "observer"):
        token = admin.run("create", "token", name, "--duration=1h").stdout.strip()
        client_config = copy.deepcopy(config)
        client_config["users"] = [{"name": "bounded", "user": {"token": token}}]
        client_config["contexts"][0]["context"]["user"] = "bounded"
        path = Path(private) / (namespace + "-" + name + ".json")
        path.write_text(json.dumps(client_config))
        path.chmod(0o600)
        result[name] = str(path)
    return result


def deployment(admin, name):
    admin.run(
        "apply",
        "-f",
        "-",
        body={
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {
                "name": name,
                "annotations": {
                    "compression.example/active": "true",
                    "compression.example/epoch": "1",
                    "compression.example/generation": "1",
                    "compression.example/effect": "",
                    "compression.example/attempt": "",
                    "compression.example/executor": "",
                },
            },
            "spec": {
                "replicas": 0,
                "selector": {"matchLabels": {"app": name}},
                "template": {
                    "metadata": {"labels": {"app": name}},
                    "spec": {
                        "containers": [
                            {"name": "app", "image": "registry.k8s.io/pause:3.10"}
                        ]
                    },
                },
            },
        },
    )
    # Only desired-spec commit is benchmarked. Zero replicas avoids pretending
    # API evidence proves pod readiness and removes image-pull noise from timing.
    previous = ""
    for _ in range(40):
        obj = admin.get(name)
        revision = obj["metadata"]["resourceVersion"]
        if revision == previous:
            return obj
        previous = revision
        time.sleep(0.1)
    raise RuntimeError("Deployment did not reach a stable initial revision")


def question(obj, namespace, image, executor, operation="release"):
    meta = obj["metadata"]
    grant = meta["annotations"]
    return {
        "namespace": namespace,
        "name": meta["name"],
        "uid": meta["uid"],
        "container": "app",
        "before_rv": meta["resourceVersion"],
        "before_image": obj["spec"]["template"]["spec"]["containers"][0]["image"],
        "image": image,
        "subject": "release-controller",
        "executor": "system:serviceaccount:" + namespace + ":" + executor,
        "attempt": str(uuid.uuid4()),
        "logical_id": operation + ":" + str(uuid.uuid4()),
        "epoch": int(grant["compression.example/epoch"]),
        "generation": int(grant["compression.example/generation"]),
    }


def frozen_patch(q):
    values = {
        "/metadata/uid": q["uid"],
        "/metadata/resourceVersion": q["before_rv"],
        "/spec/template/spec/containers/0/image": q["before_image"],
        PREFIX + "active": "true",
        PREFIX + "epoch": str(q["epoch"]),
        PREFIX + "generation": str(q["generation"]),
    }
    changes = {
        "/spec/template/spec/containers/0/image": q["image"],
        PREFIX + "effect": q["logical_id"],
        PREFIX + "attempt": q["attempt"],
        PREFIX + "executor": q["executor"],
    }
    return [{"op": "test", "path": p, "value": v} for p, v in values.items()] + [
        {"op": "replace", "path": p, "value": v} for p, v in changes.items()
    ]
