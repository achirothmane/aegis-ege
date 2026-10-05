"""Pre-registered source accounting; whole files, both variants identically formatted."""

import ast
import hashlib
import io
import json
import tokenize
from pathlib import Path

ROOT = Path(__file__).resolve().parent
COMMON = ["integration.py", "collector.py", "recover.py"]
EXCLUDED = {
    "native.py": "shared upstream mutation/RBAC/CAS transport, not finality/recovery glue",
    "durable.py": "shared real single-step durable issued/result/successor-CAS representation",
    "provision.py": "shared disposable cluster setup; separately counted setup/configuration",
    "run.py": "identical failure-corpus and marginal-operation test driver",
    "clean_setup.py": "documentation setup measurement runner",
    "measure.py": "source-accounting tool",
}


def count(path):
    text = path.read_text()
    doc_lines = set()
    for node in ast.walk(ast.parse(text)):
        if isinstance(
            node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
        ):
            if node.body and isinstance(node.body[0], ast.Expr):
                value = node.body[0].value
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    doc_lines.update(
                        range(node.body[0].lineno, node.body[0].end_lineno + 1)
                    )
    lines = set()
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if token.type not in (
            tokenize.COMMENT,
            tokenize.NL,
            tokenize.NEWLINE,
            tokenize.INDENT,
            tokenize.DEDENT,
            tokenize.ENDMARKER,
        ):
            lines.update(range(token.start[0], token.end[0] + 1))
    measurement_only = {
        token.start[0]
        for token in tokenize.generate_tokens(io.StringIO(text).readline)
        if token.type == tokenize.COMMENT and token.string == "# MEASUREMENT_ONLY"
    }
    return {
        "gross_source_loc": len(lines - doc_lines),
        "measurement_only_lines": sorted(measurement_only),
        "custom_loc": len(lines - doc_lines - measurement_only),
        "bytes": len(text.encode()),
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
    }


def main():
    files = {p.name: count(p) for p in sorted(ROOT.glob("*.py"))}
    shared = sum(files[x]["custom_loc"] for x in COMMON)
    a = shared + files["ordinary.py"]["custom_loc"]
    b = shared + files["aegis.py"]["custom_loc"]
    result = {
        "method": "Black 24.8.0 / 88; non-comment physical Python LOC excluding docstrings",
        "included_common": COMMON,
        "excluded_files": EXCLUDED,
        "files": files,
        "common_loc": shared,
        "ordinary_custom_loc": a,
        "aegis_custom_loc": b,
        "ordinary_gross_source_loc": sum(files[x]["gross_source_loc"] for x in COMMON)
        + files["ordinary.py"]["gross_source_loc"],
        "aegis_gross_source_loc": sum(files[x]["gross_source_loc"] for x in COMMON)
        + files["aegis.py"]["gross_source_loc"],
        "custom_loc_reduction_percent": (a - b) / a * 100,
        "checker_only_ordinary_loc": files["ordinary.py"]["custom_loc"],
        "mapper_and_checker_aegis_loc": files["aegis.py"]["custom_loc"],
        "zero_adapter_lower_bound_max_reduction_percent": files["ordinary.py"][
            "custom_loc"
        ]
        / a
        * 100,
        "operation2_marginal_custom_loc": {"ordinary": 0, "aegis": 0},
        "operation2_new_destination_specific_cases": {"ordinary": 1, "aegis": 1},
        "custom_test_cases": {"ordinary": 17, "aegis": 22},
        "test_accounting": "13 schedules + 3 shared controls + 1 rollback death/recovery; B adds 5 compatibility controls",
        "shared_manual_config_fields": [
            "admin_kubeconfig",
            "worker_kubeconfig",
            "observer_kubeconfig",
            "namespace",
            "deployment_name",
            "container",
            "desired_image",
            "audit_archive_path",
            "journal_path",
            "observer_root",
            "required_challenge",
            "native_grant_epoch",
            "native_grant_generation",
        ],
        "aegis_extra_manual_config_fields": ["aegis_binary_path"],
        "independent_question_fields": [
            "namespace",
            "name",
            "uid",
            "container",
            "before_rv",
            "before_image",
            "image",
            "subject",
            "executor",
            "attempt",
            "logical_id",
            "epoch",
            "generation",
        ],
        "aegis_generated_policy_fields": [
            "schema",
            "build_sha",
            "case_id",
            "destination_profile",
            "admission_policy_hash",
            "required_claim_type",
            "maximum_grade",
            "public_keys",
            "role_keys",
            "history_id",
        ],
        "aegis_roles_one_root": ["admission", "execution", "destination"],
        "operator_recovery_steps": {"ordinary": 0, "aegis": 0},
        "programmatic_recovery_stages": {"ordinary": 7, "aegis": 9},
        "recovery_stage_definition": [
            "claim owner CAS",
            "load retained question/patch",
            "native read and audit collection",
            "signature/question/freshness/native-proof binding",
            "claim judgment",
            "continuation decision",
            "retain knowledge result",
        ],
        "aegis_extra_recovery_stages": [
            "map/sign library wire evidence and policy",
            "derive library declaration fields using existing consumer",
        ],
        "native_observation_reads_each": 1,
        "native_mutation_writes_observation_only_recovery_each": 0,
        "aegis_cli_invocations_per_recovery": 2,
        "ordinary_cli_invocations_per_recovery": 0,
    }
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
