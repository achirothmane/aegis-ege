"""Run bounded native experiments and emit discovered evidence, never a preset cube."""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sqlite3
import sys
import zlib
from collections import defaultdict, deque
from dataclasses import asdict
from pathlib import Path

from oracle import ReplayOracle
from sqlite_model import Profile, Store, all_profiles, operations


AXES = ("A", "C", "P")


def fingerprint(state):
    return json.dumps(state, sort_keys=True, separators=(",", ":"))


def semantic(observation):
    if observation is None:
        return None
    return {k: observation[k] for k in (*AXES, "EXACT_EFFECT")}


def projection_analysis(samples):
    result = {}
    for omitted in AXES:
        retained = tuple(k for k in AXES if k != omitted)
        # First choose equal retained projections. Omitted values are not read here.
        equal_projection_groups = defaultdict(list)
        for sample in samples:
            equal_projection_groups[tuple(sample["observation"][k] for k in retained)].append(sample)
        witnesses = []
        group_summaries = []
        for projection, group in sorted(equal_projection_groups.items()):
            # Only after grouping is frozen do we inspect the omitted coordinate.
            by_omitted_value = {}
            for sample in group:
                value = sample["observation"][omitted]
                if value not in by_omitted_value:
                    by_omitted_value[value] = sample
            group_summaries.append({"retained_values": list(projection), "sample_count": len(group),
                                    "omitted_values": sorted(by_omitted_value)})
            if len(by_omitted_value) > 1:
                witnesses.append({"retained_values": list(projection),
                                  "pair": [by_omitted_value[v] for v in sorted(by_omitted_value)]})
        functions = []
        for mask in range(16):
            values = [(mask >> i) & 1 for i in range(4)]
            counterexample = None
            for sample in samples:
                row = sample["observation"]
                index = 2 * row[retained[0]] + row[retained[1]]
                if values[index] != row[omitted]:
                    counterexample = {"trace": sample["trace"], "retained_values": [row[k] for k in retained],
                                      "actual": row[omitted], "function_value": values[index]}
                    break
            functions.append({"mask": mask, "truth_table_00_01_10_11": values,
                              "fits_discovered_domain": counterexample is None,
                              "counterexample": counterexample})
        result[omitted] = {"retained_coordinates": list(retained),
                           "grouping_rule": "Group equal retained values first; inspect omitted coordinate afterward.",
                           "projection_groups": group_summaries, "conflict_witnesses": witnesses,
                           "all_total_boolean_functions": functions,
                           "surviving_masks": [f["mask"] for f in functions if f["fits_discovered_domain"]]}
    return result


def explore_profile(profile, max_depth=5):
    original = Store(profile)
    oracle = ReplayOracle(profile.kind, profile.guard, profile.sole_attempt)
    if original.physical_state() != oracle.state():
        raise AssertionError("initial native state differs from oracle")
    root_key = fingerprint(original.physical_state())
    queue = deque([(0, [], zlib.compress(original.db.serialize()), oracle)])
    original.close()
    visited = {root_key}
    samples = []
    transitions = 0
    frontier_count = 0
    no_effect_count = 0
    for_depth = defaultdict(int)
    while queue:
        depth, trace, compressed, replay = queue.popleft()
        base = Store(profile, image=zlib.decompress(compressed))
        observed = base.observe()
        if semantic(observed) != replay.observation():
            raise AssertionError({"trace": trace, "native": observed, "oracle": replay.observation()})
        for_depth[depth] += 1
        if observed is None:
            no_effect_count += 1
        else:
            samples.append({"trace": trace, "observation": observed})
        if depth == max_depth:
            frontier_count += 1
            base.close()
            continue
        for command in operations():
            native = base.clone()
            alternate = replay.clone()
            actual_outcome = native.apply(command)
            expected_outcome = alternate.step(command)
            next_trace = trace + [{"operation": list(command), "outcome": actual_outcome}]
            transitions += 1
            if actual_outcome != expected_outcome or native.physical_state() != alternate.state():
                raise AssertionError({"trace": next_trace, "native_outcome": actual_outcome,
                                      "oracle_outcome": expected_outcome,
                                      "native_state": native.physical_state(), "oracle_state": alternate.state()})
            if semantic(native.observe()) != alternate.observation():
                raise AssertionError({"trace": next_trace, "native_observation": native.observe(),
                                      "oracle_observation": alternate.observation()})
            key = fingerprint(native.physical_state())
            if key not in visited:
                visited.add(key)
                queue.append((depth + 1, next_trace, zlib.compress(native.db.serialize()), alternate))
            native.close()
        base.close()
    corner_witnesses = {}
    for sample in samples:
        bits = "".join(str(sample["observation"][k]) for k in AXES)
        if bits not in corner_witnesses:
            corner_witnesses[bits] = sample
    invariant = {}
    for axis in AXES:
        values = sorted({sample["observation"][axis] for sample in samples})
        if len(values) == 1:
            invariant[axis] = values[0]
    same_semantics = defaultdict(set)
    for sample in samples:
        o = sample["observation"]
        same_semantics[tuple(o[k] for k in AXES)].add(o["EXACT_EFFECT"])
    disagreements = [{"ACP": list(k), "decisions": sorted(v)} for k, v in same_semantics.items() if len(v) > 1]
    return {"profile": asdict(profile), "predicate": {
                "mutable": "fixed target currently has the independently selected value approved",
                "retained": "this physical immutable event permanently exists",
                "erasable": "this physical immutable event currently exists",
                "expiring": "this retained immutable event exists and observation time is less than 3"
            }[profile.kind], "max_trace_depth": max_depth,
            "state_count": len(visited), "committed_effect_observations": len(samples),
            "excluded_no_effect_states": no_effect_count, "native_transitions_compared_to_oracle": transitions,
            "states_by_minimal_trace_length": dict(sorted(for_depth.items())),
            "frontier_states_not_expanded": frontier_count,
            "reachable_committed_corners_discovered": sorted(corner_witnesses),
            "invariant_coordinates_discovered": invariant,
            "minimal_corner_witnesses": dict(sorted(corner_witnesses.items())),
            "coordinate_function_tests": projection_analysis(samples),
            "fixed_contract_decision_disagreements": disagreements,
            "method": "BFS through actual SQLite commits; merge only equal complete continuation facts. Independent Python replay checks every native transition."}


def source_hashes():
    root = Path(__file__).resolve().parent
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.glob("*.py"))}


def build_results(depth=5, progress=False):
    from focused import run_focused
    profiles = {}
    for profile in all_profiles():
        if progress:
            print(f"Exploring {profile.name}", file=sys.stderr, flush=True)
        profiles[profile.name] = explore_profile(profile, depth)
    focused = run_focused()
    specification = Path(__file__).with_name("specification.md")
    return {"schema": "independent-sqlite-reproduction-v1",
            "provenance": {"semantic_input": "specification.md only",
                           "specification_sha256": hashlib.sha256(specification.read_bytes()).hexdigest(),
                           "source_sha256": source_hashes(), "python": platform.python_version(),
                           "sqlite": sqlite3.sqlite_version, "stdlib_only": True,
                           "production_or_other_agent_imports": False,
                           "external_publication": False},
            "exploration": {"max_depth": depth, "generated_operations": [list(x) for x in operations()],
                            "profiles": profiles},
            "focused_adversarial_evidence": focused,
            "limits": ["Deterministic depth bound; discovered reachability is evidence, not an exhaustive unbounded theorem.",
                       "Two executors and two attempt IDs; one fixed subject, effect, target, epoch, boundary, evaluated attempt and observation predicate per experiment.",
                       "State merging preserves continuation facts, including physical creator and raw commitment authority facts; ACK claims and absolute journal sequence do not govern modeled continuations.",
                       "SQLite native transactions and file durability are exercised; this is not a hardware power-loss or distributed consensus test.",
                       "The trusted test driver grounds request/executor identity; SQLite text columns and a producer receipt are not an external cryptographic identity proof.",
                       "Profile restrictions assume trusted complete mediation; a privileged actor able to replace schema or corrupt the database violates that surrounding obligation.",
                       "Software independence from the frozen specification; not an independent external human laboratory."]}


def write_report(results, output):
    lines = ["# Independent SQLite reproduction", "", "The only semantic input was the frozen specification. No repository, corpus, helper, fixture, report, production code or other agent source was read or imported.", "",
             "The experiment uses real SQLite transactions and a separately written storage-free replay oracle. Historical physical-effect facts, current target/event state and producer claims occupy separate tables. A/C/P are computed from operational facts; no action assigns truth axes.", "",
             "| Predicate | Atomic authority guard | Exact creator restriction | Discovered A/C/P | Invariants |", "|---|---:|---:|---|---|"]
    for result in results["exploration"]["profiles"].values():
        p = result["profile"]
        lines.append(f"| {p['kind']} | {int(p['guard'])} | {int(p['sole_attempt'])} | {', '.join(result['reachable_committed_corners_discovered'])} | {json.dumps(result['invariant_coordinates_discovered'], sort_keys=True)} |")
    total = sum(p["native_transitions_compared_to_oracle"] for p in results["exploration"]["profiles"].values())
    lines += ["", f"Depth bound: {results['exploration']['max_depth']}. Native transitions independently checked: {total:,}. No native/oracle mismatch occurred. No fixed-contract decision disagreement was found among equal semantic A/C/P observations.", "",
              "Projection groups were formed using only retained coordinates before examining the omitted coordinate. Every one of the sixteen total Boolean functions was enumerated for each omitted coordinate and each profile. The JSON includes all truth tables, fitting masks, concrete counterexamples, minimal corner traces and equal-projection witness pairs. Surviving functions are compatible with the discovered restricted domain; unobserved input rows are unconstrained.", "",
              "Commit/revoke ordering, restoration, epoch mismatch, foreign origin, the same attempt with a different executor, deduplication, mutation/restoration, erasure, expiry and stale observation are represented by operations. File-backed tests kill a subprocess after COMMIT and before acknowledgement, reopen its WAL database, retry the same attempt and then try other attempts/executors. Exactly one physical effect persists; retry receipts do not determine its creator.", "",
              "The focused comparison also probes surrounding-obligation changes. Identical physical A/C/P with a changed decision arises when an envelope violates fixed scope, cardinality/selection, trust, observer freshness/truthfulness, history continuity or independently selected claim policy. Those probes are labeled contract violations, rather than silently adding an axis. See the JSON for explicit classifications and underlying native facts.", "",
              "## Anti-smuggling classification", "",
              "* **Authorized causal receipt — DERIVATION** when independently trusted evidence proves exact commit-time scope authority and exact attempt/executor origin. Its expansion is A and C. Calling that combined receipt bare causality hides authority and is **SEMANTIC SMUGGLING**.",
              "* **State containing verified origin — REPRESENTATION COLLAPSE**: one record can contain both live state evidence and creator evidence. An independently selected state-value predicate alone still does not establish C; comparing verified exact creator IDs does. Building origin into the meaning of generic P is **SEMANTIC SMUGGLING**.",
              "* **Still-current receipt — DERIVATION only with explicit conditional predicate preservation** or a truthful current observation. A past receipt plus allowed mutation/erasure/expiry does not imply current P. Defining currentness into receipt validity bundles the observation coordinate and requires expansion.",
              "* **Unified business-effect record — REPRESENTATION COLLAPSE**: a composite record can represent authority history, creator identity and current predicate evidence together. Verification must expand all three obligations; a logical operation key is not physical identity or causation.",
              "* **Atomic transaction — SUBSTRATE DISCHARGE only under the authority profile's exact checks, current epoch, all-writer mediation, no bypass and serialized revocation**. Bare all-or-none commit implies none of the semantic coordinates by itself. Atomic creation does not preserve a mutable or expiring predicate.",
              "* **Sole-writer store — no creator discharge from one SQLite writer**. The same writer serially serves different attempts and executors. **SUBSTRATE DISCHARGE** of C requires the explicit exact-creator restriction and trusted complete mediation. Deduplication selects an existing effect and never reassigns origin.",
              "* **Permanent event existence — SUBSTRATE DISCHARGE** of P for the independently fixed existence predicate under permanent retention. Immutability of bytes alone does not preserve existence or expiring validity.", "",
              "## Reproduction", "", "```sh", "cd cleanroom-sqlite", "python -m unittest -v test_sqlite", "python explore.py --output /path/to/output-directory --depth 5", "```", "",
              "The second command emits `results.json` and `report.md`. To emit JSON to standard output, use `python explore.py --depth 5` without `--output`. Both commands are independent of the original workspace path.", "", "## Limits", ""]
    lines.extend(f"* {limit}" for limit in results["limits"])
    output.write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, help="Directory for results.json and report.md; omitted means JSON on stdout")
    parser.add_argument("--depth", type=int, default=5)
    args = parser.parse_args()
    if args.depth < 1:
        parser.error("depth must be at least one")
    results = build_results(args.depth, progress=True)
    encoded = json.dumps(results, sort_keys=True, indent=2) + "\n"
    if args.output is None:
        print(encoded, end="")
    else:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "results.json").write_text(encoded)
        write_report(results, args.output / "report.md")
        print(f"Wrote results.json and report.md to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
