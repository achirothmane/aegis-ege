# Cycle 8 follow-up: complete frozen-evidence replay

Starting main: `eb801b9c6229b292df7c3b667a98e8c9b43d583f` (#244).
The complete Cycle 7 and Cycle 8 reports were read before this change.

The original independent-reproduction runner validates frozen inputs, compares
discovered corners and recomputes fitting pair functions. That comparison does
not inspect all emitted witnesses, focused cases, statistics or explanations.
Replacing the SQLite `111` minimal witness trace with an empty trace leaves its
original normalized profile result unchanged. This is a replay-assurance coverage
gap, not a discovered semantic disagreement or a falsification of the bounded
projection result.

An additional verifier now checks all five complete frozen evidence artifacts
after the original runner finishes: SQLite results and report, event-model
analysis, trace witnesses and report. The original registration is pinned in its
entirety; each reference artifact must retain its original registered hash.
Sources, result fixtures, the registration, the original runner and its workflow
remain unchanged. Neither producer receives frozen outputs as an execution oracle.

| Classification | Required comparison | Outcome |
|---|---|---|
| `EXACT_BYTES` | Original registered bytes equal the complete emitted file | Pass; byte-identical reproduction |
| `RUNTIME_PROVENANCE_ONLY` | Only SQLite JSON's `provenance.python` and/or `provenance.sqlite` version strings differ; restoring those values reproduces every original byte | Pass; explicit runtime metadata differences, never called byte-identical |
| `MISMATCH` | Any other content/serialization change, missing artifact, invalid JSON on the runtime-exception path, or changed original pin | Fail; retain emitted evidence and comparison diagnostics |

The runtime exception accommodates differing Python/SQLite builds on CI. It does
not exclude source hashes, scope, claims, traces, native facts, limits, counters,
decision diagnostics or any other provenance. Duplicate JSON keys, non-finite
values and Boolean/integer substitutions cannot disappear through normalization.
Byte identity is an additional reproducibility observation, not external proof of
physical truth or an expansion of the theorem's domain.

The failure controls use temporary copies of the actual frozen evidence. They
retain the unchanged old profile comparison while changing a minimal witness,
then require the new complete-artifact gate to fail. Other controls cover altered
reports and event traces, missing artifacts, changed reference/registration pins,
runtime metadata combined with altered facts, and failure-diagnostic retention.

Local replay of the unchanged producers preserved all 774 Cycle 7 repository
files, found zero profile disagreements and reproduced all five frozen artifacts
byte-for-byte. Their SHA-256 values remain the original registration values.
The new workflow independently reruns the producers and uploads raw outputs and
the complete-artifact comparison even on failure.

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/run_independent_reproduction.py --out /tmp/frozen-evidence-replay
python3 -B scripts/verify_frozen_reproduction.py --evidence-dir /tmp/frozen-evidence-replay
python3 -B -m unittest discover -s scripts -p 'test_verify_frozen_reproduction.py' -v
```

All 808 existing repository files retain their original bytes in this additive
follow-up. Twelve new failure/control tests pass. The
production kernel, constitutional anchors and Cycle 8 classifications **N1 / R4 /
P1** remain unchanged. This adds an assurance gate, not a fourth coordinate, a
production feature, or a new research/novelty claim.
