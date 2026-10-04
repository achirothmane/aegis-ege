# Cedar Chronicle: specification-only event experiment

This experiment was independently constructed from `Frozen reproduction specification v1`.
It has no production package imports or dependency installation. Node.js 18 or newer is
required for `findLast`; the frozen run used Node.js 24.19.0.

From this directory, run the tests:

```sh
node checks.js
```

Emit deterministic results, traces and a report into a chosen directory:

```sh
node chronicle.js --out ./rerun
```

Alternatively, emit the complete result JSON to stdout:

```sh
node chronicle.js --stdout
```

The frozen results are in `results/`. `analysis.json` includes graph statistics,
all discovered committed corners, shortest corner histories, retained-only
projection groups, separating pairs, all sixteen Boolean functions for every
retained pair, contract disagreement diagnostics, focused adversarial traces,
anti-smuggling classifications and limits. `trace-witnesses.json` is a trace
extract. `report.md` explains the experiment and conclusions.

The graph closes a finite abstraction over event transitions. It is not a graph
whose states are chosen A/C/P assignments. Raw commit-era authority facts are
retained in the behavioral state key so later restoration cannot erase history.
The separate semantic interpreter reconstructs facts from the event history.
The EXACT_EFFECT witness checker does not read the computed semantic bits.

The physical truth history is separate from acknowledgements, dedup replies,
stored snapshots and producer claims. All surrounding-contract violations are
classified explicitly before any proposed new axis. Full modeling bounds and
assumptions are included in the generated report and JSON.

Isolation: no repository, prior implementation, fixture, helper, model oracle or
other agent output was read. This is independent specification-only software
construction, not an independent external human laboratory.
