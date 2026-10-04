# Specification-only reproduction and known-mechanism substitute

The two isolated producers received only `specification.md`. They were not
given the existing repository, Cycle 7 report, implementation, fixtures, result
oracles or expected corner set. The parent compared their results only after
their source and outputs were frozen. `substitute.py` is a separate parent-built
prior-art reconstruction and is not counted as a clean-room producer.

Frozen specification SHA-256:
`50e59249ff4fa50300ec9df39228b960acaf1a5e6a01513b1f3d8452f1ae12ac`.
The registration in
`testdata/governed-action/kernel-shrink/independent-reproduction-v1.json`
records source hashes, execution interfaces and post-freeze profile mapping.
Neither producer imports the registration or receives its comparison results.

From the repository root, with Python 3.12, Node 24 and the experiment-only
`cryptography==46.0.0` dependency available:

```sh
python3 -B scripts/run_independent_reproduction.py --out /tmp/independent-reproduction
```

The runner preserves every original repository blob, executes each isolated
producer's tests and exploration, then runs the substitute and the original
reference model. It records raw evidence, all sixteen pair-function checks,
profile comparisons, disagreements and production fingerprints. A disagreement
fails the comparison while preserving evidence. Source pinning also fails if a
frozen implementation changes; retain the original revision before investigating
any scientific disagreement.

These are independently written software realizations in one orchestrated run,
with finite bounds and trusted fixture boundaries. They are not an external human
laboratory, a hardware immutability result or a complete production replacement.
The full conclusions and limits are in
`docs/governed-action/kernel-shrink/cycle-8.md`.
