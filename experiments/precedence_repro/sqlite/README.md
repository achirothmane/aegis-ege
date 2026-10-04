# Independent SQLite experiment

Only `specification.md` supplies semantics. The source imports only its own modules and the Python standard library. The SQLite implementation and storage-free replay oracle were written separately within this experiment; neither imports the other. This is software independence, not an independent external human laboratory.

Run the tests from this directory:

```sh
python -m unittest -v test_sqlite
```

Emit this experiment's complete JSON evidence and a brief report into a chosen directory:

```sh
python explore.py --output /path/to/output-directory --depth 5
```

Omit `--output` to emit result JSON to standard output. All paths are resolved relative to this experiment's own directory, not the original workspace. No packages need installing. Tested with Python/SQLite versions recorded in `results.json`.

The explorer uses native SQLite `BEGIN IMMEDIATE`/`COMMIT` for every operation, compares every transition against a separately represented replay oracle, discovers corners from resulting physical states, groups equal retained projections before examining omitted values, and enumerates all sixteen pair-to-Boolean functions. Minimal witness traces and all function counterexamples are included in JSON. The predicate is fixed for each profile.

The sixteen profiles compose four predicates (mutable target value, permanently retained event existence, erasable event existence, retained bytes with expiring validity) with an all-writer atomic exact-authority restriction and an exact attempt/executor creation restriction. One serial SQLite writer may serve many attempts. A logical operation key selects a deduplicated effect; it does not identify its causal attempt.

`crash_worker.py` uses `os._exit` after physical commit and before acknowledgement; the test runner reopens the WAL database and retries. A second test exits before commit and confirms no effect survived. The temporary databases are operational test artifacts, not preconstructed fixtures.

`focused.py` also tests adjacent revoke/commit serialization, generation ordering, restoration, exact scope mismatches, foreign origin, same-attempt/different-executor deduplication, target restoration, deletion, expiry and old observations. Explicit surrounding-obligation probes are labeled outside the fixed contract before considering any extra axis.

Read `evidence/report.md` for the frozen findings and limitations. `evidence/results.json` retains full original evidence. `SHA256SUMS` identifies the frozen sources and outputs.
