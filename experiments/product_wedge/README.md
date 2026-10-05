# Product-wedge falsification (experiment only)

Pinned Aegis: `04434db12fa0c85d3497faf6ebb40df937092c5d`.
No production code, normative predicate or academic classification changes.

The destination is the existing Cycle 8 known-mechanism SQLite substitute.
The ten schedules use scoped atomic authority, stable operation identity,
an atomic business/origin row, fresh observation, an authenticated checkpoint,
and independently provisioned questions and roots. Actual child-process death,
database reopen, duplicate requests and concurrent SQLite writers are exercised.
Durable worker history is a minimal semantic representation, not an installation
of Temporal/Restate or a conformance implementation of AADP/AIP/AIDP.

The same recovered physical facts feed both the ordinary verifier and the
unchanged Aegis `aegis-evidence-inspect` executable built from the pinned main.
Aegis is tested as an evidence consumer; its executor is not claimed to have
performed these SQLite effects. Native enforcement is shared and credited to
the destination. The additional existing Go suites exercise the Aegis runtime.

History-signing succession is discharged through an ordinary dual-signed key
transition, independently installed by the relying party, on both sides. This
does not exercise or replace Aegis's internal Genesis/quorum succession profile.
That additional profile has different trust requirements and is not labeled
equivalent to this simpler, trusted-destination profile.

Run after building the pinned CLI:

```sh
python -B experiments/product_wedge/run.py --out /tmp/wedge \
  --aegis-binary /path/to/aegis-evidence-inspect
```

Without the binary, the script emits substitute results and Aegis inputs; it
explicitly marks the actual Aegis comparison as unexecuted. It never substitutes
a reimplementation of Aegis for its executable.

All keys in this fixture are deterministic PUBLIC TEST SEEDS. This experiment
does not claim independent organizations, protected signing processes, actual
vendor deployment times, production latencies or proof against a dishonest
destination. Supplementary controls test weak evidence, stale offline evidence,
key-transition substitution and trust-root separation.
