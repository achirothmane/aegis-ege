# D04 executable extraction evidence

Validated source: `2ca871652eabab06392ec91665a57392bbd7a6c6`.
The evidence-preservation commit adds these records and documentation only;
compiled sources, dependency files, registrations and expected results are
unchanged from the validated source.

| Validation | Run | Result |
| --- | --- | --- |
| Standalone library race tests; native CRM/decision and frozen vectors | [36803946462](https://github.com/achirothmane/aegis-ege/actions/runs/36803946462) | PASS, source/worktree immutable |
| Actual PostgreSQL gosmig schedules and unchanged K07 mapping | [36803946466](https://github.com/achirothmane/aegis-ege/actions/runs/36803946466) | PASS, 13 native cases / 11 mappings |
| Full repository unit/BPF checks and real KinD integration | [36803946447](https://github.com/achirothmane/aegis-ege/actions/runs/36803946447) | PASS, both jobs |

[closeout.json](closeout.json) retains the scope, source hashes, registered CRM
fault assertions, frozen blob identities, workflow IDs and artifact digests.
[source-provenance.json](source-provenance.json) was emitted by the immutable
workflow. [native-postgresql.json](native-postgresql.json) preserves actual native
database/custody observations; [native-k07-result.json](native-k07-result.json)
preserves the unchanged mappings. Raw Go test events remain in
[library-tests.jsonl](library-tests.jsonl) and
[adapter-and-frozen-tests.jsonl](adapter-and-frozen-tests.jsonl).

The five new CRM fault schedules assert zero PATCH requests and inspect the
durable file-store state after reopening, then reject a blind replay. Existing
positive execution, lost-reply and post-expiry read-only recovery also pass.
The four additive frozen-vector bridges cover only the extracted revision and
custody relations; all 28 original K07 vectors still use the unchanged evaluator.

Initial formatting and checksum-normalization attempts are disclosed in
[validation-metadata.json](validation-metadata.json). Their expected results were
not edited; final verification used committed sources and pinned dependencies.

Classification remains **PROVISIONAL_IMPLEMENTED_TESTED**. The owner-authorized
D03 development assumption is not independent validation. Native simulation
evidence still explicitly records `d03_pass: false` and no independent
participation. [D04 scope and limitations](../d04-shared-library.md) applies.
