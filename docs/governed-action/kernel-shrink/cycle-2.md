# Kernel shrink cycle 2: retire the synthetic production package

Baseline: `2c2c35bb050d26d66a4579379df73b59d70e03c8` ([#237](https://github.com/achirothmane/aegis-ege/pull/237)).
Constitutional anchors remain [#235](https://github.com/achirothmane/aegis-ege/pull/235)
and [#236](https://github.com/achirothmane/aegis-ege/pull/236).

**Result:** the standalone module ships one fewer production package and 170
fewer production Go source lines. The retired code is an in-memory simulation
used exclusively by tests in this repository. Every executing runtime predicate,
destination check, verifier judgment and production policy relation remains exact.

| Standalone `governedaction` module | Before | After |
|---|---:|---:|
| Production packages | 3 | 2 |
| Production Go files | 9 | 8 |
| Production source lines, including comments/blanks | 1,720 | 1,550 |
| Production source bytes | 55,724 | 51,499 |
| Reference-runtime primitive types | 4 | 4 |
| Reference-runtime production lines | 955 | 955 |
| Race-tested test/subtest outcomes | 142 | 142 |

The change does not shrink a deployed consumer's transitive runtime TCB: no
production consumer in this repository imported the simulation before the move.
It reduces the module's shipped production surface and prevents its synthetic
monitor from silently becoming part of the governed execution implementation.
It proves neither semantic irreducibility nor a smaller primitive basis.

## Elimination decision

`governedaction/taintflow` explicitly described itself as a synthetic monotonic
model, not a production process monitor. Its only repository caller was the
Muse-class test corpus. The entire model now resides in
`governedaction/taint_fixture_test.go`; its three original tests reside in
`governedaction/taint_fixture_checks_test.go`.

The only model changes are its test-package namespace and private constructor
name. The corpus loses one import and calls that constructor directly. Fork,
write/read propagation, error identities, locking and label ordering are
unchanged. All sixteen M00-M15 cases retain their original classifications.

`CheckTaintEgress` stays in production. It checks trusted monitor bindings and
admitted labels; the fixture cannot replace the required monitor. Origin,
approval-use and credential-use checks also remain untouched. No currently
enforced relation is demoted to an untrusted input or removed from a live path.

The experimental simulation import path is retired. This is a source-level
breaking change for any external consumer importing that synthetic package;
the repository uses the unpublished local `v0.0.0` module and has no production
import of it. Every public API in `governedaction` and `governedaction/runtime`
is unchanged. No claim is made about unobserved external consumers.

## Preservation evidence

The new [fixture registration](../../../testdata/governed-action/kernel-shrink/fixture-demotion-v1.json)
pins the exact old/new files and production measurements. The source checker
first validates the immutable historical baselines and the complete #237 module.
It then permits only these two byte-preserving test moves, the exact caller
namespace change and an append-only README note. All other module entries must
match. Six new checker tests reject altered model/test bodies, a production
destination, missing original tests, changed corpus assertions, rewritten
historical documentation and false measurements or baseline pins.

The replay harness archives the actual #237 module into a temporary standalone
module and runs both complete suites with race detection. All 142 original
test/subtest outcomes pass without skips and match after the namespace move.
`go list` retires exactly the synthetic package; `go build ./...` passes without
it. The unchanged #236 runtime still matches all 176 output/call-order traces.
All ten existing source-removal trials still fail their intended regressions,
including custody retention and independently required EXACT_EFFECT.

[Local replay result](../../../testdata/governed-action/kernel-shrink/fixture-demotion-result-v1.json)
records these bounded checks. Native #235 CLOSED/UNKNOWN crash/succession,
independent #236 claim policy, destination fences, three-domain composition,
Terraform and KinD remain mandatory exact-head CI checks. These local results
do not substitute for native evidence or independent operator reproduction.

The local full-root test run cannot pass the Linux process/boot-identity cases:
this workspace does not expose `/proc/self/exe` or the kernel boot ID. The
portable, normative, primitive-reduction and shrink suites pass with race
detection. Host-dependent tests retain their existing requirements and must
pass on the native CI runner; no skip or surrogate identity is introduced.

Cycle-1 registrations and results, historical native registrations, freeze
manifests, normative/K07 oracles, and the signed-evidence verifier are not
rewritten. CI records fixture retirement separately from runtime shrinkage;
future changes anywhere in the module trigger the composite assurance gate.

The 170 production lines move into the test suite, rather than disappearing
from the repository. Proof tooling also grows: 70 added source-checker lines,
42 replay-harness lines and 76 checker-test lines, with small CI updates.
Those costs are separate from production measurements. No runtime dependency,
privilege, adapter requirement or semantic primitive is added.

## Stopping decision

Cycle 1's category remains **useful composition of known mechanisms**. This
cycle introduces no prior-art or novelty claim. It retires one demonstrably
test-only production component and stops there. Deleting still-live policy or
closure relations requires a separate executable alternative and preservation
evidence. Open #143/#181 remain independent work.
