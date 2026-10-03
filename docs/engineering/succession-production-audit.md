# Succession production-path audit

Inspected baseline: `ffd5a5bcd6eb9d3d6ce9200d28d368b7cbb6e6e2` (#232 merged). #230 is reconciled separately.

Roadmap candidate #233 classification: **library-capable but not yet orchestrated**.

`ParseHistorySuccessionEpochs` has only test callers in `internal/genesisbootstrap/verified_genesis_pin_test.go`. `ExecuteGovernedHistorySuccession` has only journal/server proof callers. `ExecuteQuorumRotation` is consumed by library succession protocols and proof tests, not a runtime command or server handler. Production quorum provisioning derives its binding from a verified Genesis pin, but provisioning is not a succession orchestration boundary.

#232's co-bound history/quorum constructor is useful and verified; it is not evidence that production succession is wired. No artificial caller or wrapper was added for #233. When a real production succession boundary is implemented it must obtain epochs from verified pins and reject detached configuration before mutation.

This phase strengthens #230's actual library composition boundaries: signed manifest provenance, exact envelope equality, exact predecessor, transition identity retained after activation, and native policy-fenced convergence. It does not add a runtime succession feature or promise TPM commitment fencing.
