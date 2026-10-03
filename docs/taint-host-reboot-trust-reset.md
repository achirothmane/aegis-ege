# Host reboot trust-reset proof

This proof closes one narrow recovery boundary: a signed source-recovery authorization and pinned kernel coordination state from one Linux boot must not silently become authority on a later boot.

The CI schedule executes the same taint-native test in two separate disposable VM boots. Boot A creates a real eBPF array map, writes the exact signed recovery commitment into it, pins it under bpffs, and emits a signed recovery authorization bound to Boot A's hashed Linux boot identity. The VM then terminates.

Boot B starts from a newly booted kernel. The proof requires all of the following:

- the Linux boot identity differs from Boot A;
- the bpffs pin created by Boot A is absent rather than resurrected;
- the otherwise-valid Boot A recovery authorization is rejected specifically because its boot identity is stale;
- a newly signed authorization bound to Boot B is accepted by the same authorization verifier.

The invariant is therefore:

```text
Boot A authority + Boot A kernel state
            |
            v
       kernel reboot
            |
            v
Boot B != Boot A
old bpffs coordination absent
old boot-bound authorization DENY
fresh Boot-B-bound authorization required
```

This is an executable trust-reset proof, not a claim that full source continuity automatically survives a host failure. It intentionally treats a reboot as an authority discontinuity.

## Claim boundary

This proof does not yet establish full post-reboot source re-enrollment and effect restoration, persistent recovery receipts across a real disk-backed machine restart, TPM-backed boot continuity, distributed recovery authority, or recovery across a physical host replacement. Those require separate evidence and must not be inferred from this test.
