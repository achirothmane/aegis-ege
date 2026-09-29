# Aegis-EGE evidence producers

Aegis-EGE separates **evidence production** from **execution adaptation**.

The control path is now:

```text
Execution Intent
→ Evidence Producer Registry
→ primary Evidence Producer
→ Evidence Contributors
→ composition policy
→ ALLOW / BLOCK / ESCALATE
→ Evidence Manifest
→ signed state-bound permit
→ Execution Adapter Registry
→ Execution Adapter
→ live revalidation
→ guarded mutation
→ outcome verification
```

## Why split these roles

An execution adapter answers:

> How is this exact infrastructure action authorized and executed safely?

An evidence producer answers:

> What current evidence justifies allowing this exact action against this exact state?

Those are different responsibilities.

Keeping them separate prevents future infrastructure adapters from silently becoming the sole authority for both evidence generation and mutation. It also gives Aegis-EGE a place to compose stronger evidence sources later without changing the public execution protocol.

## Reference producer

The first producer is still backed by the already-tested StateLatch Kubernetes node-drain preparation path.

It produces:

- the decision: `ALLOW / BLOCK / ESCALATE`;
- reason codes;
- authoritative observation time;
- resource-version binding;
- StateLatch evidence digest;
- deterministic plan digest;
- short-lived permit binding;
- evidence classes for authoritative Kubernetes state, PDB preflight, and server-side dry-run.

The matching execution adapter no longer prepares evidence. It only:

- reconstructs the internal StateLatch authorization from a verified Aegis permit;
- performs the guarded node-drain execution;
- relies on StateLatch live revalidation, locking, checkpointing, and outcome verification.

## Fail-closed producer contract

Aegis validates producer output before it can mint a permit.

For `ALLOW`, the producer must provide:

- a non-zero observation time;
- at least one evidence class;
- action binding;
- resource/state version;
- evidence digest;
- deterministic plan digest;
- an expiry after the observation time.

The plan digest exposed by the production result must match the digest inside the permit binding.

A non-`ALLOW` result is forbidden from carrying a permit binding.

Therefore a buggy future producer cannot accidentally return `BLOCK` or `ESCALATE` together with data that Aegis would sign into an execution permit.

## Composition boundary

The primary producer is no longer assumed to be the entire evidence universe.

Aegis can compose its output with additional named contributors, each carrying
a trust-domain label, digest, observation time, and evidence classes.

Source count and trust-domain labels are not treated as proof of independence.
When a policy requires independent failure domains, the
`aegis.ege/evidence-composition/v1` profile additionally binds producer id,
subject, observation path, material dependency coverage and declaration
assurance. The independence predicate—not label count—then determines whether
the stronger policy is satisfied.

The current Kubernetes production policy intentionally remains one-source:

```text
statelatch.kubernetes.node_drain
→ trust domain: kubernetes-control-plane
```

Multi-source behavior is exercised with synthetic contributors in tests.
C09 distinguishes ordinary multi-source corroboration from ASSERTED or
CORROBORATED independence. A real Prometheus contributor may be configured,
but its independence remains UNKNOWN unless the operator supplies the bounded
dependency declaration profile required for that stronger claim.

See [evidence-composition.md](evidence-composition.md) for the composition contract and fail-closed semantics.

## Next proof gate

The next production evidence source must earn its place by covering a failure mode outside the existing Kubernetes control-plane trust domain.

Candidate classes include independent telemetry, deterministic simulation, policy attestation, and formal verification. A source is not valuable merely because it is technically different; it must add independent decision information.
