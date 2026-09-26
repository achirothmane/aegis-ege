# Aegis-EGE evidence producers

Aegis-EGE separates **evidence production** from **execution adaptation**.

The control path is now:

```text
Execution Intent
→ Evidence Producer Registry
→ Evidence Producer
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

## What this does not claim yet

This change does not yet compose multiple independent producers for one intent.

There is currently one registered producer for:

```text
kubernetes.node_drain
```

The architectural boundary now exists for later evidence sources such as:

```text
StateLatch runtime evidence
+ independent telemetry
+ deterministic simulation
+ formal/policy attestations
```

but those sources should only be added when a concrete safety or market requirement justifies them.

## Next proof gate

Before adding a second evidence source, prove that:

1. producer output cannot mint a permit unless all generic binding invariants hold;
2. the existing KinD end-to-end path still succeeds;
3. stale or changed Kubernetes state still invalidates execution after permit issuance;
4. execution adapters remain unable to bypass the evidence-production stage through the public EGE API.

Only then should Aegis move from one producer per intent toward multi-producer evidence composition.
