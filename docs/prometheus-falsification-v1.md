# Prometheus falsification v1

## Question

Does the Prometheus evidence contributor detect a failure mode that the Kubernetes-only Aegis path would otherwise allow?

## Hypothesis

For the same real KinD node and the same node-drain intent:

```text
Kubernetes NodeReady=True
→ Kubernetes-only Aegis preparation
→ ALLOW + signed permit
```

but if an independently declared Prometheus source reports the same node as unhealthy:

```text
Kubernetes NodeReady=True
+
Prometheus node health=unhealthy
→ evidence contradiction
→ BLOCK
→ no permit
```

If both paths produce the same decision, the Prometheus contributor has not demonstrated incremental decision value for this scenario.

## Test

The integration test:

```text
TestKindPrometheusFalsificationBlocksWhatKubernetesAloneWouldAllow
```

creates one synthetic Ready node in the real KinD API server.

It then evaluates the **same target** twice.

### Baseline

Aegis is constructed without the Prometheus contributor.

Expected result:

```text
decision: ALLOW
sources:  1
permit:   present
```

This establishes that the primary Kubernetes/StateLatch path has enough evidence to authorize the drain.

### Falsification path

A second Aegis server uses the same Kubernetes adapter and target, but also requires the Prometheus contributor.

The Prometheus test endpoint returns a fresh binary unhealthy sample.

Expected result:

```text
decision: BLOCK
reason:   EVIDENCE_CONTRADICTED
permit:   absent
```

The test finally reads the node again and requires that it remains schedulable, proving that this falsification scenario did not mutate infrastructure.

## What this proves

This proves an incremental **decision capability**:

> A second evidence domain can veto a permit that the Kubernetes-only evidence path would have issued.

It also proves that the veto happens before execution because no signed permit is minted.

## What this does not prove

The test Prometheus endpoint is controlled by the integration harness. It proves Aegis composition semantics, not real-world operational independence of a production Prometheus deployment.

A production claim of independence still requires a genuinely separate observability/data path. Merely querying a Prometheus instance that mirrors the same Kubernetes control-plane signal would not establish an independent failure domain.

## Falsification criterion

The feature should be considered falsified for this scenario if any of the following occurs:

- the Kubernetes-only baseline does not reach `ALLOW`;
- the contradictory Prometheus path still reaches `ALLOW`;
- a permit is minted after the contradiction;
- the target is mutated during the contradiction test.

This keeps the claim narrow and testable:

```text
Prometheus adds a pre-execution veto for a concrete contradiction
that Kubernetes-only preparation would not see.
```
