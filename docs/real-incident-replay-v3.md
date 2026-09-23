# Real Incident Replay Benchmark v3

This benchmark uses public Kubernetes issue reports as replay sources. The goal is not to claim that KinD reproduces every production detail. Each replay isolates the safety invariant that matters to StateLatch and records the fidelity boundary explicitly.

## Replay 1 — workload appears on a drained / cordoned node

Source:

- https://github.com/kubernetes/kubernetes/issues/117843
- Kubernetes drain documentation also warns that Pods with an explicit `nodeName` can run on a drained node:
  https://kubernetes.io/docs/tasks/administer-cluster/safely-drain-node/

Incident class:

```
node drained / cordoned
→ a workload bypasses normal scheduler placement through spec.nodeName
→ workload exists on the supposedly drained node
```

Replay:

1. perform a real guarded StateLatch drain in KinD;
2. confirm the Node remains unschedulable;
3. create a new Pod with `spec.nodeName` pointing directly at that Node;
4. run postflight outcome observation.

Initial benchmark result:

```
StateLatch postflight → MATCH
```

This falsified the original postflight invariant because the implementation only checked that originally authorized Pod UIDs were absent.

Repair:

Postflight now also requires:

```
unexpected_workload_pods = 0
```

Terminal Pods, mirror/static Pods, and DaemonSet Pods remain excluded from this invariant because they have different drain semantics.

## Replay 2 — same name, different object identity

Source:

- https://github.com/kubernetes/kubernetes/issues/59848

The historical issue describes stale-read safety failures where object identity and stale state can violate Pod safety guarantees.

Incident class used by this replay:

```
authorization observes Pod name + UID A
→ Pod is deleted
→ same name is recreated with UID B
→ old authorization must not apply to replacement object
```

Replay:

1. prepare a state-bound drain authorization;
2. delete the authorized Pod;
3. recreate the same Pod name on the same Node;
4. verify the UID is different;
5. revalidate the original authorization.

Required result:

```
ESCALATE / EXECUTION_PLAN_CHANGED
```

## Replay 3 — cordon rejected but drain must not continue

Source:

- https://github.com/kubernetes/kubectl/issues/1568

The report describes a drain flow where the cordon operation was rejected by an admission webhook, yet Pod eviction continued.

Incident class:

```
cordon rejected
→ execution must stop
→ zero evictions
```

Replay fidelity:

The KinD replay uses the real StateLatch execution path and real Kubernetes Pods, but injects the cordon rejection at the mutation-executor boundary instead of installing a TLS admission webhook.

Required result:

```
ESCALATE / EXECUTION_CORDON_REJECTED
evictions = 0
```

## Interpretation

Benchmark v3 is source-backed but remains a controlled replay suite.

Passing a replay means the tested StateLatch invariant handles that incident class under the replayed conditions. It does not prove coverage of every variant of the original production incident.

A failing replay is treated as product evidence, not as a benchmark failure to hide. The first #117843 replay intentionally exposed a real StateLatch postflight gap before the repair was implemented.
