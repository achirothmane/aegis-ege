# Aegis-EGE evidence composition

Aegis-EGE evaluates a versioned composition profile before minting an execution permit.

The control path is:

```text
Execution Intent
→ primary Evidence Producer
→ zero or more Evidence Contributors
→ source declarations
→ evidence-composition/v1 assessment
→ ALLOW / BLOCK / ESCALATE
→ Evidence Manifest
→ signed state-bound permit
→ Execution Adapter
→ live revalidation
→ guarded mutation
→ outcome verification
```

## C09 claim boundary

A source name or trust-domain label is **not evidence of independence**.

The versioned composition contract is:

```text
aegis.ege/evidence-composition/v1
```

For each source, the profile can bind:

```text
producer_id
subject
observation_path
dependency_coverage[]
dependencies[] {
  kind
  id
  material
}
declaration assurance:
  UNKNOWN | ASSERTED | CORROBORATED
corroboration_refs[]
```

The subject is bound by the composer to the exact action target. Producers and
contributors do not submit an `independent=true` bit at runtime.

The manifest records a typed composition assessment:

```text
required_independence
independent_source_count
overall_independence
pair_assessments[]
```

Pair status is one of:

```text
DEPENDENT
UNKNOWN
ASSERTED
CORROBORATED
```

## What those statuses mean

### DEPENDENT

The profile found a dependency that defeats the stated independence claim, for
example:

- the same producer;
- the same observation path;
- a shared dependency marked material to the claim.

Different source names or different `trust_domain` strings cannot override
this result.

### UNKNOWN

The profile cannot establish the requested independence because a declaration
is missing, dependency coverage is incomplete, or declaration assurance is
unknown.

UNKNOWN may still be usable by a profile that only requires multiple named
sources. It cannot satisfy a policy that requires independent sources.

### ASSERTED

Both declarations cover the dependency classes required by the profile, use
different producers and observation paths, and have no shared material
dependency in that declared scope.

ASSERTED means exactly that: the profile owner supplied those declarations.
Aegis does not turn them into a claim of universal physical independence.

### CORROBORATED

CORROBORATED satisfies all ASSERTED conditions and both declarations are marked
`CORROBORATED` with non-empty corroboration references.

Those references are bound into the signed evidence manifest. Their presence
means the deployment profile says the declarations were reviewed/corroborated;
Aegis does not introduce a topology database or universal verifier for arbitrary
reference schemes.

## Material dependency scope

The profile explicitly declares the dependency classes it requires, for
example:

```text
upstream
credential
administrative
```

A source declaration must state that it covered every required class before it
can count toward an independence requirement.

Dependencies can also be declared as non-material for the profile's stated
claim. Two sources may legitimately share such a dependency without being
classified dependent for that particular claim.

Example:

```text
source A:
  upstream       = kubernetes-api       material
  credential     = kube-reader          material
  administrative = kubernetes-admin     material
  facility       = dc-1                 non-material

source B:
  upstream       = prometheus-store     material
  credential     = prometheus-reader    material
  administrative = observability-admin  material
  facility       = dc-1                 non-material
```

The shared facility is outside this profile's material independence claim. A
shared cache, upstream, credential, or administrative domain that is declared
material would make the pair DEPENDENT.

## Trust domains remain descriptive

`trust_domain` is retained for compatibility and operator visibility. Policies
may still require multiple trust-domain labels.

That is a label-diversity constraint only.

It does **not** satisfy:

```text
min_independent_sources
required_independence
```

Those fields are evaluated from the typed declaration/dependency predicate.

## Current Kubernetes + Prometheus behavior

Without a Prometheus contributor, the node-drain path remains a one-source
profile.

When Prometheus is configured without an independence profile, Aegis can still
require:

```text
two named sources
two distinct trust-domain labels
agreement on node health
```

but the signed composition assessment remains:

```text
required_independence = UNKNOWN
overall_independence  = UNKNOWN
independent_source_count = 0
```

That is intentionally the narrower claim.

To require independence, the operator supplies
`--prometheus-independence-profile=<json>`. The profile must declare both
`statelatch.kubernetes.node_drain` and `prometheus.node_health`, the
dependency classes that matter, and the required assurance level.

A profile asking for two ASSERTED or CORROBORATED independent sources fails
closed when that predicate is not established.

## Example bounded profile

```json
{
  "required_independence": "ASSERTED",
  "min_independent_sources": 2,
  "required_dependency_kinds": [
    "administrative",
    "credential",
    "upstream"
  ],
  "source_declarations": {
    "statelatch.kubernetes.node_drain": {
      "producer_id": "producer:kubernetes-node-drain",
      "observation_path": "path:kubernetes-api-live",
      "dependency_coverage": [
        "administrative",
        "credential",
        "upstream"
      ],
      "dependencies": [
        {
          "kind": "upstream",
          "id": "upstream:kubernetes-api",
          "material": true
        },
        {
          "kind": "credential",
          "id": "credential:kubernetes-reader",
          "material": true
        },
        {
          "kind": "administrative",
          "id": "admin:kubernetes",
          "material": true
        }
      ],
      "assurance": "ASSERTED"
    },
    "prometheus.node_health": {
      "producer_id": "producer:prometheus-node-health",
      "observation_path": "path:prometheus-query",
      "dependency_coverage": [
        "administrative",
        "credential",
        "upstream"
      ],
      "dependencies": [
        {
          "kind": "upstream",
          "id": "upstream:prometheus-store",
          "material": true
        },
        {
          "kind": "credential",
          "id": "credential:prometheus-reader",
          "material": true
        },
        {
          "kind": "administrative",
          "id": "admin:observability",
          "material": true
        }
      ],
      "assurance": "ASSERTED"
    }
  }
}
```

These identifiers are examples, not defaults. Deployments must declare their
actual material dependencies.

## Fail-closed semantics

The primary producer remains responsible for the exact action/state/plan binding
used by the execution adapter.

Contributors can strengthen or contradict that evidence.

If a configured contributor:

- returns `BLOCK`, the composition returns `BLOCK`;
- returns `ESCALATE`, the composition returns `ESCALATE`;
- fails to produce evidence, the composition returns
  `ESCALATE / INSUFFICIENT_EVIDENCE`;
- produces invalid ALLOW evidence, Aegis refuses permit minting;
- fails the named-source/label-diversity policy, Aegis escalates;
- fails a required independence predicate, Aegis escalates.

Contradiction retains its meaning. It is not converted into a weak
independence/insufficiency result.

## Bounded implementation

The current evaluator is deliberately small:

- no topology database;
- no universal producer registry service;
- no universal confidence score;
- no claim to enumerate every physical dependency;
- at most 16 composed sources per bounded assessment;
- exact maximum pairwise-qualifying source-set count is used for the configured
  independence threshold.

Older sources remain usable under profiles that do not require independence.

## Adversarial properties covered by C09

The test corpus verifies that:

- different labels over one material upstream do not become independent;
- different labels from the same producer do not become independent;
- a missing declaration remains UNKNOWN;
- ASSERTED cannot satisfy a CORROBORATED requirement;
- shared dependencies explicitly outside the material claim do not
  automatically defeat the narrower predicate;
- contradictory evidence still BLOCKs;
- multiple named sources can remain usable while the independence claim stays
  UNKNOWN.

The governing rule is:

> Evidence count and label diversity do not establish independent failure
> domains.
