# Four-Primitive Held-Out Generalization v16

Status: **non-normative post-minimality generalization experiment**

v12-v15 independently attempted to remove each member of the surviving basis:

```text
Identity
State
Attestation / Provenance Binding
Transition / Effect Identity
```

Every three-primitive reduction lost a distinction required by the modeled corpus.

v16 asks a different question:

> does the surviving four-primitive basis still compose on a post-freeze, previously unseen domain without adding a fifth semantic primitive?

## Held-out case

The case is the public D03-A Terraform incident:

```text
D03A-TFAWS-49231
hashicorp/terraform-provider-aws
```

The provider could successfully create an external Bedrock AgentCore memory strategy and then fail locally before recording the resulting object in Terraform state.

A second apply could therefore observe the same local state:

```text
strategy absent
```

and issue another create even though the first external effect may already have happened.

The safety distinction is:

```text
local state says absent
!=
proof that no external effect exists
```

## Four-primitive composition

The ordinary action is represented as:

```text
Identity
  service:terraform-provider-aws

State
  exact Terraform target revision / plan-bound local state

Attestation
  trusted state-bound admission decision

Transition
  create_strategy from exact current state to intended next state
```

Possible-effect custody is **not** a fifth primitive.

It is another State instance:

```text
governance.effect_custody
RESERVED -> CROSSING -> UNKNOWN -> CLOSED
```

and custody phase changes are ordinary Transition instances.

The executor/owner is another Identity instance.

Multiple instances of a primitive do not expand the semantic basis.

## Held-out failure sequence

v16 executes the relevant sequence:

```text
exact four-primitive admission
        ↓
custody = RESERVED
        ↓
effect boundary ALLOW
        ↓
custody = CROSSING
        ↓
provider may create external strategy
        ↓
local Terraform state write/response fails
        ↓
custody = UNKNOWN
        ↓
local business state still appears absent
        ↓
ordinary admission alone still appears admissible
        ↓
four-primitive boundary checks custody
        ↓
DENY second create
```

The important result is that the new domain does not require a semantic concept such as `OrphanedEffect`, `ProviderMutation`, `TerraformResource`, or `RetryToken` inside the kernel basis.

Those are domain/composite meanings built from the existing four.

## Effect identity

v16 also derives logical effect identity directly from the surviving semantic relations.

Material changes to subject, state revision, target, or operation/transition change the logical effect identity.

Changing only the trusted authorization path does not manufacture a different logical effect.

This preserves the distinction between who/what/state/effect and which trusted producer authorized the same effect.

## Executable checks

The experiment verifies:

- Terraform is not one of the original three primitive-reduction fixtures;
- the held-out Terraform proposal admits through the same four-primitive runtime surface;
- the basis remains exactly four primitives;
- possible-effect custody is ordinary State;
- custody phase changes are ordinary Transition;
- UNKNOWN custody blocks a second create even while local Terraform state still appears unchanged;
- UNKNOWN cannot become RESERVED merely because the caller retries;
- subject/state/target/operation substitutions fail closed;
- missing Attestation fails closed;
- material effect changes alter logical effect identity;
- authorization-path changes do not alter logical effect identity.

## Claim boundary

v16 does **not** prove global completeness or mathematical minimality.

It also does not turn the D03-A held-out corpus into independent implementation evidence.

The bounded claim is:

> after direct elimination testing of all four surviving primitives, a new infrastructure-provisioning failure mode can be represented and safely distinguished using only those four primitive types, with no domain-specific semantic primitive added to the kernel basis.

That is evidence of compositional generalization, not a universal proof.

This remains non-normative and does not modify frozen governed-action kernel v1 semantics.