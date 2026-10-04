# Cycle 6: bounded three-obligation independence

Baseline: merged #241, `93b8fc2cd4ce89eafce08205843abd34c3d89a2f`.

Cycle 5 removed another representation without deleting a semantic relation:
the PostgreSQL profile no longer needs a separate mutable custody table or a
separate completion table. One physical business-effect row can carry the
stable effect key and exact causal completion.

The next question is therefore not another storage merge. It is whether the
three relations that still decide the independently required result can be
derived from one another.

This cycle tests the reduced native representation itself.

## Candidate basis

For the bounded `postgresql/native-fence/v1` + `EXACT_EFFECT` profile, the
three coordinates are:

1. **A — continuing authority at commitment**
2. **C — exact actual-attempt causal attribution**
3. **P — current required postcondition**

The experiment constructs one separating pair for each coordinate. In each
pair the other two retained projections are equal while the target coordinate
changes.

| Target relation | Fixed projection | Separating world |
| --- | --- | --- |
| A | exact physical cause + current required state | the same exact attempt/effect row exists and the required state holds, but authority was absent at physical commitment; current authority is restored afterward |
| C | trusted admission + current required state | the same requested claim, admission and state are present, but another valid attempt is the actual committer |
| P | trusted admission + exact physical cause | the exact admitted commit remains byte-identical while the target state changes later |

If all three pairs hold, no one of A, C or P is a deterministic function of the
other two projections in this profile.

That is stronger than saying that a particular field check is useful. It is a
bounded information-separation result.

## Native construction

`TestPostgresCompositeThreeObligationIndependence` runs against the same
reduced PostgreSQL path introduced by #241:

`physical business effect == immutable causal row`

There is still no separate mutable custody table and no separate completion
table.

### A is independent of C + P

The control uses the governed native executor and closes normally.

The separating world first makes continuing authority inactive, then commits
one genuine PostgreSQL business-effect row whose exact effect, attempt, owner,
transition and state projection match the control. The row records
`authority_active=false` truthfully. Present-time authority is then restored
before observation, so current authority cannot reveal the historical answer.

The independent consumer must keep the claim UNKNOWN and report invalid
authority-at-commit. Exact cause plus matching current state cannot manufacture
historical authority.

### C is independent of A + P

Both worlds have the same requested claim, admission relation, current state,
authority view and one logical effect.

In the separating world another valid execution attempt commits the effect.
The unified physical row retains that actual attempt and executor.

The independent consumer must reject the requested attempt's exact-effect
claim. Trusted admission plus matching current state cannot manufacture which
attempt caused the effect.

### P is independent of A + C

One admitted attempt commits normally and initially closes.

The target state is then changed independently. The physical causal row is
unchanged.

The independent consumer must retain exact historical causality and valid
authority-at-commit while refusing current CLOSED. Admission plus exact
historical cause cannot manufacture a current postcondition.

## What this proves

If the native cases pass, the strongest justified statement is:

> Within the tested PostgreSQL EXACT_EFFECT profile, A, C and P form a
> three-coordinate separating basis: none is derivable from the other two
> retained projections.

This does **not** prove a globally smallest universal theory. It does not prove
that every system needs three Go types, three tables, or three service objects.
#240 and #241 already show that several mechanisms and records can be collapsed
while the relations survive.

The distinction is important:

`minimum representations != minimum semantic information`

Cycle 6 is about the latter.

## Consequence for further reduction

A future two-relation kernel cannot be justified by merely merging records,
renaming fields, moving logic to an adapter, or selecting one of these
coordinates as a proxy for another. It must change the relied-on claim,
strengthen an external assumption enough to make one coordinate functionally
determined, or produce a new executable counterexample to this bounded
independence basis.

No production runtime or verifier change is introduced by this cycle.
