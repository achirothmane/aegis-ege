# Doctrine Epoch formal model v0.1

This directory contains the first executable state-machine model for the Level -2 doctrine lifecycle.

The model is deliberately small. It covers:

- a current doctrine epoch;
- frozen amendment visibility;
- threshold ratification;
- activation of a replacement epoch;
- compromised-epoch handling;
- emergency halt;
- quorum-gated restart;
- evidence / authority / sector admissibility before execution;
- append-only historical decision and constitutional logs.

## Checked properties

The TLC configuration asks the model checker to verify:

- TypeOK
- ExecutedOnlyWhenAdmissible
- AmendmentRequiresFrozenVisibility
- RestartRequiresIndependentQuorum
- DecisionHistoryAppendOnly
- AmendmentHistoryAppendOnly
- RestartHistoryAppendOnly
- NoNewActionUnderCompromisedEpoch

## Important boundary

A successful TLC run proves properties only for this finite abstract model and its configured state space.

It does not prove:

- physical hardware correctness;
- cryptographic implementation correctness;
- correctness of human doctrine choices;
- absence of implementation/refinement bugs;
- production safety.

The next formal step after this model stabilizes is a refinement mapping from implementation artifacts to these Level -2 / Level -1 state variables.
