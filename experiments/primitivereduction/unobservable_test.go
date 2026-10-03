package primitivereduction

import "testing"

func unknownCustodyForFixture(t *testing.T, fixture domainFixture) (Proposal, StateRef) {
	t.Helper()
	proposal := fixture.new()
	executor := Identity{ID: "executor:" + fixture.name, Kind: "process"}
	reserved, err := PrepareEffectCustody(proposal, executor, "001")
	if err != nil {
		t.Fatal(err)
	}
	crossing, err := AdvanceEffectCustody(reserved, CustodyCrossing)
	if err != nil {
		t.Fatal(err)
	}
	unknown, err := AdvanceEffectCustody(crossing.To, CustodyUnknown)
	if err != nil {
		t.Fatal(err)
	}
	return proposal, unknown.To
}

func providerContractFor(t *testing.T, proposal Proposal, custody StateRef, dedup, finalObservation bool) ProviderContract {
	t.Helper()
	effectID, err := EffectIdentity(proposal)
	if err != nil {
		t.Fatal(err)
	}
	contract := ProviderContract{
		ProviderID:               "provider:test",
		SupportsAtomicDedup:       dedup,
		SupportsFinalObservation: finalObservation,
		Evidence: Evidence{
			ID:          "provider-contract",
			Type:        "provider-semantics-attestation",
			StateDigest: custody.Digest,
			Valid:       true,
		},
	}
	if dedup {
		contract.IdempotencyKey = effectID
	}
	return contract
}

func TestOpaqueProviderCreatesIndistinguishableRecoveryWorlds(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal, custody := unknownCustodyForFixture(t, fixture)
			contract := providerContractFor(t, proposal, custody, false, false)

			// World A: provider applied the effect, response was lost.
			appliedWorld := EvaluateUnknownRecovery(proposal, custody, contract, nil)

			// World B: provider never applied the effect, response was lost.
			// The kernel sees exactly the same local inputs because the provider
			// exposes neither atomic dedup nor final observation.
			absentWorld := EvaluateUnknownRecovery(proposal, custody, contract, nil)

			if appliedWorld != RecoveryStopUnknown || absentWorld != RecoveryStopUnknown {
				t.Fatalf("opaque provider must remain STOP_UNKNOWN in indistinguishable worlds: applied=%s absent=%s", appliedWorld, absentWorld)
			}
		})
	}
}

func TestAtomicDedupMakesSameEffectRetrySafe(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal, custody := unknownCustodyForFixture(t, fixture)
			contract := providerContractFor(t, proposal, custody, true, false)

			if got := EvaluateUnknownRecovery(proposal, custody, contract, nil); got != RecoveryRetrySameEffect {
				t.Fatalf("atomic dedup should permit retry of the same logical effect, got %s", got)
			}

			contract.IdempotencyKey = "wrong-effect-id"
			if got := EvaluateUnknownRecovery(proposal, custody, contract, nil); got != RecoveryStopUnknown {
				t.Fatalf("wrong dedup key must not permit retry, got %s", got)
			}
		})
	}
}

func TestFinalProviderObservationCanResolveUnknown(t *testing.T) {
	for _, fixture := range fixtures() {
		t.Run(fixture.name, func(t *testing.T) {
			proposal, custody := unknownCustodyForFixture(t, fixture)
			contract := providerContractFor(t, proposal, custody, false, true)
			effectID, err := EffectIdentity(proposal)
			if err != nil {
				t.Fatal(err)
			}

			applied := ProviderObservation{
				EffectID: effectID,
				Status:   ProviderApplied,
				Evidence: Evidence{
					ID:          "provider-observation-applied",
					Type:        "provider-final-observation",
					StateDigest: custody.Digest,
					Valid:       true,
				},
			}
			if got := EvaluateUnknownRecovery(proposal, custody, contract, &applied); got != RecoveryCloseApplied {
				t.Fatalf("final APPLIED observation should close, got %s", got)
			}
			closed, err := ApplyRecoveryObservation(proposal, custody, contract, applied)
			if err != nil {
				t.Fatalf("apply APPLIED observation: %v", err)
			}
			if closed.To.Facts[factCustodyPhase] != CustodyClosed {
				t.Fatalf("APPLIED observation did not close custody: %+v", closed.To)
			}

			absent := ProviderObservation{
				EffectID: effectID,
				Status:   ProviderAbsent,
				Evidence: Evidence{
					ID:          "provider-observation-absent",
					Type:        "provider-final-observation",
					StateDigest: custody.Digest,
					Valid:       true,
				},
			}
			if got := EvaluateUnknownRecovery(proposal, custody, contract, &absent); got != RecoveryRetrySameEffect {
				t.Fatalf("final ABSENT observation should permit same-effect retry, got %s", got)
			}
			if _, err := ApplyRecoveryObservation(proposal, custody, contract, absent); err == nil {
				t.Fatal("ABSENT observation must not be converted into CLOSED")
			}
		})
	}
}

func TestNonFinalObservationNeverManufacturesClosure(t *testing.T) {
	proposal, custody := unknownCustodyForFixture(t, fixtures()[0])
	contract := providerContractFor(t, proposal, custody, false, false)
	effectID, err := EffectIdentity(proposal)
	if err != nil {
		t.Fatal(err)
	}
	observation := ProviderObservation{
		EffectID: effectID,
		Status:   ProviderApplied,
		Evidence: Evidence{
			ID:          "non-final-provider-read",
			Type:        "best-effort-provider-read",
			StateDigest: custody.Digest,
			Valid:       true,
		},
	}

	if got := EvaluateUnknownRecovery(proposal, custody, contract, &observation); got != RecoveryStopUnknown {
		t.Fatalf("non-final observation must not manufacture certainty, got %s", got)
	}
}

func TestStaleProviderSemanticsFailClosed(t *testing.T) {
	proposal, custody := unknownCustodyForFixture(t, fixtures()[1])
	contract := providerContractFor(t, proposal, custody, true, true)
	contract.Evidence.StateDigest = "sha256:stale"

	if got := EvaluateUnknownRecovery(proposal, custody, contract, nil); got != RecoveryStopUnknown {
		t.Fatalf("stale provider contract must fail closed, got %s", got)
	}
}

func TestObservationForAnotherEffectCannotResolveCustody(t *testing.T) {
	proposal, custody := unknownCustodyForFixture(t, fixtures()[2])
	contract := providerContractFor(t, proposal, custody, false, true)

	observation := ProviderObservation{
		EffectID: "another-logical-effect",
		Status:   ProviderApplied,
		Evidence: Evidence{
			ID:          "wrong-effect-observation",
			Type:        "provider-final-observation",
			StateDigest: custody.Digest,
			Valid:       true,
		},
	}
	if got := EvaluateUnknownRecovery(proposal, custody, contract, &observation); got != RecoveryStopUnknown {
		t.Fatalf("foreign effect observation resolved custody: %s", got)
	}
}

func TestUnobservableBoundaryStillUsesSixPrimitives(t *testing.T) {
	got := CandidatePrimitives()
	if len(got) != 6 {
		t.Fatalf("unobservable-effect experiment expanded primitive basis: %v", got)
	}
	for _, forbidden := range []Primitive{
		"provider_contract",
		"idempotency",
		"exactly_once",
		"observation_finality",
		"recovery_action",
		"effect_identity",
	} {
		for _, primitive := range got {
			if primitive == forbidden {
				t.Fatalf("%q must remain derived/provider semantics in v6", forbidden)
			}
		}
	}
}
