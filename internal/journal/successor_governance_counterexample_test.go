package journal

import (
	"errors"
	"testing"
)

func TestVCS14RejectsMixedGenesisProvenance(t *testing.T) {
	for _, field := range []string{"envelope", "manifest"} {
		t.Run(field, func(t *testing.T) {
			f := newVCS14RotationFixture(t)
			plan := f.plan
			if field == "envelope" {
				plan.oldEpoch.binding.capabilityEnvelopeHash = sha256Digest([]byte("different envelope"))
			} else {
				plan.oldEpoch.genesisManifestHash = sha256Digest([]byte("different manifest"))
			}
			if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, f.signed, f.oldBinding, f.newBinding, plan, f.oldStore, f.newStore, f.now); err == nil {
				t.Fatal("accepted quorum provenance from a different Genesis source")
			}
			for _, store := range f.stores {
				head, err := store.base.Load(f.ctx, f.oldHead.JournalID)
				if err != nil || !sameSemanticHead(head, f.oldHead) {
					t.Fatalf("mixed Genesis provenance mutated a witness before rejection: head=%+v err=%v", head, err)
				}
			}
		})
	}
}

func TestVCS14ResumesInterruptedQuorumWithoutDualAuthority(t *testing.T) {
	for _, phase := range []string{"freeze", "activate"} {
		t.Run(phase, func(t *testing.T) {
			f := newVCS14RotationFixture(t)
			if phase == "freeze" {
				f.stores["witness-c"].failJoint = 1
			} else {
				f.stores["witness-c"].failActive = 1
				f.stores["witness-c"].failActiveHash = f.plan.newEpoch.PolicyHash()
			}
			if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, f.signed, f.oldBinding, f.newBinding, f.plan, f.oldStore, f.newStore, f.now); err == nil {
				t.Fatal("expected interruption")
			}
			for _, pair := range []struct {
				store   *QuorumHeadStore
				binding GenesisEnrollmentSuccessorGovernanceBinding
			}{{f.oldStore, f.oldBinding}, {f.newStore, f.newBinding}} {
				if _, err := RequireActiveSuccessorGovernanceAuthority(f.ctx, pair.store, f.oldHead.JournalID, pair.binding); err == nil {
					t.Fatal("authority became current during interrupted freeze/handoff")
				}
			}
			if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, f.signed, f.oldBinding, f.newBinding, f.plan, f.oldStore, f.newStore, f.now); err != nil {
				t.Fatal(err)
			}
			if _, err := RequireActiveSuccessorGovernanceAuthority(f.ctx, f.newStore, f.oldHead.JournalID, f.newBinding); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestVCS14RejectsManifestAndSequenceSubstitution(t *testing.T) {
	f := newVCS14RotationFixture(t)
	wrong := f.signed
	wrong.Authorization.OldGenesisManifestHash = sha256Digest([]byte("other manifest"))
	wrong.OldApproval, _ = SignSuccessorGovernanceRotationApproval(wrong.Authorization, f.oldPrivate)
	wrong.NewApproval, _ = SignSuccessorGovernanceRotationApproval(wrong.Authorization, f.newPrivate)
	if err := VerifySignedSuccessorGovernanceRotation(wrong, f.oldBinding, f.newBinding, f.now); !errors.Is(err, ErrSuccessorGovernanceRotation) {
		t.Fatalf("co-signatures admitted a different manifest: %v", err)
	}
	exhausted := f.signed.Authorization
	exhausted.PreviousSequence = ^uint64(0)
	if err := ValidateSuccessorGovernanceRotationAuthorization(exhausted); err == nil {
		t.Fatal("authority sequence wrapped")
	}
}

func TestVCS14RejectsDifferentTransitionAfterCompletion(t *testing.T) {
	f := newVCS14RotationFixture(t)
	// Make the original transition deterministic independently of the
	// majority-convergence scheduling bug: all old witnesses retain the freeze.
	frozen, err := FreezeSuccessorGovernanceAuthority(f.ctx, f.oldStore, f.signed, f.oldBinding, f.newBinding, f.now)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"witness-a", "witness-b", "witness-c"} {
		current, err := f.stores[id].base.Load(f.ctx, f.oldHead.JournalID)
		if err != nil {
			t.Fatal(err)
		}
		if !sameSemanticHead(current, frozen) {
			if _, err := f.stores[id].base.CompareAndAdvance(f.ctx, current, frozen); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, f.signed, f.oldBinding, f.newBinding, f.plan, f.oldStore, f.newStore, f.now); err != nil {
		t.Fatal(err)
	}
	other := f.signed
	other.Authorization.RotationID = "different-but-validly-signed-transition"
	other.OldApproval, err = SignSuccessorGovernanceRotationApproval(other.Authorization, f.oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	other.NewApproval, err = SignSuccessorGovernanceRotationApproval(other.Authorization, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ExecuteSuccessorGovernanceCrossGenesisRotation(f.ctx, other, f.oldBinding, f.newBinding, f.plan, f.oldStore, f.newStore, f.now); err == nil {
		t.Fatal("claimed completion for a transition that never froze or committed")
	}
}
