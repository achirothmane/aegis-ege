package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

type vcs14RotationFixture struct {
	ctx        context.Context
	now        time.Time
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding
	newBinding GenesisEnrollmentSuccessorGovernanceBinding
	oldPrivate ed25519.PrivateKey
	newPrivate ed25519.PrivateKey
	plan       QuorumRotationPlan
	oldStore   *QuorumHeadStore
	newStore   *QuorumHeadStore
	stores     map[string]*rotationPolicyTestStore
	signed     SignedSuccessorGovernanceRotation
	oldHead    ExternalHead
}

func newVCS14RotationFixture(t *testing.T) vcs14RotationFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 10, 3, 8, 40, 0, 0, time.UTC)
	oldPublic, oldPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newPublic, newPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	oldEnvelope := vcs14CombinedEnvelope(
		t,
		oldPublic,
		2,
		"witness-a",
		"witness-b",
		"witness-c",
	)
	newEnvelope := vcs14CombinedEnvelope(
		t,
		newPublic,
		2,
		"witness-b",
		"witness-c",
		"witness-d",
	)
	oldEnvelopeHash := sha256Digest(oldEnvelope)
	newEnvelopeHash := sha256Digest(newEnvelope)
	oldQuorumBinding, err := ParseGenesisQuorumBinding(oldEnvelope, oldEnvelopeHash)
	if err != nil {
		t.Fatal(err)
	}
	newQuorumBinding, err := ParseGenesisQuorumBinding(newEnvelope, newEnvelopeHash)
	if err != nil {
		t.Fatal(err)
	}
	oldBinding, err := ParseGenesisEnrollmentSuccessorGovernanceBinding(
		oldEnvelope,
		oldEnvelopeHash,
		41,
	)
	if err != nil {
		t.Fatal(err)
	}
	newBinding, err := ParseGenesisEnrollmentSuccessorGovernanceBinding(
		newEnvelope,
		newEnvelopeHash,
		42,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldEpoch, err := NewGovernedQuorumEpoch(
		oldQuorumBinding,
		41,
		sha256Digest([]byte("vcs14-genesis-41")),
	)
	if err != nil {
		t.Fatal(err)
	}
	newEpoch, err := NewGovernedQuorumEpoch(
		newQuorumBinding,
		42,
		sha256Digest([]byte("vcs14-genesis-42")),
	)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := NewQuorumRotationPlan(oldEpoch, newEpoch)
	if err != nil {
		t.Fatal(err)
	}

	oldHead, err := activeSuccessorGovernanceHead(
		oldBinding,
		SuccessorGovernanceAuthorityJournalID,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}
	oldPolicy := oldEpoch.activePolicy()
	newPolicy := newEpoch.activePolicy()
	stores := map[string]*rotationPolicyTestStore{
		"witness-a": newRotationPolicyTestStore(
			oldHead,
			quorumTrustHashForTest("witness-a"),
			oldPolicy,
		),
		"witness-b": newRotationPolicyTestStore(
			oldHead,
			quorumTrustHashForTest("witness-b"),
			oldPolicy,
		),
		"witness-c": newRotationPolicyTestStore(
			oldHead,
			quorumTrustHashForTest("witness-c"),
			oldPolicy,
		),
		"witness-d": newRotationPolicyTestStore(
			oldHead,
			quorumTrustHashForTest("witness-d"),
			newPolicy,
		),
	}
	oldStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-a", Store: stores["witness-a"]},
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
		},
		oldQuorumBinding,
		41,
	)
	if err != nil {
		t.Fatal(err)
	}
	newStore, err := NewGovernedQuorumHeadStore(
		[]QuorumHeadMember{
			{ID: "witness-b", Store: stores["witness-b"]},
			{ID: "witness-c", Store: stores["witness-c"]},
			{ID: "witness-d", Store: stores["witness-d"]},
		},
		newQuorumBinding,
		42,
	)
	if err != nil {
		t.Fatal(err)
	}

	auth, err := NewSuccessorGovernanceRotationAuthorization(
		"vcs14-a-to-b",
		SuccessorGovernanceAuthorityJournalID,
		0,
		oldBinding,
		newBinding,
		now.Add(-time.Minute),
		now.Add(10*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	oldApproval, err := SignSuccessorGovernanceRotationApproval(auth, oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newApproval, err := SignSuccessorGovernanceRotationApproval(auth, newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	signed := SignedSuccessorGovernanceRotation{
		Authorization: auth,
		OldApproval:   oldApproval,
		NewApproval:   newApproval,
	}
	if err := VerifySignedSuccessorGovernanceRotation(
		signed,
		oldBinding,
		newBinding,
		now,
	); err != nil {
		t.Fatal(err)
	}

	return vcs14RotationFixture{
		ctx:        ctx,
		now:        now,
		oldBinding: oldBinding,
		newBinding: newBinding,
		oldPrivate: oldPrivate,
		newPrivate: newPrivate,
		plan:       plan,
		oldStore:   oldStore,
		newStore:   newStore,
		stores:     stores,
		signed:     signed,
		oldHead:    oldHead,
	}
}

func TestVCS14CrossGenesisSuccessorGovernanceRotationHasNoDualAuthorityWindow(t *testing.T) {
	f := newVCS14RotationFixture(t)

	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		SuccessorGovernanceAuthorityJournalID,
		f.oldBinding,
	); err != nil {
		t.Fatalf("old authority not active before rotation: %v", err)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
		f.newBinding,
	); err == nil {
		t.Fatal("new authority became active before freeze/quorum handoff")
	}

	frozen, err := FreezeSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.Sequence != 1 {
		t.Fatalf("frozen sequence=%d want=1", frozen.Sequence)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		SuccessorGovernanceAuthorityJournalID,
		f.oldBinding,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("old authority remained active during JOINT_FROZEN: %v", err)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		SuccessorGovernanceAuthorityJournalID,
		f.newBinding,
	); err == nil {
		t.Fatal("new authority activated on old Genesis quorum")
	}
	if _, err := ActivateSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.now,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("new authority activated before quorum handoff: %v", err)
	}

	result, err := ExecuteSuccessorGovernanceCrossGenesisRotation(
		f.ctx,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.plan,
		f.oldStore,
		f.newStore,
		f.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.ActiveHead.Sequence != 2 ||
		!validSHA256Digest(result.AuthorityTransitionHash) ||
		!validSHA256Digest(result.QuorumTransitionHash) {
		t.Fatalf("unexpected rotation result: %+v", result)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
		f.newBinding,
	); err != nil {
		t.Fatalf("new authority not active after rotation: %v", err)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
		f.oldBinding,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("old authority resurrected under new Genesis: %v", err)
	}
	if _, err := f.oldStore.Load(
		f.ctx,
		SuccessorGovernanceAuthorityJournalID,
	); !errors.Is(err, ErrExternalHeadQuorum) {
		t.Fatalf("retired old quorum remained authoritative: %v", err)
	}

	replayed, err := ExecuteSuccessorGovernanceCrossGenesisRotation(
		f.ctx,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.plan,
		f.oldStore,
		f.newStore,
		f.now,
	)
	if err != nil {
		t.Fatalf("completed rotation was not idempotent: %v", err)
	}
	if !sameSemanticHead(replayed.ActiveHead, result.ActiveHead) {
		t.Fatalf("rotation replay changed active authority: got=%+v want=%+v", replayed.ActiveHead, result.ActiveHead)
	}
}

func TestVCS14CrashAfterQuorumHandoffResumesOnlyExactFrozenTransition(t *testing.T) {
	f := newVCS14RotationFixture(t)

	frozen, err := FreezeSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	qr, err := ExecuteQuorumRotation(
		f.ctx,
		f.plan,
		f.oldStore,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if !sameSemanticHead(qr.Head, frozen) {
		t.Fatalf("quorum handoff changed frozen authority head: got=%+v want=%+v", qr.Head, frozen)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
		f.newBinding,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("new authority active before post-crash resume: %v", err)
	}

	result, err := ExecuteSuccessorGovernanceCrossGenesisRotation(
		f.ctx,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.plan,
		f.oldStore,
		f.newStore,
		f.now,
	)
	if err != nil {
		t.Fatalf("resume from migrated JOINT_FROZEN failed: %v", err)
	}
	if _, err := RequireActiveSuccessorGovernanceAuthority(
		f.ctx,
		f.newStore,
		SuccessorGovernanceAuthorityJournalID,
		f.newBinding,
	); err != nil {
		t.Fatalf("resumed transition did not activate exact new authority: %v", err)
	}
	if result.ActiveHead.Sequence != 2 {
		t.Fatalf("resumed active sequence=%d want=2", result.ActiveHead.Sequence)
	}
}

func TestVCS14RotationRequiresBothExactOldAndNewAuthorityApprovals(t *testing.T) {
	f := newVCS14RotationFixture(t)

	missingNew := f.signed
	missingNew.NewApproval = SuccessorGovernanceRotationApproval{}
	if err := VerifySignedSuccessorGovernanceRotation(
		missingNew,
		f.oldBinding,
		f.newBinding,
		f.now,
	); err == nil {
		t.Fatal("old authority alone authorized rotation")
	}

	missingOld := f.signed
	missingOld.OldApproval = SuccessorGovernanceRotationApproval{}
	if err := VerifySignedSuccessorGovernanceRotation(
		missingOld,
		f.oldBinding,
		f.newBinding,
		f.now,
	); err == nil {
		t.Fatal("new authority self-appointed without old authority approval")
	}

	_, unrelatedPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongNew := f.signed
	wrongNew.NewApproval, err = SignSuccessorGovernanceRotationApproval(
		f.signed.Authorization,
		unrelatedPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedSuccessorGovernanceRotation(
		wrongNew,
		f.oldBinding,
		f.newBinding,
		f.now,
	); err == nil {
		t.Fatal("unrelated new authority signature was accepted")
	}
}

func TestVCS14RejectsStalePredecessorAndDifferentTransitionAfterFreeze(t *testing.T) {
	f := newVCS14RotationFixture(t)

	if _, err := FreezeSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		f.signed,
		f.oldBinding,
		f.newBinding,
		f.now,
	); err != nil {
		t.Fatal(err)
	}

	otherAuth := f.signed.Authorization
	otherAuth.RotationID = "vcs14-different-transition"
	oldApproval, err := SignSuccessorGovernanceRotationApproval(otherAuth, f.oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	newApproval, err := SignSuccessorGovernanceRotationApproval(otherAuth, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	other := SignedSuccessorGovernanceRotation{
		Authorization: otherAuth,
		OldApproval:   oldApproval,
		NewApproval:   newApproval,
	}
	if _, err := FreezeSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		other,
		f.oldBinding,
		f.newBinding,
		f.now,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("different transition replaced frozen authority head: %v", err)
	}

	staleAuth, err := NewSuccessorGovernanceRotationAuthorization(
		"vcs14-stale",
		SuccessorGovernanceAuthorityJournalID,
		7,
		f.oldBinding,
		f.newBinding,
		f.now.Add(-time.Minute),
		f.now.Add(time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}
	staleOld, err := SignSuccessorGovernanceRotationApproval(staleAuth, f.oldPrivate)
	if err != nil {
		t.Fatal(err)
	}
	staleNew, err := SignSuccessorGovernanceRotationApproval(staleAuth, f.newPrivate)
	if err != nil {
		t.Fatal(err)
	}
	stale := SignedSuccessorGovernanceRotation{
		Authorization: staleAuth,
		OldApproval: staleOld,
		NewApproval: staleNew,
	}
	if _, err := FreezeSuccessorGovernanceAuthority(
		f.ctx,
		f.oldStore,
		stale,
		f.oldBinding,
		f.newBinding,
		f.now,
	); !errors.Is(err, ErrSuccessorGovernanceAuthority) {
		t.Fatalf("stale predecessor sequence was accepted: %v", err)
	}
}

func vcs14CombinedEnvelope(
	t *testing.T,
	governancePublicKey ed25519.PublicKey,
	threshold int,
	ids ...string,
) []byte {
	t.Helper()
	members := make([]QuorumTrustPolicyMember, 0, len(ids))
	for _, id := range ids {
		members = append(members, QuorumTrustPolicyMember{
			ID:                id,
			TrustManifestHash: quorumTrustHashForTest(id),
		})
	}
	envelope := struct {
		Version                       string                              `json:"version"`
		ExternalWitnessQuorum         QuorumTrustPolicy                   `json:"external_witness_quorum"`
		EnrollmentSuccessorGovernance EnrollmentSuccessorGovernancePolicy `json:"enrollment_successor_governance"`
	}{
		Version: "aegis-ege/capability-envelope/v1",
		ExternalWitnessQuorum: QuorumTrustPolicy{
			Protocol:  QuorumTrustPolicyVersion,
			Threshold: threshold,
			Members:   members,
		},
		EnrollmentSuccessorGovernance: EnrollmentSuccessorGovernancePolicy{
			Protocol:        EnrollmentSuccessorGovernancePolicyVersion,
			AuthorityID:     "successor-governance-" + ids[0],
			PublicKeyBase64: base64.StdEncoding.EncodeToString(governancePublicKey),
		},
	}
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
