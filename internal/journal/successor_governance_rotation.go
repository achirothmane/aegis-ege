package journal

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ucarion/jcs"
)

const (
	SuccessorGovernanceRotationVersion    = "aegis-ege/successor-governance-rotation/v1"
	SuccessorGovernanceAuthorityJournalID = "governance/enrollment-successor-authority"
)

var (
	ErrSuccessorGovernanceRotation  = errors.New("successor governance rotation is invalid")
	ErrSuccessorGovernanceAuthority = errors.New("successor governance authority is not current")
)

type SuccessorGovernanceRotationAuthorization struct {
	Version                   string    `json:"version"`
	RotationID                string    `json:"rotation_id"`
	JournalID                 string    `json:"journal_id"`
	PreviousSequence          uint64    `json:"previous_sequence"`
	PreviousHeadHash          string    `json:"previous_head_hash"`
	PreviousKeyID             string    `json:"previous_key_id"`
	OldGenesisManifestHash    string    `json:"old_genesis_manifest_hash"`
	NewGenesisManifestHash    string    `json:"new_genesis_manifest_hash"`
	OldGenesisEpoch           uint64    `json:"old_genesis_epoch"`
	OldCapabilityEnvelopeHash string    `json:"old_capability_envelope_hash"`
	OldPolicyHash             string    `json:"old_policy_hash"`
	OldAuthorityID            string    `json:"old_authority_id"`
	OldAuthorityKeyID         string    `json:"old_authority_key_id"`
	NewGenesisEpoch           uint64    `json:"new_genesis_epoch"`
	NewCapabilityEnvelopeHash string    `json:"new_capability_envelope_hash"`
	NewPolicyHash             string    `json:"new_policy_hash"`
	NewAuthorityID            string    `json:"new_authority_id"`
	NewAuthorityKeyID         string    `json:"new_authority_key_id"`
	NotBefore                 time.Time `json:"not_before"`
	ExpiresAt                 time.Time `json:"expires_at"`
}

type SuccessorGovernanceRotationApproval struct {
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

type SignedSuccessorGovernanceRotation struct {
	Authorization SuccessorGovernanceRotationAuthorization `json:"authorization"`
	OldApproval   SuccessorGovernanceRotationApproval      `json:"old_approval"`
	NewApproval   SuccessorGovernanceRotationApproval      `json:"new_approval"`
}

type SuccessorGovernanceRotationResult struct {
	FrozenHead              ExternalHead
	QuorumTransitionHash    string
	ActiveHead              ExternalHead
	AuthorityTransitionHash string
}

type successorGovernanceBindingCommitment struct {
	GenesisEpoch           uint64 `json:"genesis_epoch"`
	GenesisManifestHash    string `json:"genesis_manifest_hash"`
	CapabilityEnvelopeHash string `json:"capability_envelope_hash"`
	PolicyHash             string `json:"policy_hash"`
	AuthorityID            string `json:"authority_id"`
	AuthorityKeyID         string `json:"authority_key_id"`
}

func NewSuccessorGovernanceRotationAuthorization(
	rotationID string,
	journalID string,
	previous ExternalHead,
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding,
	newBinding GenesisEnrollmentSuccessorGovernanceBinding,
	notBefore time.Time,
	expiresAt time.Time,
) (SuccessorGovernanceRotationAuthorization, error) {
	oldCommitment, _, err := successorGovernanceBindingCommitmentFor(oldBinding)
	if err != nil {
		return SuccessorGovernanceRotationAuthorization{}, fmt.Errorf("%w: old binding: %v", ErrSuccessorGovernanceRotation, err)
	}
	newCommitment, _, err := successorGovernanceBindingCommitmentFor(newBinding)
	if err != nil {
		return SuccessorGovernanceRotationAuthorization{}, fmt.Errorf("%w: new binding: %v", ErrSuccessorGovernanceRotation, err)
	}
	if previous.JournalID != strings.TrimSpace(journalID) || !successorGovernanceHeadMatchesBinding(previous, oldBinding) {
		return SuccessorGovernanceRotationAuthorization{}, fmt.Errorf("%w: exact current predecessor is required", ErrSuccessorGovernanceRotation)
	}
	auth := SuccessorGovernanceRotationAuthorization{
		Version:                   SuccessorGovernanceRotationVersion,
		RotationID:                strings.TrimSpace(rotationID),
		JournalID:                 strings.TrimSpace(journalID),
		PreviousSequence:          previous.Sequence,
		PreviousHeadHash:          previous.HeadHash,
		PreviousKeyID:             previous.KeyID,
		OldGenesisManifestHash:    oldBinding.GenesisManifestHash(),
		NewGenesisManifestHash:    newBinding.GenesisManifestHash(),
		OldGenesisEpoch:           oldCommitment.GenesisEpoch,
		OldCapabilityEnvelopeHash: oldCommitment.CapabilityEnvelopeHash,
		OldPolicyHash:             oldCommitment.PolicyHash,
		OldAuthorityID:            oldCommitment.AuthorityID,
		OldAuthorityKeyID:         oldCommitment.AuthorityKeyID,
		NewGenesisEpoch:           newCommitment.GenesisEpoch,
		NewCapabilityEnvelopeHash: newCommitment.CapabilityEnvelopeHash,
		NewPolicyHash:             newCommitment.PolicyHash,
		NewAuthorityID:            newCommitment.AuthorityID,
		NewAuthorityKeyID:         newCommitment.AuthorityKeyID,
		NotBefore:                 notBefore.UTC(),
		ExpiresAt:                 expiresAt.UTC(),
	}
	if err := ValidateSuccessorGovernanceRotationAuthorization(auth); err != nil {
		return SuccessorGovernanceRotationAuthorization{}, err
	}
	return auth, nil
}

func ValidateSuccessorGovernanceRotationAuthorization(
	auth SuccessorGovernanceRotationAuthorization,
) error {
	if auth.Version != SuccessorGovernanceRotationVersion {
		return fmt.Errorf("%w: unsupported version %q", ErrSuccessorGovernanceRotation, auth.Version)
	}
	if strings.TrimSpace(auth.RotationID) == "" || strings.TrimSpace(auth.JournalID) == "" {
		return fmt.Errorf("%w: rotation and journal ids are required", ErrSuccessorGovernanceRotation)
	}
	if auth.OldGenesisEpoch == 0 || auth.NewGenesisEpoch <= auth.OldGenesisEpoch {
		return fmt.Errorf("%w: Genesis epoch must advance", ErrSuccessorGovernanceRotation)
	}
	if auth.PreviousSequence > ^uint64(0)-2 {
		return fmt.Errorf("%w: authority sequence exhausted", ErrSuccessorGovernanceRotation)
	}
	if strings.TrimSpace(auth.PreviousKeyID) == "" {
		return fmt.Errorf("%w: predecessor key identity is required", ErrSuccessorGovernanceRotation)
	}
	for label, digest := range map[string]string{
		"previous head":           auth.PreviousHeadHash,
		"old Genesis manifest":    auth.OldGenesisManifestHash,
		"new Genesis manifest":    auth.NewGenesisManifestHash,
		"old capability envelope": auth.OldCapabilityEnvelopeHash,
		"old policy":              auth.OldPolicyHash,
		"new capability envelope": auth.NewCapabilityEnvelopeHash,
		"new policy":              auth.NewPolicyHash,
	} {
		if !validSHA256Digest(strings.TrimSpace(digest)) {
			return fmt.Errorf("%w: %s hash must be sha256", ErrSuccessorGovernanceRotation, label)
		}
	}
	if strings.TrimSpace(auth.OldAuthorityID) == "" ||
		strings.TrimSpace(auth.NewAuthorityID) == "" ||
		strings.TrimSpace(auth.OldAuthorityKeyID) == "" ||
		strings.TrimSpace(auth.NewAuthorityKeyID) == "" {
		return fmt.Errorf("%w: old and new authority identities are required", ErrSuccessorGovernanceRotation)
	}
	if auth.OldPolicyHash == auth.NewPolicyHash ||
		auth.OldAuthorityKeyID == auth.NewAuthorityKeyID {
		return fmt.Errorf("%w: successor governance authority must actually change", ErrSuccessorGovernanceRotation)
	}
	if auth.NotBefore.IsZero() || auth.ExpiresAt.IsZero() ||
		!auth.ExpiresAt.After(auth.NotBefore) {
		return fmt.Errorf("%w: validity window is invalid", ErrSuccessorGovernanceRotation)
	}
	return nil
}

func SignSuccessorGovernanceRotationApproval(
	auth SuccessorGovernanceRotationAuthorization,
	privateKey ed25519.PrivateKey,
) (SuccessorGovernanceRotationApproval, error) {
	if err := ValidateSuccessorGovernanceRotationAuthorization(auth); err != nil {
		return SuccessorGovernanceRotationApproval{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SuccessorGovernanceRotationApproval{}, fmt.Errorf("%w: invalid Ed25519 private key", ErrSuccessorGovernanceRotation)
	}
	payload, err := canonicalSuccessorGovernanceRotationPayload(auth)
	if err != nil {
		return SuccessorGovernanceRotationApproval{}, err
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	return SuccessorGovernanceRotationApproval{
		KeyID:     Ed25519KeyID(publicKey),
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedSuccessorGovernanceRotation(
	signed SignedSuccessorGovernanceRotation,
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding,
	newBinding GenesisEnrollmentSuccessorGovernanceBinding,
	now time.Time,
) error {
	if err := ValidateSuccessorGovernanceRotationAuthorization(signed.Authorization); err != nil {
		return err
	}
	oldCommitment, oldPublicKey, err := successorGovernanceBindingCommitmentFor(oldBinding)
	if err != nil {
		return fmt.Errorf("%w: old binding: %v", ErrSuccessorGovernanceRotation, err)
	}
	newCommitment, newPublicKey, err := successorGovernanceBindingCommitmentFor(newBinding)
	if err != nil {
		return fmt.Errorf("%w: new binding: %v", ErrSuccessorGovernanceRotation, err)
	}
	auth := signed.Authorization
	if auth.OldGenesisEpoch != oldCommitment.GenesisEpoch ||
		auth.OldGenesisManifestHash != oldBinding.GenesisManifestHash() ||
		auth.NewGenesisManifestHash != newBinding.GenesisManifestHash() ||
		auth.OldCapabilityEnvelopeHash != oldCommitment.CapabilityEnvelopeHash ||
		auth.OldPolicyHash != oldCommitment.PolicyHash ||
		auth.OldAuthorityID != oldCommitment.AuthorityID ||
		auth.OldAuthorityKeyID != oldCommitment.AuthorityKeyID ||
		auth.NewGenesisEpoch != newCommitment.GenesisEpoch ||
		auth.NewCapabilityEnvelopeHash != newCommitment.CapabilityEnvelopeHash ||
		auth.NewPolicyHash != newCommitment.PolicyHash ||
		auth.NewAuthorityID != newCommitment.AuthorityID ||
		auth.NewAuthorityKeyID != newCommitment.AuthorityKeyID {
		return fmt.Errorf("%w: authorization does not match exact old/new Genesis bindings", ErrSuccessorGovernanceRotation)
	}
	if !successorGovernanceHeadMatchesBinding(successorGovernancePredecessor(signed), oldBinding) {
		return fmt.Errorf("%w: predecessor does not name the old authority", ErrSuccessorGovernanceRotation)
	}
	if string(oldPublicKey) == string(newPublicKey) {
		return fmt.Errorf("%w: old and new authority public keys must differ", ErrSuccessorGovernanceRotation)
	}
	payload, err := canonicalSuccessorGovernanceRotationPayload(auth)
	if err != nil {
		return err
	}
	if err := verifySuccessorGovernanceRotationApproval(
		signed.OldApproval,
		oldPublicKey,
		payload,
	); err != nil {
		return fmt.Errorf("%w: old authority approval: %v", ErrSuccessorGovernanceRotation, err)
	}
	if err := verifySuccessorGovernanceRotationApproval(
		signed.NewApproval,
		newPublicKey,
		payload,
	); err != nil {
		return fmt.Errorf("%w: new authority approval: %v", ErrSuccessorGovernanceRotation, err)
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(auth.NotBefore.UTC()) || !now.Before(auth.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: rotation is outside its validity window", ErrSuccessorGovernanceRotation)
	}
	return nil
}

func SuccessorGovernanceRotationDigest(
	signed SignedSuccessorGovernanceRotation,
) (string, error) {
	if err := ValidateSuccessorGovernanceRotationAuthorization(signed.Authorization); err != nil {
		return "", err
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		return "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", err
	}
	return sha256Digest(append(
		[]byte("aegis-ege/signed-successor-governance-rotation/v1\x00"),
		[]byte(canonical)...,
	)), nil
}

func InitializeSuccessorGovernanceAuthority(
	ctx context.Context,
	store *QuorumHeadStore,
	journalID string,
	binding GenesisEnrollmentSuccessorGovernanceBinding,
) (ExternalHead, error) {
	if err := requireQuorumStoreGenesisBinding(store, binding); err != nil {
		return ExternalHead{}, err
	}
	expected, err := activeSuccessorGovernanceHead(binding, journalID, 0)
	if err != nil {
		return ExternalHead{}, err
	}
	current, err := store.Load(ctx, journalID)
	switch {
	case err == nil:
		if sameSemanticHead(current, expected) {
			return current, nil
		}
		return ExternalHead{}, fmt.Errorf("%w: authority head already initialized differently", ErrSuccessorGovernanceAuthority)
	case !errors.Is(err, ErrExternalHeadNotFound):
		return ExternalHead{}, err
	}
	return store.CompareAndAdvance(ctx, ExternalHead{}, expected)
}

func RequireActiveSuccessorGovernanceAuthority(
	ctx context.Context,
	store *QuorumHeadStore,
	journalID string,
	binding GenesisEnrollmentSuccessorGovernanceBinding,
) (ExternalHead, error) {
	if err := requireQuorumStoreGenesisBinding(store, binding); err != nil {
		return ExternalHead{}, err
	}
	current, err := store.Load(ctx, journalID)
	if err != nil {
		return ExternalHead{}, err
	}
	if !successorGovernanceHeadMatchesBinding(current, binding) {
		return ExternalHead{}, ErrSuccessorGovernanceAuthority
	}
	return current, nil
}

func FreezeSuccessorGovernanceAuthority(
	ctx context.Context,
	store *QuorumHeadStore,
	signed SignedSuccessorGovernanceRotation,
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding,
	newBinding GenesisEnrollmentSuccessorGovernanceBinding,
	now time.Time,
) (ExternalHead, error) {
	if err := requireQuorumStoreGenesisBinding(store, oldBinding); err != nil {
		return ExternalHead{}, err
	}
	if err := VerifySignedSuccessorGovernanceRotation(signed, oldBinding, newBinding, now); err != nil {
		return ExternalHead{}, err
	}
	auth := signed.Authorization
	oldHead := successorGovernancePredecessor(signed)
	jointHead, err := jointSuccessorGovernanceHead(signed)
	if err != nil {
		return ExternalHead{}, err
	}
	current, err := store.Load(ctx, auth.JournalID)
	if err != nil {
		return ExternalHead{}, err
	}
	if sameSemanticHead(current, jointHead) {
		return store.ConvergeAuthorizedTransition(ctx, []ExternalHead{oldHead, jointHead}, jointHead)
	}
	if !sameSemanticHead(current, oldHead) {
		return ExternalHead{}, fmt.Errorf("%w: exact old authority head is not current", ErrSuccessorGovernanceAuthority)
	}
	advanced, err := store.CompareAndAdvance(ctx, current, jointHead)
	if err != nil {
		return ExternalHead{}, err
	}
	converged, err := store.ConvergeAuthorizedTransition(
		ctx,
		[]ExternalHead{oldHead, jointHead},
		jointHead,
	)
	if err != nil {
		return ExternalHead{}, err
	}
	if !sameSemanticHead(converged, advanced) {
		return ExternalHead{}, fmt.Errorf(
			"%w: frozen authority head did not converge across old quorum",
			ErrSuccessorGovernanceAuthority,
		)
	}
	return converged, nil
}

func ActivateSuccessorGovernanceAuthority(
	ctx context.Context,
	store *QuorumHeadStore,
	signed SignedSuccessorGovernanceRotation,
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding,
	newBinding GenesisEnrollmentSuccessorGovernanceBinding,
	now time.Time,
) (ExternalHead, error) {
	if err := requireQuorumStoreGenesisBinding(store, newBinding); err != nil {
		return ExternalHead{}, err
	}
	if err := VerifySignedSuccessorGovernanceRotation(signed, oldBinding, newBinding, now); err != nil {
		return ExternalHead{}, err
	}
	auth := signed.Authorization
	jointHead, err := jointSuccessorGovernanceHead(signed)
	if err != nil {
		return ExternalHead{}, err
	}
	newHead, err := activatedSuccessorGovernanceHead(newBinding, signed)
	if err != nil {
		return ExternalHead{}, err
	}
	current, err := store.Load(ctx, auth.JournalID)
	if err != nil {
		return ExternalHead{}, err
	}
	if sameSemanticHead(current, newHead) {
		return store.ConvergeAuthorizedTransition(ctx, []ExternalHead{successorGovernancePredecessor(signed), jointHead, newHead}, newHead)
	}
	if !sameSemanticHead(current, jointHead) {
		return ExternalHead{}, fmt.Errorf("%w: exact JOINT_FROZEN authority head is not current", ErrSuccessorGovernanceAuthority)
	}
	advanced, err := store.CompareAndAdvance(ctx, current, newHead)
	if err != nil {
		return ExternalHead{}, err
	}
	oldHead := successorGovernancePredecessor(signed)
	converged, err := store.ConvergeAuthorizedTransition(
		ctx,
		[]ExternalHead{oldHead, jointHead, newHead},
		newHead,
	)
	if err != nil {
		return ExternalHead{}, err
	}
	if !sameSemanticHead(converged, advanced) {
		return ExternalHead{}, fmt.Errorf("%w: authority head did not converge after activation", ErrSuccessorGovernanceAuthority)
	}
	return converged, nil
}

func ExecuteSuccessorGovernanceCrossGenesisRotation(
	ctx context.Context,
	signed SignedSuccessorGovernanceRotation,
	oldBinding GenesisEnrollmentSuccessorGovernanceBinding,
	newBinding GenesisEnrollmentSuccessorGovernanceBinding,
	quorumPlan QuorumRotationPlan,
	oldStore *QuorumHeadStore,
	newStore *QuorumHeadStore,
	now time.Time,
) (SuccessorGovernanceRotationResult, error) {
	if quorumPlan.oldEpoch.genesisEpoch != oldBinding.GenesisEpoch() ||
		quorumPlan.newEpoch.genesisEpoch != newBinding.GenesisEpoch() ||
		quorumPlan.oldEpoch.genesisManifestHash != oldBinding.GenesisManifestHash() ||
		quorumPlan.newEpoch.genesisManifestHash != newBinding.GenesisManifestHash() ||
		quorumPlan.oldEpoch.CapabilityEnvelopeHash() != oldBinding.CapabilityEnvelopeHash() ||
		quorumPlan.newEpoch.CapabilityEnvelopeHash() != newBinding.CapabilityEnvelopeHash() {
		return SuccessorGovernanceRotationResult{}, fmt.Errorf(
			"%w: quorum rotation provenance does not match exact authority Genesis bindings",
			ErrSuccessorGovernanceRotation,
		)
	}
	if err := requireQuorumStoreGenesisBinding(oldStore, oldBinding); err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	if err := requireQuorumStoreGenesisBinding(newStore, newBinding); err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	if oldStore.QuorumPolicyHash() != quorumPlan.oldEpoch.PolicyHash() || newStore.QuorumPolicyHash() != quorumPlan.newEpoch.PolicyHash() {
		return SuccessorGovernanceRotationResult{}, ErrQuorumPolicyMismatch
	}
	if err := VerifySignedSuccessorGovernanceRotation(
		signed,
		oldBinding,
		newBinding,
		now,
	); err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	frozen, err := jointSuccessorGovernanceHead(signed)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	activeExpected, err := activatedSuccessorGovernanceHead(newBinding, signed)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	_, quorumTransitionHash, err := quorumPlan.jointPolicy(
		signed.Authorization.JournalID,
		frozen,
	)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	authorityTransitionHash, err := SuccessorGovernanceRotationDigest(signed)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}

	// Recovery after the quorum substrate has already crossed Genesis.
	// NEW ACTIVE means the exact transition already completed. JOINT_FROZEN
	// means the old quorum is no longer needed and activation can resume using
	// only the target Genesis store.
	if currentNew, loadErr := newStore.Load(
		ctx,
		signed.Authorization.JournalID,
	); loadErr == nil {
		switch {
		case sameSemanticHead(currentNew, activeExpected):
			return SuccessorGovernanceRotationResult{
				FrozenHead:              frozen,
				QuorumTransitionHash:    quorumTransitionHash,
				ActiveHead:              currentNew,
				AuthorityTransitionHash: authorityTransitionHash,
			}, nil
		case sameSemanticHead(currentNew, frozen):
			active, err := ActivateSuccessorGovernanceAuthority(
				ctx,
				newStore,
				signed,
				oldBinding,
				newBinding,
				now,
			)
			if err != nil {
				return SuccessorGovernanceRotationResult{}, err
			}
			return SuccessorGovernanceRotationResult{
				FrozenHead:              frozen,
				QuorumTransitionHash:    quorumTransitionHash,
				ActiveHead:              active,
				AuthorityTransitionHash: authorityTransitionHash,
			}, nil
		default:
			return SuccessorGovernanceRotationResult{}, fmt.Errorf(
				"%w: target Genesis quorum exposes an unauthorized authority head",
				ErrSuccessorGovernanceAuthority,
			)
		}
	} else if !errors.Is(loadErr, ErrExternalHeadQuorum) &&
		!errors.Is(loadErr, ErrExternalHeadNotFound) {
		return SuccessorGovernanceRotationResult{}, loadErr
	}

	// During either quorum phase, neither ordinary OLD nor ordinary NEW
	// reads may establish a majority. The stable shared handles retain the
	// exact frozen authority head and the quorum protocol can resume it.
	shared, err := quorumPlan.sharedPolicyStores(oldStore, newStore)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	retained, retainedErr := observeSharedRotationHead(ctx, shared, signed.Authorization.JournalID)
	if retainedErr != nil || !sameSemanticHead(retained, frozen) {
		frozen, err = FreezeSuccessorGovernanceAuthority(
			ctx,
			oldStore,
			signed,
			oldBinding,
			newBinding,
			now,
		)
		if err != nil {
			return SuccessorGovernanceRotationResult{}, err
		}
	}
	quorumResult, err := ExecuteQuorumRotation(
		ctx,
		quorumPlan,
		oldStore,
		newStore,
		signed.Authorization.JournalID,
	)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	if !sameSemanticHead(quorumResult.Head, frozen) {
		return SuccessorGovernanceRotationResult{}, fmt.Errorf(
			"%w: quorum rotation did not preserve exact frozen authority head",
			ErrSuccessorGovernanceRotation,
		)
	}
	active, err := ActivateSuccessorGovernanceAuthority(
		ctx,
		newStore,
		signed,
		oldBinding,
		newBinding,
		now,
	)
	if err != nil {
		return SuccessorGovernanceRotationResult{}, err
	}
	return SuccessorGovernanceRotationResult{
		FrozenHead:              frozen,
		QuorumTransitionHash:    quorumResult.TransitionHash,
		ActiveHead:              active,
		AuthorityTransitionHash: authorityTransitionHash,
	}, nil
}

func successorGovernanceBindingCommitmentFor(
	binding GenesisEnrollmentSuccessorGovernanceBinding,
) (successorGovernanceBindingCommitment, ed25519.PublicKey, error) {
	publicKey, err := binding.PublicKey()
	if err != nil {
		return successorGovernanceBindingCommitment{}, nil, err
	}
	if binding.GenesisEpoch() == 0 ||
		!validSHA256Digest(binding.CapabilityEnvelopeHash()) ||
		!validSHA256Digest(binding.PolicyHash()) ||
		strings.TrimSpace(binding.AuthorityID()) == "" {
		return successorGovernanceBindingCommitment{}, nil, errors.New("valid Genesis successor governance binding is required")
	}
	return successorGovernanceBindingCommitment{
		GenesisEpoch:           binding.GenesisEpoch(),
		GenesisManifestHash:    binding.GenesisManifestHash(),
		CapabilityEnvelopeHash: binding.CapabilityEnvelopeHash(),
		PolicyHash:             binding.PolicyHash(),
		AuthorityID:            binding.AuthorityID(),
		AuthorityKeyID:         Ed25519KeyID(publicKey),
	}, publicKey, nil
}

func successorGovernanceBindingDigest(
	binding GenesisEnrollmentSuccessorGovernanceBinding,
) (string, string, error) {
	commitment, _, err := successorGovernanceBindingCommitmentFor(binding)
	if err != nil {
		return "", "", err
	}
	raw, err := json.Marshal(commitment)
	if err != nil {
		return "", "", err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", "", err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return "", "", err
	}
	return sha256Digest(append(
		[]byte("aegis-ege/successor-governance-authority-state/v1\x00"),
		[]byte(canonical)...,
	)), commitment.AuthorityKeyID, nil
}

func activeSuccessorGovernanceHead(
	binding GenesisEnrollmentSuccessorGovernanceBinding,
	journalID string,
	sequence uint64,
) (ExternalHead, error) {
	journalID = strings.TrimSpace(journalID)
	if journalID == "" {
		return ExternalHead{}, fmt.Errorf("%w: journal id is required", ErrSuccessorGovernanceAuthority)
	}
	digest, keyID, err := successorGovernanceBindingDigest(binding)
	if err != nil {
		return ExternalHead{}, err
	}
	return ExternalHead{
		JournalID: journalID,
		Sequence:  sequence,
		HeadHash:  digest,
		KeyID:     keyID,
	}, nil
}

func jointSuccessorGovernanceHead(
	signed SignedSuccessorGovernanceRotation,
) (ExternalHead, error) {
	digest, err := SuccessorGovernanceRotationDigest(signed)
	if err != nil {
		return ExternalHead{}, err
	}
	return ExternalHead{
		JournalID: strings.TrimSpace(signed.Authorization.JournalID),
		Sequence:  signed.Authorization.PreviousSequence + 1,
		HeadHash:  digest,
		KeyID:     "joint:" + digest,
	}, nil
}

func requireQuorumStoreGenesisBinding(
	store *QuorumHeadStore,
	binding GenesisEnrollmentSuccessorGovernanceBinding,
) error {
	if store == nil {
		return ErrSuccessorGovernanceAuthority
	}
	policy, ok := store.governedPolicyState()
	if !ok || policy.Phase != QuorumPolicyPhaseActive ||
		policy.GenesisEpoch != binding.GenesisEpoch() ||
		store.capabilityEnvelopeHash != binding.CapabilityEnvelopeHash() {
		return fmt.Errorf(
			"%w: quorum store does not share exact authority Genesis binding for epoch %d",
			ErrSuccessorGovernanceAuthority,
			binding.GenesisEpoch(),
		)
	}
	return nil
}

func verifySuccessorGovernanceRotationApproval(
	approval SuccessorGovernanceRotationApproval,
	publicKey ed25519.PublicKey,
	payload []byte,
) error {
	if approval.KeyID != Ed25519KeyID(publicKey) {
		return errors.New("approval key id does not match authority")
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil {
		return errors.New("approval signature is not valid base64")
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("approval signature verification failed")
	}
	return nil
}

func canonicalSuccessorGovernanceRotationPayload(
	auth SuccessorGovernanceRotationAuthorization,
) ([]byte, error) {
	if err := ValidateSuccessorGovernanceRotationAuthorization(auth); err != nil {
		return nil, err
	}
	normalized := auth
	normalized.RotationID = strings.TrimSpace(normalized.RotationID)
	normalized.JournalID = strings.TrimSpace(normalized.JournalID)
	normalized.OldAuthorityID = strings.TrimSpace(normalized.OldAuthorityID)
	normalized.OldAuthorityKeyID = strings.TrimSpace(normalized.OldAuthorityKeyID)
	normalized.NewAuthorityID = strings.TrimSpace(normalized.NewAuthorityID)
	normalized.NewAuthorityKeyID = strings.TrimSpace(normalized.NewAuthorityKeyID)
	normalized.NotBefore = normalized.NotBefore.UTC()
	normalized.ExpiresAt = normalized.ExpiresAt.UTC()
	raw, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	canonical, err := jcs.Format(value)
	if err != nil {
		return nil, err
	}
	return append(
		[]byte("aegis-ege/successor-governance-rotation/v1\x00"),
		[]byte(canonical)...,
	), nil
}

// The activated head retains the exact transition identity in the head's
// signed logical key identity. This is authority-state metadata, not a new
// journal signing key. A different co-signed rotation cannot claim this head.
func activatedSuccessorGovernanceHead(binding GenesisEnrollmentSuccessorGovernanceBinding, signed SignedSuccessorGovernanceRotation) (ExternalHead, error) {
	head, err := activeSuccessorGovernanceHead(binding, signed.Authorization.JournalID, signed.Authorization.PreviousSequence+2)
	if err != nil {
		return ExternalHead{}, err
	}
	transitionHash, err := SuccessorGovernanceRotationDigest(signed)
	if err != nil {
		return ExternalHead{}, err
	}
	head.KeyID += "/rotation/" + transitionHash
	return head, nil
}

func successorGovernancePredecessor(signed SignedSuccessorGovernanceRotation) ExternalHead {
	auth := signed.Authorization
	return ExternalHead{JournalID: auth.JournalID, Sequence: auth.PreviousSequence, HeadHash: auth.PreviousHeadHash, KeyID: auth.PreviousKeyID}
}

func successorGovernanceHeadMatchesBinding(head ExternalHead, binding GenesisEnrollmentSuccessorGovernanceBinding) bool {
	digest, keyID, err := successorGovernanceBindingDigest(binding)
	if err != nil || head.HeadHash != digest {
		return false
	}
	if head.Sequence == 0 {
		return head.KeyID == keyID
	}
	prefix := keyID + "/rotation/"
	return head.Sequence%2 == 0 && strings.HasPrefix(head.KeyID, prefix) && validSHA256Digest(strings.TrimPrefix(head.KeyID, prefix))
}
