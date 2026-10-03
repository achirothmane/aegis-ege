//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

// CompleteAndCommitCrossGenesisGovernedTPMEnrollmentSuccessor is the VCS-14
// rotation-aware successor path. It requires the supplied Genesis governance
// binding to be the authority currently published by the independent quorum
// head before delegating to the VCS-13 hardware-replacement proof.
func CompleteAndCommitCrossGenesisGovernedTPMEnrollmentSuccessor(
	ctx context.Context,
	pending kernelfabric.PendingTPMEnrollment,
	proof kernelfabric.TPMEnrollmentProof,
	now time.Time,
	destination *TPMNVHistoryAnchor,
	store kernelfabric.AnchoredEnrollmentIdentityStore,
	enrollmentAuthorityKey ed25519.PrivateKey,
	signedSuccessor kernelfabric.SignedEnrollmentIdentitySuccessorAuthorization,
	successorGovernance journal.GenesisEnrollmentSuccessorGovernanceBinding,
	successorAuthorityStore *journal.QuorumHeadStore,
	successorAuthorityJournalID string,
	signedTransfer SignedTPMHistoryContinuityTransferAuthorization,
	transferPublicKey ed25519.PublicKey,
	destinationAttestation SignedTPMRootMigrationDestinationAttestation,
	attestationTrust TPMRootMigrationAttestationTrust,
) (
	kernelfabric.EnrolledTPMIdentity,
	kernelfabric.SignedEnrollmentIdentityReceipt,
	string,
	error,
) {
	if _, err := journal.RequireActiveSuccessorGovernanceAuthority(
		ctx,
		successorAuthorityStore,
		successorAuthorityJournalID,
		successorGovernance,
	); err != nil {
		return kernelfabric.EnrolledTPMIdentity{},
			kernelfabric.SignedEnrollmentIdentityReceipt{},
			"",
			fmt.Errorf(
				"%w: current successor governance authority: %v",
				ErrTPMEnrollmentSuccessorGovernance,
				err,
			)
	}
	return CompleteAndCommitGovernedTPMEnrollmentSuccessor(
		ctx,
		pending,
		proof,
		now,
		destination,
		store,
		enrollmentAuthorityKey,
		signedSuccessor,
		successorGovernance,
		signedTransfer,
		transferPublicKey,
		destinationAttestation,
		attestationTrust,
	)
}
