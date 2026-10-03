package computesettlement

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

// CaptureCrossGenesisGovernedSuccessorEnrollmentBoundAegisExecutionRoot is the
// VCS-14 settlement profile. A historical Genesis binding is insufficient:
// the independent quorum head must still name that binding as the current
// successor-governance authority.
func CaptureCrossGenesisGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
	ctx context.Context,
	pid int,
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	platformSource kernelfabric.PlatformMeasurementSource,
	enrolled kernelfabric.EnrolledTPMIdentity,
	receiptSource kernelfabric.EnrollmentIdentityReceiptReader,
	enrollmentAuthorityPublicKey ed25519.PublicKey,
	signedSuccessor kernelfabric.SignedEnrollmentIdentitySuccessorAuthorization,
	successorGovernance journal.GenesisEnrollmentSuccessorGovernanceBinding,
	successorAuthorityStore *journal.QuorumHeadStore,
	successorAuthorityJournalID string,
	now time.Time,
) (GovernedSuccessorEnrollmentBoundAegisExecutionRoot, error) {
	if _, err := journal.RequireActiveSuccessorGovernanceAuthority(
		ctx,
		successorAuthorityStore,
		successorAuthorityJournalID,
		successorGovernance,
	); err != nil {
		return GovernedSuccessorEnrollmentBoundAegisExecutionRoot{}, fmt.Errorf(
			"current successor governance authority: %w",
			err,
		)
	}
	return CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
		ctx,
		pid,
		state,
		activation,
		runtimeLease,
		expectedProfile,
		trust,
		platformSource,
		enrolled,
		receiptSource,
		enrollmentAuthorityPublicKey,
		signedSuccessor,
		successorGovernance,
		now,
	)
}
