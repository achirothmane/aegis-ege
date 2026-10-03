//go:build linux

package computesettlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

func TestVCS12GovernedSuccessorEnrollmentDrivesSettlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governancePub, governancePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governanceBinding := vcs13GovernanceBinding(t, 13, governancePub)

	store := vcs11Store(t)
	predecessorEK := "sha256:" + strings.Repeat("a", 64)
	successorEK := "sha256:" + strings.Repeat("b", 64)
	predecessor := vcs11Identity(live.state.DeviceID, predecessorEK, live.now.Add(-2*time.Minute))
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "vcs12-r1", 1, "", predecessor)
	d1, err := store.Append(context.Background(), r1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}

	successor := vcs11Identity(live.state.DeviceID, successorEK, live.now.Add(-time.Minute))
	auth := vcs12SuccessorAuthorization(live.now, live.state.DeviceID, d1, predecessorEK, successorEK, governanceBinding)
	auth.NotBefore = successor.EnrolledAt.Add(-time.Minute)
	auth.ExpiresAt = live.now.Add(-30 * time.Second)
	signedAuth, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(auth, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	authDigest, err := kernelfabric.EnrollmentIdentitySuccessorAuthorizationDigest(signedAuth)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := kernelfabric.NewGovernedEnrollmentIdentitySuccessorReceipt(
		auth.SuccessorEnrollmentID,
		2,
		d1,
		authDigest,
		successor,
		successor.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signedR2, err := kernelfabric.SignEnrollmentIdentityReceipt(r2, enrollmentPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Append(context.Background(), signedR2, enrollmentPub); err == nil {
		t.Fatal("direct append must not advance a governed v2 successor receipt")
	}
	if _, err := store.AppendGovernedSuccessor(
		context.Background(),
		signedR2,
		enrollmentPub,
		signedAuth,
		governancePub,
		r2.IssuedAt,
	); err != nil {
		t.Fatal(err)
	}

	commitment := vcs09Commitment(
		t,
		successorEK,
		"sha256:"+strings.Repeat("c", 64),
		71,
	)
	root, err := CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		successor,
		store,
		enrollmentPub,
		signedAuth,
		governanceBinding,
		live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if root.SuccessorAuthorizationDigest != authDigest {
		t.Fatalf("successor authorization digest=%s want=%s", root.SuccessorAuthorizationDigest, authDigest)
	}

	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, live.profile, streams, providerAuthority, tenantAuthority)
	provenance := vcs07Provenance(t, f, live.profile, root.Root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)
	result := vcs07Reconcile(
		t,
		f,
		live.profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root.Root,
		provenance,
		bindings,
		provenanceAuthority,
	)
	if result.Disposition != Settled {
		t.Fatalf("governed successor hardware root should settle: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS12LegacySignedSuccessorReceiptCannotSatisfyGovernedRoot(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governancePub, governancePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governanceBinding := vcs13GovernanceBinding(t, 13, governancePub)
	store := vcs11Store(t)
	predecessorEK := "sha256:" + strings.Repeat("a", 64)
	successorEK := "sha256:" + strings.Repeat("b", 64)
	predecessor := vcs11Identity(live.state.DeviceID, predecessorEK, live.now.Add(-2*time.Minute))
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "vcs12-legacy-r1", 1, "", predecessor)
	d1, err := store.Append(context.Background(), r1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}
	successor := vcs11Identity(live.state.DeviceID, successorEK, live.now.Add(-time.Minute))
	legacyR2 := vcs11SignedReceipt(t, enrollmentPriv, "vcs12-successor", 2, d1, successor)
	if _, err := store.Append(context.Background(), legacyR2, enrollmentPub); err != nil {
		t.Fatal(err)
	}
	auth := vcs12SuccessorAuthorization(live.now, live.state.DeviceID, d1, predecessorEK, successorEK, governanceBinding)
	signedAuth, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(auth, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	commitment := vcs09Commitment(
		t,
		successorEK,
		"sha256:"+strings.Repeat("c", 64),
		72,
	)
	_, err = CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		successor,
		store,
		enrollmentPub,
		signedAuth,
		governanceBinding,
		live.now,
	)
	if err == nil {
		t.Fatal("legacy signed R2 without governed v2 lineage must not satisfy VCS-12")
	}
}

func TestVCS12DifferentSuccessorAuthorizationCannotSatisfyCurrentReceipt(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governancePub, governancePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governanceBinding := vcs13GovernanceBinding(t, 13, governancePub)
	store := vcs11Store(t)
	predecessorEK := "sha256:" + strings.Repeat("a", 64)
	successorEK := "sha256:" + strings.Repeat("b", 64)
	predecessor := vcs11Identity(live.state.DeviceID, predecessorEK, live.now.Add(-2*time.Minute))
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "vcs12-auth-r1", 1, "", predecessor)
	d1, err := store.Append(context.Background(), r1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}
	successor := vcs11Identity(live.state.DeviceID, successorEK, live.now.Add(-time.Minute))
	auth := vcs12SuccessorAuthorization(live.now, live.state.DeviceID, d1, predecessorEK, successorEK, governanceBinding)
	signedAuth, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(auth, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	authDigest, err := kernelfabric.EnrollmentIdentitySuccessorAuthorizationDigest(signedAuth)
	if err != nil {
		t.Fatal(err)
	}
	r2, err := kernelfabric.NewGovernedEnrollmentIdentitySuccessorReceipt(
		auth.SuccessorEnrollmentID,
		2,
		d1,
		authDigest,
		successor,
		successor.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signedR2, err := kernelfabric.SignEnrollmentIdentityReceipt(r2, enrollmentPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.AppendGovernedSuccessor(
		context.Background(),
		signedR2,
		enrollmentPub,
		signedAuth,
		governancePub,
		r2.IssuedAt,
	); err != nil {
		t.Fatal(err)
	}

	other := auth
	other.AuthorizationID = "vcs12-other-authorization"
	other.ContinuityTransferAuthorizationDigest = "sha256:" + strings.Repeat("d", 64)
	signedOther, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(other, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	commitment := vcs09Commitment(
		t,
		successorEK,
		"sha256:"+strings.Repeat("c", 64),
		73,
	)
	_, err = CaptureGovernedSuccessorEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		successor,
		store,
		enrollmentPub,
		signedOther,
		governanceBinding,
		live.now,
	)
	if err == nil || errors.Is(err, kernelfabric.ErrEnrollmentIdentitySignatureInvalid) {
		t.Fatalf("different valid successor authorization should fail exact lineage binding, got %v", err)
	}
}

func vcs12SuccessorAuthorization(
	now time.Time,
	deviceID,
	predecessorDigest,
	predecessorEK,
	successorEK string,
	governance journal.GenesisEnrollmentSuccessorGovernanceBinding,
) kernelfabric.EnrollmentIdentitySuccessorAuthorization {
	return kernelfabric.EnrollmentIdentitySuccessorAuthorization{
		Version:                                kernelfabric.EnrollmentIdentitySuccessorAuthorizationVersionV2,
		AuthorizationID:                        "vcs12-governed-successor",
		DeviceID:                               deviceID,
		PredecessorReceiptDigest:               predecessorDigest,
		PredecessorSequence:                    1,
		PredecessorHardwareIdentityDigest:      predecessorEK,
		SuccessorEnrollmentID:                  "vcs12-successor",
		SuccessorEnrollmentRequestDigest:       "sha256:" + strings.Repeat("1", 64),
		SuccessorHardwareIdentityDigest:        successorEK,
		ContinuityTransferAuthorizationDigest: "sha256:" + strings.Repeat("2", 64),
		DestinationAttestationDigest:           "sha256:" + strings.Repeat("3", 64),
		SourceDeviceIdentity:                   "sha256:" + strings.Repeat("4", 64),
		DestinationDeviceIdentity:              "sha256:" + strings.Repeat("5", 64),
		DestinationMeasuredBootIdentity:        "sha256:" + strings.Repeat("6", 64),
		DestinationGeneration:                  7,
		HistoryWitnessPolicyHash:               "sha256:" + strings.Repeat("7", 64),
		OwnershipWitnessPolicyHash:             "sha256:" + strings.Repeat("8", 64),
		GovernanceGenesisEpoch:                 governance.GenesisEpoch(),
		GovernanceCapabilityEnvelopeHash:       governance.CapabilityEnvelopeHash(),
		GovernancePolicyHash:                   governance.PolicyHash(),
		NotBefore:                              now.Add(-time.Minute),
		ExpiresAt:                              now.Add(time.Minute),
	}
}


func vcs13GovernanceBinding(
	t *testing.T,
	genesisEpoch uint64,
	publicKey ed25519.PublicKey,
) journal.GenesisEnrollmentSuccessorGovernanceBinding {
	t.Helper()
	envelope, err := json.Marshal(map[string]any{
		"enrollment_successor_governance": journal.EnrollmentSuccessorGovernancePolicy{
			Protocol:        journal.EnrollmentSuccessorGovernancePolicyVersion,
			AuthorityID:     "vcs13-successor-governance",
			PublicKeyBase64: base64.StdEncoding.EncodeToString(publicKey),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(envelope)
	envelopeHash := "sha256:" + hex.EncodeToString(sum[:])
	binding, err := journal.ParseGenesisEnrollmentSuccessorGovernanceBinding(
		envelope,
		envelopeHash,
		genesisEpoch,
		envelopeHash, // fixture manifest pin; not a production Genesis verification
	)
	if err != nil {
		t.Fatal(err)
	}
	return binding
}
