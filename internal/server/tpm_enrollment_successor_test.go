//go:build linux && cgo

package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/journal"
	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestVCS12GovernedEnrollmentSuccessorRequiresTransferredHeadAndSameLiveTPM(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 5, 15, 0, 0, time.UTC)
	deviceID := "device:vcs12"

	historyQuorum := newHistoryTransferQuorum(
		t,
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
	)
	historyWitness, err := NewExternalHeadTaintRecoveryHistoryAnchor(
		historyQuorum,
		"enrollment/vcs12/history",
	)
	if err != nil {
		t.Fatal(err)
	}
	ownershipQuorum := newHistoryTransferQuorum(
		t,
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
		journal.NewMemoryHeadStore(),
	)
	ownership, err := NewTaintRecoveryHistoryOwnershipWitness(
		ownershipQuorum,
		"enrollment/vcs12/active-device",
	)
	if err != nil {
		t.Fatal(err)
	}

	simA, err := simulator.GetWithFixedSeedInsecure(1201)
	if err != nil {
		t.Fatal(err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A190),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A191),
		StatePath:     filepath.Join(dir, "enrollment-a-anchor.json"),
		IndexAuth:     []byte("vcs12-a-counter"),
		HeadIndexAuth: []byte("vcs12-a-head"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceA, cfgA); err != nil {
		t.Fatal(err)
	}
	localA, err := NewTPMNVHistoryAnchor(deviceA, cfgA)
	if err != nil {
		t.Fatal(err)
	}
	sourceDeviceIdentity, err := localA.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ownership.Initialize(ctx, sourceDeviceIdentity); err != nil {
		t.Fatal(err)
	}
	ownedA, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localA, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}

	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sourceEK, err := localA.helper.enrollmentHardwareIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	sourceIdentity := kernelfabric.EnrolledTPMIdentity{
		DeviceID:                   deviceID,
		AK:                         kernelfabric.TPMAttestationParameters{Public: []byte("vcs12-source-ak")},
		EKSPKISHA256:               sourceEK,
		BootstrapAttestorPublicKey: append([]byte(nil), bootstrapPub...),
		TPMManufacturer:            "SIM",
		TPMVendorInfo:              "VCS12-A",
		TPMFirmwareMajor:           1,
		TPMFirmwareMinor:           0,
		EnrolledAt:                 now.Add(-10 * time.Minute),
	}
	r1, err := kernelfabric.NewEnrollmentIdentityReceipt(
		"vcs12-r1",
		1,
		"",
		sourceIdentity,
		sourceIdentity.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signedR1, err := kernelfabric.SignEnrollmentIdentityReceipt(r1, enrollmentPriv)
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(dir, "enrollment-current.json")
	storeA := kernelfabric.AnchoredEnrollmentIdentityStore{
		Store:  kernelfabric.EnrollmentIdentityReceiptStore{Path: receiptPath},
		Anchor: ownedA,
	}
	r1Digest, err := storeA.Append(ctx, signedR1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}
	sourceState, ok, err := readTPMNVHistoryAnchorState(cfgA.StatePath)
	if err != nil || !ok {
		t.Fatalf("read source anchor state: ok=%t err=%v", ok, err)
	}
	if sourceState.Sequence != 1 || sourceState.HeadDigest != r1Digest {
		t.Fatalf("source enrollment head mismatch: %+v", sourceState)
	}
	if err := simA.Close(); err != nil {
		t.Fatal(err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(1202)
	if err != nil {
		t.Fatal(err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)
	cfgB := TPMNVHistoryAnchorConfig{
		NVIndex:       tpm2.TPMHandle(0x0180A190),
		HeadNVIndex:   tpm2.TPMHandle(0x0180A191),
		StatePath:     filepath.Join(dir, "enrollment-b-anchor.json"),
		IndexAuth:     []byte("vcs12-b-counter"),
		HeadIndexAuth: []byte("vcs12-b-head"),
	}
	if err := ProvisionTPMNVHistoryAnchor(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	localB, err := NewTPMNVHistoryAnchor(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	destinationState, ok, err := readTPMNVHistoryAnchorState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read destination anchor state: ok=%t err=%v", ok, err)
	}
	destinationDeviceIdentity, err := localB.DeviceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destinationBootIdentity, err := localB.MeasuredBootIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	destinationEK, err := localB.helper.enrollmentHardwareIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if destinationEK == sourceEK {
		t.Fatal("replacement TPM unexpectedly reused predecessor EK identity")
	}

	// Reconstruct the exact ECC endorsement primary used by the Aegis live
	// enrollment identity exporter. go-attestation TPM.EKs() historically
	// enumerates the RSA EK on Linux, so using its first result would test a
	// different hardware identity than VCS-10/VCS-12.
	ekPrimary, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(cfgB.EndorsementAuth),
		},
		InPublic: tpm2.New2B(tpm2.ECCEKTemplate),
	}).Execute(deviceB)
	if err != nil {
		t.Fatal(err)
	}
	publicArea, err := ekPrimary.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	detail, err := publicArea.Parameters.ECCDetail()
	if err != nil {
		t.Fatal(err)
	}
	curve, err := detail.CurveID.Curve()
	if err != nil {
		t.Fatal(err)
	}
	unique, err := publicArea.Unique.ECC()
	if err != nil {
		t.Fatal(err)
	}
	exactECCEK := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(unique.X.Buffer),
		Y:     new(big.Int).SetBytes(unique.Y.Buffer),
	}
	ekDER, err := x509.MarshalPKIXPublicKey(exactECCEK)
	if err != nil {
		t.Fatal(err)
	}
	ekHash := sha256.Sum256(ekDER)
	ceremonyEK := "sha256:" + hex.EncodeToString(ekHash[:])
	if ceremonyEK != destinationEK {
		t.Fatalf("reconstructed ECC EK=%s live destination EK=%s", ceremonyEK, destinationEK)
	}
	if _, err := (tpm2.FlushContext{FlushHandle: ekPrimary.ObjectHandle}).Execute(deviceB); err != nil {
		t.Fatal(err)
	}
	selectedEK := attest.EK{Public: exactECCEK}

	attestTPM := attest.InjectSimulatedTPMForTest(simB)
	ak, err := attestTPM.NewAK(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close(attestTPM)
	params := ak.AttestationParameters()
	successorBootstrapPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := kernelfabric.TPMEnrollmentRequest{
		Version:  kernelfabric.TPMEnrollmentRequestVersion,
		DeviceID: deviceID,
		AK: kernelfabric.TPMAttestationParameters{
			Public:            append([]byte(nil), params.Public...),
			CreateData:        append([]byte(nil), params.CreateData...),
			CreateAttestation: append([]byte(nil), params.CreateAttestation...),
			CreateSignature:   append([]byte(nil), params.CreateSignature...),
		},
		EKPublicDER:                ekDER,
		BootstrapAttestorPublicKey: append([]byte(nil), successorBootstrapPub...),
		CreatedAt:                  now,
	}
	challenge, pending, err := kernelfabric.BeginTPMEnrollment(
		request,
		kernelfabric.TPMEnrollmentTrustPolicy{
			AllowedEKSPKI: map[string]struct{}{destinationEK: {}},
			Now:           func() time.Time { return now },
		},
		time.Minute,
	)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := ak.ActivateCredentialWithEK(attestTPM, attest.EncryptedCredential{
		Credential: challenge.EncryptedCredential,
		Secret:     challenge.EncryptedSecret,
	}, selectedEK)
	if err != nil {
		t.Fatal(err)
	}
	transcript, err := kernelfabric.TPMEnrollmentTranscriptPayload(challenge)
	if err != nil {
		t.Fatal(err)
	}
	transcriptSignature, err := ak.SignMsg(attestTPM, transcript, crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	proof := kernelfabric.TPMEnrollmentProof{
		Version:             kernelfabric.TPMEnrollmentProofVersion,
		EnrollmentID:        challenge.EnrollmentID,
		DeviceID:            challenge.DeviceID,
		Secret:              secret,
		TranscriptSignature: transcriptSignature,
		CompletedAt:         now.Add(time.Second),
	}
	requestDigest, err := kernelfabric.TPMEnrollmentRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}

	transferPub, transferPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPub, attestationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationTrust := migrationAttestationTrustForTest(
		t,
		attestationPub,
		31,
		17,
		"sha256:"+strings.Repeat("e", 64),
	)
	governancePub, governancePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	governanceBinding := vcs13ServerGovernanceBinding(t, 13, governancePub)
	transferID := "vcs12-a-to-b"
	destinationAttestation, err := SignTPMRootMigrationDestinationAttestation(
		TPMRootMigrationDestinationAttestation{
			Version:                         TPMRootMigrationDestinationAttestationVersion,
			AttestationID:                   "vcs12-destination-attestation",
			MigrationID:                     transferID,
			EnrolledDeviceID:                deviceID,
			DestinationDeviceIdentity:       destinationDeviceIdentity,
			DestinationMeasuredBootIdentity: destinationBootIdentity,
			DestinationGeneration:           destinationState.Generation,
			RemoteDecisionID:                "vcs12-remote-decision",
			RemoteChallengeID:               "vcs12-remote-challenge",
			RemoteDecisionDigest:            "sha256:" + strings.Repeat("d", 64),
			RemoteDecisionVerifiedAt:        now.Add(-30 * time.Second),
			Decision:                        "ALLOW",
			VerifiedAt:                      now.Add(-20 * time.Second),
			ExpiresAt:                       now.Add(30 * time.Second),
			VerifierID:                      "vcs12-independent-attestor",
		},
		attestationPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	destinationAttestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		t.Fatal(err)
	}
	transferAuth := TPMHistoryContinuityTransferAuthorization{
		Version:                            TPMHistoryContinuityTransferAuthorizationVersion,
		TransferID:                         transferID,
		HistoryWitnessID:                   "enrollment/vcs12/history",
		HistoryWitnessPolicyHash:           historyWitness.QuorumPolicyHash(),
		OwnershipWitnessID:                 "enrollment/vcs12/active-device",
		OwnershipWitnessPolicyHash:         ownership.QuorumPolicyHash(),
		SourceDeviceIdentity:               sourceState.DeviceIdentity,
		SourceMeasuredBootIdentity:         sourceState.MeasuredBootIdentity,
		SourceStateDigest:                  sourceState.Digest,
		SourceGeneration:                   sourceState.Generation,
		SourceSequence:                     1,
		SourceHeadDigest:                   r1Digest,
		SourceOwnershipEpoch:               0,
		DestinationDeviceIdentity:          destinationDeviceIdentity,
		DestinationMeasuredBootIdentity:    destinationBootIdentity,
		DestinationStateDigest:             destinationState.Digest,
		DestinationGeneration:              destinationState.Generation,
		DestinationNVIndex:                      uint32(cfgB.NVIndex),
		DestinationHeadNVIndex:                  uint32(cfgB.HeadNVIndex),
		DestinationAttestationDigest:            destinationAttestationDigest,
		DestinationAttestationGenesisEpoch:      attestationTrust.genesisEpoch,
		DestinationAttestationTrustRootRef:      attestationTrust.trustRootRef,
		DestinationAttestationTrustRootEpoch:    attestationTrust.trustRootEpoch,
		DestinationAttestationPolicyHash:        attestationTrust.attestationPolicyHash,
		NotBefore:                               now.Add(-time.Minute),
		ExpiresAt:                          now.Add(5 * time.Minute),
	}
	signedTransfer, err := SignTPMHistoryContinuityTransferAuthorization(transferAuth, transferPriv)
	if err != nil {
		t.Fatal(err)
	}
	transferDigest, err := TPMHistoryContinuityTransferAuthorizationDigest(signedTransfer)
	if err != nil {
		t.Fatal(err)
	}
	successorAuth := kernelfabric.EnrollmentIdentitySuccessorAuthorization{
		Version:                                kernelfabric.EnrollmentIdentitySuccessorAuthorizationVersionV2,
		AuthorizationID:                        "vcs12-successor-governance",
		DeviceID:                               deviceID,
		PredecessorReceiptDigest:               r1Digest,
		PredecessorSequence:                    1,
		PredecessorHardwareIdentityDigest:      sourceEK,
		SuccessorEnrollmentID:                  challenge.EnrollmentID,
		SuccessorEnrollmentRequestDigest:       requestDigest,
		SuccessorHardwareIdentityDigest:        destinationEK,
		ContinuityTransferAuthorizationDigest: transferDigest,
		DestinationAttestationDigest:           destinationAttestationDigest,
		SourceDeviceIdentity:                   sourceDeviceIdentity,
		DestinationDeviceIdentity:              destinationDeviceIdentity,
		DestinationMeasuredBootIdentity:        destinationBootIdentity,
		DestinationGeneration:                  destinationState.Generation,
		HistoryWitnessPolicyHash:               historyWitness.QuorumPolicyHash(),
		OwnershipWitnessPolicyHash:             ownership.QuorumPolicyHash(),
		GovernanceGenesisEpoch:                 governanceBinding.GenesisEpoch(),
		GovernanceCapabilityEnvelopeHash:       governanceBinding.CapabilityEnvelopeHash(),
		GovernancePolicyHash:                   governanceBinding.PolicyHash(),
		NotBefore:                              now.Add(-time.Minute),
		ExpiresAt:                              now.Add(5 * time.Minute),
	}
	signedSuccessor, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(successorAuth, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	successorDigest, err := kernelfabric.EnrollmentIdentitySuccessorAuthorizationDigest(signedSuccessor)
	if err != nil {
		t.Fatal(err)
	}

	ownedB, err := NewOwnedConjunctiveTaintRecoveryHistoryAnchor(localB, historyWitness, ownership)
	if err != nil {
		t.Fatal(err)
	}
	storeB := kernelfabric.AnchoredEnrollmentIdentityStore{
		Store:  kernelfabric.EnrollmentIdentityReceiptStore{Path: receiptPath},
		Anchor: ownedB,
	}

	// A valid destination TPM and a valid enrollment ceremony do not authorize
	// R2 before the exact R1 head has transferred and ownership moved to B.
	if _, _, _, err := CompleteAndCommitGovernedTPMEnrollmentSuccessor(
		ctx,
		pending,
		proof,
		now.Add(2*time.Second),
		localB,
		storeB,
		enrollmentPriv,
		signedSuccessor,
		governanceBinding,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
	); !errors.Is(err, ErrTPMEnrollmentSuccessorGovernance) {
		t.Fatalf("fresh TPM-B without continuity transfer was not rejected: %v", err)
	}
	localBefore, err := localB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if localBefore.Sequence != 0 || localBefore.HeadDigest != "" {
		t.Fatalf("rejected pre-transfer successor mutated destination head: %+v", localBefore)
	}

	if err := TransferTPMNVHistoryContinuity(
		ctx,
		cfgA.StatePath,
		localB,
		historyWitness,
		ownership,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
		now,
	); err != nil {
		t.Fatalf("authorized enrollment-head continuity transfer failed: %v", err)
	}
	transferred, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if transferred.Sequence != 1 || transferred.HeadDigest != r1Digest {
		t.Fatalf("destination did not inherit exact R1 head: %+v", transferred)
	}

	// Bind the successor ceremony to a different EK while keeping all continuity
	// proof coordinates valid. The live TPM-B identity must still reject it.
	fakeEK := "sha256:" + strings.Repeat("9", 64)
	badPending := pending
	badPending.EKSPKISHA256 = fakeEK
	badPending.Challenge.EKSPKISHA256 = fakeEK
	badSuccessorAuth := successorAuth
	badSuccessorAuth.SuccessorHardwareIdentityDigest = fakeEK
	badSignedSuccessor, err := kernelfabric.SignEnrollmentIdentitySuccessorAuthorization(badSuccessorAuth, governancePriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := CompleteAndCommitGovernedTPMEnrollmentSuccessor(
		ctx,
		badPending,
		proof,
		now.Add(2*time.Second),
		localB,
		storeB,
		enrollmentPriv,
		badSignedSuccessor,
		governanceBinding,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
	); !errors.Is(err, ErrTPMEnrollmentSuccessorGovernance) {
		t.Fatalf("different successor EK was not rejected: %v", err)
	}
	stillR1, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stillR1.Sequence != 1 || stillR1.HeadDigest != r1Digest {
		t.Fatalf("rejected mismatched EK changed durable head: %+v", stillR1)
	}

	successorIdentity, signedR2, r2Digest, err := CompleteAndCommitGovernedTPMEnrollmentSuccessor(
		ctx,
		pending,
		proof,
		now.Add(2*time.Second),
		localB,
		storeB,
		enrollmentPriv,
		signedSuccessor,
		governanceBinding,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
	)
	if err != nil {
		t.Fatal(err)
	}
	if successorIdentity.EKSPKISHA256 != destinationEK ||
		signedR2.Receipt.Version != kernelfabric.EnrollmentIdentityReceiptVersionV2 ||
		signedR2.Receipt.Sequence != 2 ||
		signedR2.Receipt.PreviousReceiptDigest != r1Digest ||
		signedR2.Receipt.SuccessorAuthorizationDigest != successorDigest {
		t.Fatalf("unexpected governed R2: identity=%+v receipt=%+v", successorIdentity, signedR2.Receipt)
	}
	currentB, err := ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if currentB.Sequence != 2 || currentB.HeadDigest != r2Digest {
		t.Fatalf("destination did not advance to governed R2: %+v", currentB)
	}

	// Same ceremony + same authorization is idempotent after commit.
	_, replayedR2, replayedDigest, err := CompleteAndCommitGovernedTPMEnrollmentSuccessor(
		ctx,
		pending,
		proof,
		now.Add(3*time.Second),
		localB,
		storeB,
		enrollmentPriv,
		signedSuccessor,
		governanceBinding,
		signedTransfer,
		transferPub,
		destinationAttestation,
		attestationTrust,
	)
	if err != nil {
		t.Fatalf("governed successor retry failed: %v", err)
	}
	if replayedDigest != r2Digest || replayedR2.Receipt.Sequence != 2 {
		t.Fatalf("governed successor retry changed R2: digest=%s receipt=%+v", replayedDigest, replayedR2.Receipt)
	}
	currentB, err = ownedB.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if currentB.Sequence != 2 || currentB.HeadDigest != r2Digest {
		t.Fatalf("governed successor retry advanced durable head: %+v", currentB)
	}
}


func vcs13ServerGovernanceBinding(
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
