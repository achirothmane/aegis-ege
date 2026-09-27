package kernelfabric

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/google/go-attestation/attest"
)

const (
	TPMEnrollmentRequestVersion   = "aegis.ege/tpm-enrollment-request/v1"
	TPMEnrollmentChallengeVersion = "aegis.ege/tpm-enrollment-challenge/v1"
	TPMEnrollmentProofVersion     = "aegis.ege/tpm-enrollment-proof/v1"
	RemoteAttestationChallengeVersion = "aegis.ege/remote-attestation-challenge/v1"
	RemoteAttestationEvidenceVersion  = "aegis.ege/remote-attestation-evidence/v1"
	RemoteAttestationDecisionVersion  = "aegis.ege/remote-attestation-decision/v1"

	DefaultRemoteChallengeTTL = 2 * time.Minute
	RemoteQuoteNonceSize      = 20
)

var (
	ErrEnrollmentTrustRejected     = errors.New("TPM enrollment EK trust rejected")
	ErrEnrollmentActivationFailed  = errors.New("TPM credential activation failed")
	ErrRemoteChallengeExpired      = errors.New("remote attestation challenge expired")
	ErrRemoteAttestationInvalid    = errors.New("remote attestation evidence is invalid")
	ErrRemoteQuoteInvalid          = errors.New("TPM quote verification failed")
	ErrRemoteIMAReplayMismatch     = errors.New("IMA PCR replay does not match quoted PCR")
	ErrRemoteEventLogMismatch      = errors.New("platform event log replay failed")
)

type TPMAttestationParameters struct {
	Public            []byte `json:"public"`
	CreateData        []byte `json:"create_data"`
	CreateAttestation []byte `json:"create_attestation"`
	CreateSignature   []byte `json:"create_signature"`
}

func attestationParametersFromWire(in TPMAttestationParameters) attest.AttestationParameters {
	return attest.AttestationParameters{
		Public:            append([]byte(nil), in.Public...),
		CreateData:        append([]byte(nil), in.CreateData...),
		CreateAttestation: append([]byte(nil), in.CreateAttestation...),
		CreateSignature:   append([]byte(nil), in.CreateSignature...),
	}
}

func attestationParametersToWire(in attest.AttestationParameters) TPMAttestationParameters {
	return TPMAttestationParameters{
		Public:            append([]byte(nil), in.Public...),
		CreateData:        append([]byte(nil), in.CreateData...),
		CreateAttestation: append([]byte(nil), in.CreateAttestation...),
		CreateSignature:   append([]byte(nil), in.CreateSignature...),
	}
}

type TPMEnrollmentRequest struct {
	Version          string                   `json:"version"`
	DeviceID         string                   `json:"device_id"`
	AK               TPMAttestationParameters `json:"ak"`
	EKPublicDER      []byte                   `json:"ek_public_der"`
	EKCertificateDER []byte                   `json:"ek_certificate_der,omitempty"`
	TPMManufacturer  string                   `json:"tpm_manufacturer,omitempty"`
	TPMVendorInfo    string                   `json:"tpm_vendor_info,omitempty"`
	TPMFirmwareMajor int                      `json:"tpm_firmware_major,omitempty"`
	TPMFirmwareMinor int                      `json:"tpm_firmware_minor,omitempty"`
	CreatedAt        time.Time                `json:"created_at"`
}

type TPMEnrollmentChallenge struct {
	Version             string `json:"version"`
	EnrollmentID        string `json:"enrollment_id"`
	DeviceID            string `json:"device_id"`
	EncryptedCredential []byte `json:"encrypted_credential"`
	EncryptedSecret     []byte `json:"encrypted_secret"`
	IssuedAt            time.Time `json:"issued_at"`
	ExpiresAt           time.Time `json:"expires_at"`
}

type PendingTPMEnrollment struct {
	Request        TPMEnrollmentRequest
	Challenge      TPMEnrollmentChallenge
	ExpectedSecret []byte
	EKSPKISHA256   string
}

type TPMEnrollmentProof struct {
	Version      string `json:"version"`
	EnrollmentID string `json:"enrollment_id"`
	DeviceID     string `json:"device_id"`
	Secret       []byte `json:"secret"`
	CompletedAt  time.Time `json:"completed_at"`
}

type EnrolledTPMIdentity struct {
	DeviceID          string                   `json:"device_id"`
	AK                 TPMAttestationParameters `json:"ak"`
	EKSPKISHA256       string                   `json:"ek_spki_sha256"`
	EKCertificateSHA256 string                  `json:"ek_certificate_sha256,omitempty"`
	TPMManufacturer   string                   `json:"tpm_manufacturer,omitempty"`
	TPMVendorInfo     string                   `json:"tpm_vendor_info,omitempty"`
	TPMFirmwareMajor  int                      `json:"tpm_firmware_major,omitempty"`
	TPMFirmwareMinor  int                      `json:"tpm_firmware_minor,omitempty"`
	EnrolledAt        time.Time                `json:"enrolled_at"`
}

type TPMEnrollmentTrustPolicy struct {
	AllowedEKSPKI map[string]struct{}
	EKRoots       *x509.CertPool
	Now           func() time.Time
}

func BeginTPMEnrollment(
	req TPMEnrollmentRequest,
	policy TPMEnrollmentTrustPolicy,
	ttl time.Duration,
) (TPMEnrollmentChallenge, PendingTPMEnrollment, error) {
	if ttl <= 0 {
		ttl = DefaultRemoteChallengeTTL
	}
	if req.Version != TPMEnrollmentRequestVersion {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, fmt.Errorf("unsupported enrollment request version %q", req.Version)
	}
	if strings.TrimSpace(req.DeviceID) == "" || len(req.EKPublicDER) == 0 {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, errors.New("device id and EK public key are required")
	}
	ekPublic, err := x509.ParsePKIXPublicKey(req.EKPublicDER)
	if err != nil {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, fmt.Errorf("parse EK public key: %w", err)
	}
	ekDigest := sha256.Sum256(req.EKPublicDER)
	ekSPKI := "sha256:" + hex.EncodeToString(ekDigest[:])
	if err := verifyEKTrust(req, ekPublic, ekSPKI, policy); err != nil {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, err
	}

	params := attest.ActivationParameters{
		EK: ekPublic,
		AK: attestationParametersFromWire(req.AK),
	}
	secret, encrypted, err := params.Generate()
	if err != nil {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, fmt.Errorf("generate TPM activation challenge: %w", err)
	}

	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	enrollmentID, err := randomToken(24)
	if err != nil {
		return TPMEnrollmentChallenge{}, PendingTPMEnrollment{}, err
	}
	challenge := TPMEnrollmentChallenge{
		Version:             TPMEnrollmentChallengeVersion,
		EnrollmentID:        enrollmentID,
		DeviceID:            req.DeviceID,
		EncryptedCredential: append([]byte(nil), encrypted.Credential...),
		EncryptedSecret:     append([]byte(nil), encrypted.Secret...),
		IssuedAt:            now,
		ExpiresAt:           now.Add(ttl),
	}
	return challenge, PendingTPMEnrollment{
		Request:        req,
		Challenge:      challenge,
		ExpectedSecret: append([]byte(nil), secret...),
		EKSPKISHA256:   ekSPKI,
	}, nil
}

func verifyEKTrust(
	req TPMEnrollmentRequest,
	ekPublic crypto.PublicKey,
	ekSPKI string,
	policy TPMEnrollmentTrustPolicy,
) error {
	if _, ok := policy.AllowedEKSPKI[ekSPKI]; ok {
		return nil
	}
	if len(req.EKCertificateDER) == 0 || policy.EKRoots == nil {
		return fmt.Errorf("%w: EK %s is neither allowlisted nor backed by a trusted certificate", ErrEnrollmentTrustRejected, ekSPKI)
	}
	cert, err := x509.ParseCertificate(req.EKCertificateDER)
	if err != nil {
		return fmt.Errorf("%w: parse EK certificate: %v", ErrEnrollmentTrustRejected, err)
	}
	if !publicKeysEqual(cert.PublicKey, ekPublic) {
		return fmt.Errorf("%w: EK certificate public key does not match request EK", ErrEnrollmentTrustRejected)
	}
	now := time.Now()
	if policy.Now != nil {
		now = policy.Now()
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: policy.EKRoots, CurrentTime: now}); err != nil {
		return fmt.Errorf("%w: EK certificate verify: %v", ErrEnrollmentTrustRejected, err)
	}
	return nil
}

func CompleteTPMEnrollment(
	pending PendingTPMEnrollment,
	proof TPMEnrollmentProof,
	now time.Time,
) (EnrolledTPMIdentity, error) {
	if proof.Version != TPMEnrollmentProofVersion {
		return EnrolledTPMIdentity{}, fmt.Errorf("unsupported enrollment proof version %q", proof.Version)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if proof.EnrollmentID != pending.Challenge.EnrollmentID ||
		proof.DeviceID != pending.Challenge.DeviceID {
		return EnrolledTPMIdentity{}, ErrEnrollmentActivationFailed
	}
	if !now.Before(pending.Challenge.ExpiresAt) {
		return EnrolledTPMIdentity{}, ErrRemoteChallengeExpired
	}
	if subtle.ConstantTimeCompare(proof.Secret, pending.ExpectedSecret) != 1 {
		return EnrolledTPMIdentity{}, ErrEnrollmentActivationFailed
	}
	var certDigest string
	if len(pending.Request.EKCertificateDER) > 0 {
		sum := sha256.Sum256(pending.Request.EKCertificateDER)
		certDigest = "sha256:" + hex.EncodeToString(sum[:])
	}
	return EnrolledTPMIdentity{
		DeviceID:           pending.Request.DeviceID,
		AK:                 pending.Request.AK,
		EKSPKISHA256:       pending.EKSPKISHA256,
		EKCertificateSHA256: certDigest,
		TPMManufacturer:    pending.Request.TPMManufacturer,
		TPMVendorInfo:      pending.Request.TPMVendorInfo,
		TPMFirmwareMajor:   pending.Request.TPMFirmwareMajor,
		TPMFirmwareMinor:   pending.Request.TPMFirmwareMinor,
		EnrolledAt:         now.UTC(),
	}, nil
}

type RemoteAttestationChallenge struct {
	Version     string    `json:"version"`
	ChallengeID string    `json:"challenge_id"`
	DeviceID    string    `json:"device_id"`
	Nonce       []byte    `json:"nonce"`
	PCRBank     string    `json:"pcr_bank"`
	PCRs        []int     `json:"pcrs"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
}

func NewRemoteAttestationChallenge(
	deviceID string,
	ttl time.Duration,
	now time.Time,
) (RemoteAttestationChallenge, error) {
	if strings.TrimSpace(deviceID) == "" {
		return RemoteAttestationChallenge{}, errors.New("device id is required")
	}
	if ttl <= 0 {
		ttl = DefaultRemoteChallengeTTL
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	nonce := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return RemoteAttestationChallenge{}, fmt.Errorf("generate attestation nonce: %w", err)
	}
	challengeID, err := randomToken(24)
	if err != nil {
		return RemoteAttestationChallenge{}, err
	}
	pcrs := make([]int, 24)
	for i := range pcrs {
		pcrs[i] = i
	}
	return RemoteAttestationChallenge{
		Version:     RemoteAttestationChallengeVersion,
		ChallengeID: challengeID,
		DeviceID:    deviceID,
		Nonce:       nonce,
		PCRBank:     "sha256",
		PCRs:        pcrs,
		IssuedAt:    now.UTC(),
		ExpiresAt:   now.UTC().Add(ttl),
	}, nil
}

type AttestedPCR struct {
	Index  int    `json:"index"`
	Bank   string `json:"bank"`
	Digest []byte `json:"digest"`
}

type TPMQuoteEvidence struct {
	Quote     []byte `json:"quote"`
	Signature []byte `json:"signature"`
}

type RemoteAttestationEvidence struct {
	Version                string                 `json:"version"`
	DeviceID               string                 `json:"device_id"`
	ChallengeID            string                 `json:"challenge_id"`
	BootstrapReceipt       SignedBootstrapReceipt `json:"bootstrap_receipt"`
	Quote                  TPMQuoteEvidence       `json:"quote"`
	PCRs                   []AttestedPCR          `json:"pcrs"`
	PlatformEventLog       []byte                 `json:"platform_event_log"`
	IMASHA256Measurements  []byte                 `json:"ima_sha256_measurements"`
	CollectedAt            time.Time              `json:"collected_at"`
}

func RemoteQuoteNonce(
	challenge RemoteAttestationChallenge,
	receipt SignedBootstrapReceipt,
	imaMeasurements []byte,
	platformEventLog []byte,
) ([]byte, error) {
	if err := validateRemoteChallenge(challenge, time.Time{}); err != nil {
		return nil, err
	}
	receiptDigest, err := SignedBootstrapReceiptDigest(receipt)
	if err != nil {
		return nil, err
	}
	imaDigest := sha256.Sum256(imaMeasurements)
	eventDigest := sha256.Sum256(platformEventLog)
	challengePayload, err := canonicalRemoteChallengePayload(challenge)
	if err != nil {
		return nil, err
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/remote-attestation-quote/v1\x00"))
	h.Write(challengePayload)
	h.Write([]byte(receiptDigest))
	h.Write(imaDigest[:])
	h.Write(eventDigest[:])
	full := h.Sum(nil)
	return append([]byte(nil), full[:RemoteQuoteNonceSize]...), nil
}

func SignedBootstrapReceiptDigest(receipt SignedBootstrapReceipt) (string, error) {
	if err := ValidateBootstrapReceipt(receipt.Receipt); err != nil {
		return "", err
	}
	payload, err := json.Marshal(receipt)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(append([]byte("aegis-ege/signed-bootstrap-receipt/v1\x00"), payload...))
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

type RemoteAttestationPolicy struct {
	RequiredLockdownModes map[string]struct{}
	RequirePlatformEventLog bool
	RequireIMAReplay        bool
	VerifierKey             ed25519.PrivateKey
	VerifierID              string
	Now                     func() time.Time
}

type RemoteAttestationDecision struct {
	Version          string    `json:"version"`
	DecisionID       string    `json:"decision_id"`
	ChallengeID      string    `json:"challenge_id"`
	DeviceID         string    `json:"device_id"`
	Decision         string    `json:"decision"`
	ReasonCodes      []string  `json:"reason_codes,omitempty"`
	BootstrapDigest  string    `json:"bootstrap_digest"`
	AKPublicSHA256   string    `json:"ak_public_sha256"`
	PCR10SHA256      string    `json:"pcr10_sha256,omitempty"`
	IMAReplaySHA256  string    `json:"ima_replay_sha256,omitempty"`
	VerifiedAt       time.Time `json:"verified_at"`
	VerifierID       string    `json:"verifier_id"`
}

type SignedRemoteAttestationDecision struct {
	Decision  RemoteAttestationDecision `json:"decision"`
	KeyID     string                    `json:"key_id"`
	Signature string                    `json:"signature"`
}

func VerifyRemoteAttestation(
	challenge RemoteAttestationChallenge,
	identity EnrolledTPMIdentity,
	evidence RemoteAttestationEvidence,
	policy RemoteAttestationPolicy,
) (SignedRemoteAttestationDecision, error) {
	now := time.Now().UTC()
	if policy.Now != nil {
		now = policy.Now().UTC()
	}
	if err := validateRemoteChallenge(challenge, now); err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	if evidence.Version != RemoteAttestationEvidenceVersion ||
		evidence.DeviceID != identity.DeviceID ||
		evidence.DeviceID != challenge.DeviceID ||
		evidence.ChallengeID != challenge.ChallengeID {
		return SignedRemoteAttestationDecision{}, ErrRemoteAttestationInvalid
	}
	if err := ValidateBootstrapReceipt(evidence.BootstrapReceipt.Receipt); err != nil {
		return SignedRemoteAttestationDecision{}, fmt.Errorf("%w: bootstrap receipt: %v", ErrRemoteAttestationInvalid, err)
	}
	if len(policy.RequiredLockdownModes) > 0 {
		if _, ok := policy.RequiredLockdownModes[evidence.BootstrapReceipt.Receipt.Host.LockdownMode]; !ok {
			return signRemoteDecision(blockRemoteDecision(
				challenge, identity, evidence, now,
				"LOCKDOWN_MODE_NOT_ALLOWED",
			), policy)
		}
	}

	nonce, err := RemoteQuoteNonce(
		challenge,
		evidence.BootstrapReceipt,
		evidence.IMASHA256Measurements,
		evidence.PlatformEventLog,
	)
	if err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	akPublic, err := attest.ParseAKPublic(identity.AK.Public)
	if err != nil {
		return SignedRemoteAttestationDecision{}, fmt.Errorf("%w: parse enrolled AK: %v", ErrRemoteAttestationInvalid, err)
	}
	pcrs, err := wirePCRsToAttest(evidence.PCRs, challenge)
	if err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	quote := attest.Quote{
		Quote:     evidence.Quote.Quote,
		Signature: evidence.Quote.Signature,
	}
	if err := akPublic.VerifyAll([]attest.Quote{quote}, pcrs, nonce); err != nil {
		return signRemoteDecision(blockRemoteDecision(
			challenge, identity, evidence, now,
			"TPM_QUOTE_INVALID",
		), policy)
	}

	if policy.RequirePlatformEventLog {
		eventLog, err := attest.ParseEventLog(evidence.PlatformEventLog)
		if err != nil {
			return signRemoteDecision(blockRemoteDecision(
				challenge, identity, evidence, now,
				"PLATFORM_EVENT_LOG_PARSE_FAILED",
			), policy)
		}
		if _, err := eventLog.Verify(pcrs); err != nil {
			return signRemoteDecision(blockRemoteDecision(
				challenge, identity, evidence, now,
				"PLATFORM_EVENT_LOG_REPLAY_FAILED",
			), policy)
		}
	}

	pcr10, err := findPCRDigest(pcrs, 10, crypto.SHA256)
	if err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	var replayDigest []byte
	if policy.RequireIMAReplay {
		replayDigest, err = ReplayIMASHA256PCR10(evidence.IMASHA256Measurements)
		if err != nil {
			return signRemoteDecision(blockRemoteDecision(
				challenge, identity, evidence, now,
				"IMA_REPLAY_FAILED",
			), policy)
		}
		if !bytes.Equal(replayDigest, pcr10) {
			return signRemoteDecision(blockRemoteDecision(
				challenge, identity, evidence, now,
				"IMA_PCR10_MISMATCH",
			), policy)
		}
	}

	decision := baseRemoteDecision(challenge, identity, evidence, now)
	decision.Decision = "ALLOW"
	decision.ReasonCodes = []string{"TPM_QUOTE_VERIFIED"}
	if policy.RequirePlatformEventLog {
		decision.ReasonCodes = append(decision.ReasonCodes, "PLATFORM_EVENT_LOG_VERIFIED")
	}
	if policy.RequireIMAReplay {
		decision.ReasonCodes = append(decision.ReasonCodes, "IMA_PCR10_REPLAY_VERIFIED")
		decision.IMAReplaySHA256 = "sha256:" + hex.EncodeToString(replayDigest)
	}
	decision.PCR10SHA256 = "sha256:" + hex.EncodeToString(pcr10)
	return signRemoteDecision(decision, policy)
}

func wirePCRsToAttest(in []AttestedPCR, challenge RemoteAttestationChallenge) ([]attest.PCR, error) {
	if challenge.PCRBank != "sha256" {
		return nil, fmt.Errorf("%w: unsupported PCR bank %q", ErrRemoteAttestationInvalid, challenge.PCRBank)
	}
	expected := map[int]struct{}{}
	for _, idx := range challenge.PCRs {
		expected[idx] = struct{}{}
	}
	seen := map[int]struct{}{}
	out := make([]attest.PCR, 0, len(in))
	for _, p := range in {
		if p.Bank != "sha256" || len(p.Digest) != sha256.Size {
			return nil, fmt.Errorf("%w: invalid PCR %d encoding", ErrRemoteAttestationInvalid, p.Index)
		}
		if _, ok := expected[p.Index]; !ok {
			continue
		}
		if _, dup := seen[p.Index]; dup {
			return nil, fmt.Errorf("%w: duplicate PCR %d", ErrRemoteAttestationInvalid, p.Index)
		}
		seen[p.Index] = struct{}{}
		out = append(out, attest.PCR{
			Index:     p.Index,
			Digest:    append([]byte(nil), p.Digest...),
			DigestAlg: crypto.SHA256,
		})
	}
	if len(seen) != len(expected) {
		return nil, fmt.Errorf("%w: evidence covers %d/%d requested PCRs", ErrRemoteAttestationInvalid, len(seen), len(expected))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

func findPCRDigest(pcrs []attest.PCR, index int, alg crypto.Hash) ([]byte, error) {
	for _, p := range pcrs {
		if p.Index == index && p.DigestAlg == alg {
			return append([]byte(nil), p.Digest...), nil
		}
	}
	return nil, fmt.Errorf("%w: PCR %d not present", ErrRemoteAttestationInvalid, index)
}

func baseRemoteDecision(
	challenge RemoteAttestationChallenge,
	identity EnrolledTPMIdentity,
	evidence RemoteAttestationEvidence,
	now time.Time,
) RemoteAttestationDecision {
	bootstrapDigest, _ := SignedBootstrapReceiptDigest(evidence.BootstrapReceipt)
	akHash := sha256.Sum256(identity.AK.Public)
	decisionID, _ := randomToken(24)
	return RemoteAttestationDecision{
		Version:         RemoteAttestationDecisionVersion,
		DecisionID:      decisionID,
		ChallengeID:     challenge.ChallengeID,
		DeviceID:        challenge.DeviceID,
		BootstrapDigest: bootstrapDigest,
		AKPublicSHA256:  "sha256:" + hex.EncodeToString(akHash[:]),
		VerifiedAt:      now.UTC(),
	}
}

func blockRemoteDecision(
	challenge RemoteAttestationChallenge,
	identity EnrolledTPMIdentity,
	evidence RemoteAttestationEvidence,
	now time.Time,
	reason string,
) RemoteAttestationDecision {
	d := baseRemoteDecision(challenge, identity, evidence, now)
	d.Decision = "BLOCK"
	d.ReasonCodes = []string{reason}
	return d
}

func signRemoteDecision(
	decision RemoteAttestationDecision,
	policy RemoteAttestationPolicy,
) (SignedRemoteAttestationDecision, error) {
	if len(policy.VerifierKey) != ed25519.PrivateKeySize {
		return SignedRemoteAttestationDecision{}, errors.New("remote attestation verifier signing key is required")
	}
	decision.VerifierID = strings.TrimSpace(policy.VerifierID)
	if decision.VerifierID == "" {
		return SignedRemoteAttestationDecision{}, errors.New("remote attestation verifier id is required")
	}
	payload, err := canonicalRemoteDecisionPayload(decision)
	if err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	keyID, err := BootstrapKeyID(policy.VerifierKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRemoteAttestationDecision{}, err
	}
	return SignedRemoteAttestationDecision{
		Decision:  decision,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(policy.VerifierKey, payload)),
	}, nil
}

func VerifySignedRemoteAttestationDecision(
	signed SignedRemoteAttestationDecision,
	publicKey ed25519.PublicKey,
) error {
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return ErrBootstrapSignatureInvalid
	}
	sig, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalRemoteDecisionPayload(signed.Decision)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, sig) {
		return ErrBootstrapSignatureInvalid
	}
	return nil
}

func validateRemoteChallenge(challenge RemoteAttestationChallenge, now time.Time) error {
	if challenge.Version != RemoteAttestationChallengeVersion ||
		strings.TrimSpace(challenge.ChallengeID) == "" ||
		strings.TrimSpace(challenge.DeviceID) == "" ||
		len(challenge.Nonce) < 16 ||
		challenge.PCRBank != "sha256" ||
		len(challenge.PCRs) == 0 ||
		challenge.IssuedAt.IsZero() ||
		challenge.ExpiresAt.IsZero() ||
		!challenge.ExpiresAt.After(challenge.IssuedAt) {
		return ErrRemoteAttestationInvalid
	}
	if !now.IsZero() && !now.Before(challenge.ExpiresAt) {
		return ErrRemoteChallengeExpired
	}
	return nil
}

func canonicalRemoteChallengePayload(challenge RemoteAttestationChallenge) ([]byte, error) {
	c := challenge
	c.IssuedAt = c.IssuedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	c.PCRs = append([]int(nil), c.PCRs...)
	sort.Ints(c.PCRs)
	body, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/remote-attestation-challenge/v1\x00"), body...), nil
}

func canonicalRemoteDecisionPayload(decision RemoteAttestationDecision) ([]byte, error) {
	d := decision
	d.VerifiedAt = d.VerifiedAt.UTC()
	d.ReasonCodes = append([]string(nil), d.ReasonCodes...)
	sort.Strings(d.ReasonCodes)
	body, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	return append([]byte("aegis-ege/remote-attestation-decision/v1\x00"), body...), nil
}

func randomToken(size int) (string, error) {
	raw := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func publicKeysEqual(a, b crypto.PublicKey) bool {
	aDER, errA := x509.MarshalPKIXPublicKey(a)
	bDER, errB := x509.MarshalPKIXPublicKey(b)
	return errA == nil && errB == nil && bytes.Equal(aDER, bDER)
}
