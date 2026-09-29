package genesisbootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ucarion/jcs"

	"github.com/achirothmane/easl"
	"github.com/achirothmane/easl/genesis"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const (
	BundleVersion                     = "aegis.ege/genesis-verification-bundle/v2"
	AssuranceProfileVersion           = "aegis.ege/genesis-assurance/v2"
	BuildProvenanceStatementVersion   = "aegis.ege/build-provenance/v1"
	ProofVerificationRecordVersion    = "aegis.ege/proof-verification-record/v1"
	RevocationListVersion             = "aegis.ege/genesis-revocations/v1"
	DoctrineAuthorityStatementVersion = "aegis.ege/doctrine-authority-statement/v1"
	maxExactJSONInteger               = uint64(1<<53 - 1)
)

type ArtifactPaths struct {
	Specification      string `json:"specification"`
	InvariantSet       string `json:"invariant_set"`
	AssumptionSet      string `json:"assumption_set"`
	ForbiddenStateSet  string `json:"forbidden_state_set"`
	TauBounds          string `json:"tau_bounds"`
	ProofScope         string `json:"proof_scope"`
	ThreatModel        string `json:"threat_model"`
	CapabilityEnvelope string `json:"capability_envelope"`
	AttestationPolicy  string `json:"attestation_policy"`
	NoncePolicy        string `json:"nonce_policy"`
	EnforcementPolicy  string `json:"enforcement_policy"`
	RefinementMapping  string `json:"refinement_mapping"`
	ExecutableContract string `json:"executable_contract"`
	BuildProvenance    string `json:"build_provenance"`
	Materials          string `json:"materials"`
	SBOM               string `json:"sbom"`
	ApprovalPolicy     string `json:"approval_policy"`
}

type RelyingContext struct {
	ExpectedManifestPayloadHash string `json:"expected_manifest_payload_hash"`
	ExpectedDeviceID            string `json:"expected_device_id"`
	ExpectedChallengeID         string `json:"expected_challenge_id"`
}

type CurrentSubject struct {
	BootIDHash string
}

type VerificationBundle struct {
	Version                            string        `json:"version"`
	AssuranceProfile                   string        `json:"assurance_profile"`
	RelyingContext                     RelyingContext `json:"relying_context"`
	DoctrineManifest                   string        `json:"doctrine_manifest"`
	SignedDoctrineAuthorityStatement   string        `json:"signed_doctrine_authority_statement"`
	DoctrineAuthorityPublicKey         string        `json:"doctrine_authority_public_key"`
	ManifestSignerPublicKey            string        `json:"manifest_signer_public_key"`
	RemoteAttestationDecision          string        `json:"remote_attestation_decision"`
	RemoteAttestationVerifierPublicKey string        `json:"remote_attestation_verifier_public_key"`
	BootstrapReceipt                   string        `json:"bootstrap_receipt"`
	BootstrapAttestorPublicKey         string        `json:"bootstrap_attestor_public_key"`
	SignedRevocationList               string        `json:"signed_revocation_list"`
	RevocationAuthorityPublicKey       string        `json:"revocation_authority_public_key"`
	MaxAttestationAgeSeconds           int64         `json:"max_attestation_age_seconds"`
	Artifacts                          ArtifactPaths `json:"artifacts"`
	ProofArtifactPaths                 []string      `json:"proof_artifact_paths"`
}


type DoctrineAuthorityStatement struct {
	Version              string    `json:"version"`
	DoctrineID           string    `json:"doctrine_id"`
	DoctrineEpoch        uint64    `json:"doctrine_epoch"`
	DoctrineManifestHash string    `json:"doctrine_manifest_hash"`
	IssuedAt             time.Time `json:"issued_at"`
	ExpiresAt            time.Time `json:"expires_at"`
}

type SignedDoctrineAuthorityStatement struct {
	Statement DoctrineAuthorityStatement `json:"statement"`
	KeyID     string                     `json:"key_id"`
	Signature string                     `json:"signature"`
}

type RevocationList struct {
	Version                      string    `json:"version"`
	Epoch                        uint64    `json:"epoch"`
	MinimumAcceptedGenesisEpoch  uint64    `json:"minimum_accepted_genesis_epoch"`
	MinimumAcceptedDoctrineEpoch uint64    `json:"minimum_accepted_doctrine_epoch"`
	MinimumTrustRootEpoch        uint64    `json:"minimum_trust_root_epoch"`
	IssuedAt                    time.Time `json:"issued_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
	RevokedManifestHashes       []string  `json:"revoked_manifest_hashes,omitempty"`
	RevokedSignerKeyIDs         []string  `json:"revoked_signer_key_ids,omitempty"`
	RevokedTrustRootRefs        []string  `json:"revoked_trust_root_refs,omitempty"`
}

type SignedRevocationList struct {
	List      RevocationList `json:"list"`
	KeyID     string         `json:"key_id"`
	Signature string         `json:"signature"`
}

type BuildProvenanceStatement struct {
	Version                     string    `json:"version"`
	BuilderIdentity             string    `json:"builder_identity"`
	SourceRevision              string    `json:"source_revision"`
	SubjectImplementationDigest string    `json:"subject_implementation_digest"`
	MaterialsHash               string    `json:"materials_hash"`
	SBOMHash                    string    `json:"sbom_hash"`
	BuiltAt                     time.Time `json:"built_at"`
	IssuedAt                    time.Time `json:"issued_at"`
	ExpiresAt                   time.Time `json:"expires_at"`
}

type SignedBuildProvenanceStatement struct {
	Statement BuildProvenanceStatement `json:"statement"`
	KeyID     string                   `json:"key_id"`
	Signature string                   `json:"signature"`
}

type ProofVerificationRecord struct {
	Version          string    `json:"version"`
	Result           string    `json:"result"`
	VerificationMode string    `json:"verification_mode"`
	SpecHash         string    `json:"spec_hash"`
	ProofScopeHash   string    `json:"proof_scope_hash"`
	Toolchain        []string  `json:"toolchain"`
	ModelBounds      []string  `json:"model_bounds"`
	CheckedAt        time.Time `json:"checked_at"`
}

type ProductionVerifier struct {
	now                 time.Time
	bundle              VerificationBundle
	currentSubject      CurrentSubject
	doctrineAuthority   ed25519.PublicKey
	doctrineStatement   SignedDoctrineAuthorityStatement
	doctrineDigest      string
	manifestSigner      ed25519.PublicKey
	remoteVerifier      ed25519.PublicKey
	bootstrapAttestor   ed25519.PublicKey
	revocationAuthority ed25519.PublicKey
	remoteDecision      kernelfabric.SignedRemoteAttestationDecision
	bootstrapReceipt    kernelfabric.SignedBootstrapReceipt
	revocations         SignedRevocationList
	buildProvenance     SignedBuildProvenanceStatement
	proofRecords        []ProofVerificationRecord
	executableDigest    string
}

func BootstrapProduction(
	ctx context.Context,
	manifestPath string,
	bundlePath string,
	minimumAcceptedEpoch uint64,
	minimumAcceptedDoctrineEpoch uint64,
	requiredConformance genesis.ConformanceLevel,
	now time.Time,
) (*easl.Runtime, genesis.Result, error) {
	subject, err := CurrentProductionSubject("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, genesis.Result{State: genesis.StateLocked}, fmt.Errorf("capture current Genesis subject: %w", err)
	}
	return BootstrapProductionWithSubject(
		ctx,
		manifestPath,
		bundlePath,
		minimumAcceptedEpoch,
		minimumAcceptedDoctrineEpoch,
		requiredConformance,
		subject,
		now,
	)
}

func BootstrapProductionWithSubject(
	ctx context.Context,
	manifestPath string,
	bundlePath string,
	minimumAcceptedEpoch uint64,
	minimumAcceptedDoctrineEpoch uint64,
	requiredConformance genesis.ConformanceLevel,
	subject CurrentSubject,
	now time.Time,
) (*easl.Runtime, genesis.Result, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}

	manifest, err := LoadManifest(manifestPath)
	if err != nil {
		return nil, genesis.Result{State: genesis.StateLocked}, fmt.Errorf("load Genesis manifest: %w", err)
	}
	bundle, err := LoadVerificationBundle(bundlePath)
	if err != nil {
		return nil, genesis.Result{State: genesis.StateLocked}, fmt.Errorf("load Genesis verification bundle: %w", err)
	}
	verifier, err := NewProductionVerifier(bundle, subject, now)
	if err != nil {
		return nil, genesis.Result{State: genesis.StateLocked}, fmt.Errorf("construct production Genesis verifier: %w", err)
	}

	runtime, result := easl.Bootstrap(ctx, easl.BootstrapInput{
		Manifest: manifest,
		Verification: genesis.Context{
			Now:                          now,
			MinimumAcceptedEpoch:         maxUint64(minimumAcceptedEpoch, verifier.revocations.List.MinimumAcceptedGenesisEpoch),
			MinimumAcceptedDoctrineEpoch: maxUint64(minimumAcceptedDoctrineEpoch, verifier.revocations.List.MinimumAcceptedDoctrineEpoch),
			ExpectedDoctrineManifestHash: verifier.doctrineDigest,
			ExpectedImplementationDigest: verifier.executableDigest,
			RequiredConformance:          requiredConformance,
		},
		Verifier: verifier,
	})
	if result.State != genesis.StateReady || runtime == nil {
		return nil, result, fmt.Errorf("Genesis verification did not reach BOOTSTRAP_READY")
	}
	return runtime, result, nil
}

func NewProductionVerifier(bundle VerificationBundle, subject CurrentSubject, now time.Time) (*ProductionVerifier, error) {
	if bundle.Version != BundleVersion {
		return nil, fmt.Errorf("unsupported verification bundle version %q", bundle.Version)
	}
	if bundle.AssuranceProfile != AssuranceProfileVersion {
		return nil, fmt.Errorf("unsupported Genesis assurance profile %q", bundle.AssuranceProfile)
	}
	if !strings.HasPrefix(bundle.RelyingContext.ExpectedManifestPayloadHash, "sha256:") {
		return nil, errors.New("expected_manifest_payload_hash must be a sha256 digest")
	}
	if strings.TrimSpace(bundle.RelyingContext.ExpectedDeviceID) == "" {
		return nil, errors.New("expected_device_id is required")
	}
	if strings.TrimSpace(bundle.RelyingContext.ExpectedChallengeID) == "" {
		return nil, errors.New("expected_challenge_id is required")
	}
	if !strings.HasPrefix(subject.BootIDHash, "sha256:") {
		return nil, errors.New("current subject boot id hash is required")
	}
	if bundle.MaxAttestationAgeSeconds <= 0 {
		return nil, errors.New("max_attestation_age_seconds must be positive")
	}
	requiredPaths := map[string]string{
		"doctrine_manifest":                       bundle.DoctrineManifest,
		"signed_doctrine_authority_statement":     bundle.SignedDoctrineAuthorityStatement,
		"doctrine_authority_public_key":           bundle.DoctrineAuthorityPublicKey,
		"manifest_signer_public_key":               bundle.ManifestSignerPublicKey,
		"remote_attestation_decision":            bundle.RemoteAttestationDecision,
		"remote_attestation_verifier_public_key": bundle.RemoteAttestationVerifierPublicKey,
		"bootstrap_receipt":                      bundle.BootstrapReceipt,
		"bootstrap_attestor_public_key":          bundle.BootstrapAttestorPublicKey,
		"signed_revocation_list":                 bundle.SignedRevocationList,
		"revocation_authority_public_key":        bundle.RevocationAuthorityPublicKey,
	}
	for name, path := range requiredPaths {
		if strings.TrimSpace(path) == "" {
			return nil, fmt.Errorf("%s is required", name)
		}
	}

	doctrineAuthority, err := kernelfabric.LoadEd25519PublicKey(bundle.DoctrineAuthorityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load doctrine authority public key: %w", err)
	}
	var doctrineStatement SignedDoctrineAuthorityStatement
	if err := readStrictJSON(bundle.SignedDoctrineAuthorityStatement, &doctrineStatement); err != nil {
		return nil, fmt.Errorf("read doctrine authority statement: %w", err)
	}
	doctrineDigest, err := fileDigest(bundle.DoctrineManifest)
	if err != nil {
		return nil, fmt.Errorf("hash doctrine manifest: %w", err)
	}

	manifestSigner, err := kernelfabric.LoadEd25519PublicKey(bundle.ManifestSignerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load manifest signer public key: %w", err)
	}
	remoteVerifier, err := kernelfabric.LoadEd25519PublicKey(bundle.RemoteAttestationVerifierPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load remote attestation verifier public key: %w", err)
	}
	bootstrapAttestor, err := kernelfabric.LoadEd25519PublicKey(bundle.BootstrapAttestorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load bootstrap attestor public key: %w", err)
	}
	revocationAuthority, err := kernelfabric.LoadEd25519PublicKey(bundle.RevocationAuthorityPublicKey)
	if err != nil {
		return nil, fmt.Errorf("load revocation authority public key: %w", err)
	}

	var remoteDecision kernelfabric.SignedRemoteAttestationDecision
	if err := readStrictJSON(bundle.RemoteAttestationDecision, &remoteDecision); err != nil {
		return nil, fmt.Errorf("read remote attestation decision: %w", err)
	}
	var bootstrapReceipt kernelfabric.SignedBootstrapReceipt
	if err := readStrictJSON(bundle.BootstrapReceipt, &bootstrapReceipt); err != nil {
		return nil, fmt.Errorf("read bootstrap receipt: %w", err)
	}
	var revocations SignedRevocationList
	if err := readStrictJSON(bundle.SignedRevocationList, &revocations); err != nil {
		return nil, fmt.Errorf("read revocation list: %w", err)
	}
	var buildProvenance SignedBuildProvenanceStatement
	if err := readStrictJSON(bundle.Artifacts.BuildProvenance, &buildProvenance); err != nil {
		return nil, fmt.Errorf("read signed build provenance: %w", err)
	}
	proofRecords := make([]ProofVerificationRecord, 0, len(bundle.ProofArtifactPaths))
	for i, path := range bundle.ProofArtifactPaths {
		var record ProofVerificationRecord
		if err := readStrictJSON(path, &record); err != nil {
			return nil, fmt.Errorf("read proof verification record %d: %w", i, err)
		}
		proofRecords = append(proofRecords, record)
	}

	executableDigest, err := currentExecutableDigest()
	if err != nil {
		return nil, err
	}

	return &ProductionVerifier{
		now:                 now.UTC(),
		bundle:              bundle,
		currentSubject:      subject,
		doctrineAuthority:   doctrineAuthority,
		doctrineStatement:   doctrineStatement,
		doctrineDigest:      doctrineDigest,
		manifestSigner:      manifestSigner,
		remoteVerifier:      remoteVerifier,
		bootstrapAttestor:   bootstrapAttestor,
		revocationAuthority: revocationAuthority,
		remoteDecision:      remoteDecision,
		bootstrapReceipt:    bootstrapReceipt,
		revocations:         revocations,
		buildProvenance:     buildProvenance,
		proofRecords:        proofRecords,
		executableDigest:    executableDigest,
	}, nil
}


func CurrentProductionSubject(bootIDPath string) (CurrentSubject, error) {
	bootHash, err := kernelfabric.ReadBootIDHash(bootIDPath)
	if err != nil {
		return CurrentSubject{}, err
	}
	return CurrentSubject{
		BootIDHash: "sha256:" + hex.EncodeToString(bootHash[:]),
	}, nil
}

func (v *ProductionVerifier) VerifyDoctrineBinding(_ context.Context, m genesis.Manifest) error {
	if err := VerifySignedDoctrineAuthorityStatement(v.doctrineStatement, v.doctrineAuthority, v.now); err != nil {
		return err
	}
	statement := v.doctrineStatement.Statement
	if v.doctrineDigest != statement.DoctrineManifestHash {
		return fmt.Errorf("doctrine manifest file digest %s does not match authority statement %s", v.doctrineDigest, statement.DoctrineManifestHash)
	}
	if m.Doctrine.DoctrineID != statement.DoctrineID {
		return fmt.Errorf("Genesis doctrine_id %q does not match authority statement %q", m.Doctrine.DoctrineID, statement.DoctrineID)
	}
	if m.Doctrine.DoctrineEpoch != statement.DoctrineEpoch {
		return fmt.Errorf("Genesis doctrine epoch %d does not match authority statement %d", m.Doctrine.DoctrineEpoch, statement.DoctrineEpoch)
	}
	if m.Doctrine.DoctrineManifestHash != statement.DoctrineManifestHash {
		return fmt.Errorf("Genesis doctrine manifest hash %s does not match authority statement %s", m.Doctrine.DoctrineManifestHash, statement.DoctrineManifestHash)
	}
	return nil
}

func (v *ProductionVerifier) VerifyAuthenticity(_ context.Context, m genesis.Manifest) error {
	payloadHash, err := ManifestPayloadHash(m)
	if err != nil {
		return err
	}
	if payloadHash != v.bundle.RelyingContext.ExpectedManifestPayloadHash {
		return fmt.Errorf(
			"Genesis manifest payload hash %s does not match relying-context pin %s",
			payloadHash,
			v.bundle.RelyingContext.ExpectedManifestPayloadHash,
		)
	}
	if m.Authenticity.SignatureAlgorithm != "ed25519" {
		return fmt.Errorf("unsupported Genesis signature algorithm %q", m.Authenticity.SignatureAlgorithm)
	}
	keyID, err := kernelfabric.BootstrapKeyID(v.manifestSigner)
	if err != nil {
		return err
	}
	if m.Authenticity.SignerKeyID != keyID {
		return fmt.Errorf("manifest signer key id %q does not match trusted key %q", m.Authenticity.SignerKeyID, keyID)
	}
	payload, err := CanonicalManifestPayload(m)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	actualHash := "sha256:" + hex.EncodeToString(sum[:])
	if actualHash != m.Authenticity.SignedPayloadHash {
		return fmt.Errorf("signed payload hash mismatch: got %s want %s", actualHash, m.Authenticity.SignedPayloadHash)
	}
	signature, err := base64.StdEncoding.DecodeString(m.Authenticity.Signature)
	if err != nil {
		return fmt.Errorf("decode manifest signature: %w", err)
	}
	if !ed25519.Verify(v.manifestSigner, payload, signature) {
		return errors.New("Genesis manifest Ed25519 signature is invalid")
	}
	return nil
}

func (v *ProductionVerifier) VerifyTrustRoot(_ context.Context, m genesis.Manifest) error {
	keyID, err := kernelfabric.BootstrapKeyID(v.remoteVerifier)
	if err != nil {
		return err
	}
	if m.Trust.TrustRootRef != keyID {
		return fmt.Errorf("trust_root_ref %q does not match remote attestation verifier key %q", m.Trust.TrustRootRef, keyID)
	}
	if m.Trust.TrustRootEpoch < v.revocations.List.MinimumTrustRootEpoch {
		return fmt.Errorf("trust root epoch %d is below revocation floor %d", m.Trust.TrustRootEpoch, v.revocations.List.MinimumTrustRootEpoch)
	}
	return nil
}

func (v *ProductionVerifier) VerifyAttestation(_ context.Context, _ genesis.Manifest) error {
	if err := kernelfabric.VerifySignedRemoteAttestationDecision(v.remoteDecision, v.remoteVerifier); err != nil {
		return fmt.Errorf("verify signed remote attestation decision: %w", err)
	}
	decision := v.remoteDecision.Decision
	if decision.DeviceID != v.bundle.RelyingContext.ExpectedDeviceID {
		return fmt.Errorf(
			"remote attestation device %q does not match relying-context device %q",
			decision.DeviceID,
			v.bundle.RelyingContext.ExpectedDeviceID,
		)
	}
	if decision.ChallengeID != v.bundle.RelyingContext.ExpectedChallengeID {
		return fmt.Errorf(
			"remote attestation challenge %q does not match relying-context challenge %q",
			decision.ChallengeID,
			v.bundle.RelyingContext.ExpectedChallengeID,
		)
	}
	if decision.Decision != "ALLOW" {
		return fmt.Errorf("remote attestation decision is %q", decision.Decision)
	}
	if decision.VerifiedAt.IsZero() {
		return errors.New("remote attestation verified_at is missing")
	}
	if decision.VerifiedAt.After(v.now.Add(5 * time.Second)) {
		return errors.New("remote attestation decision is unreasonably in the future")
	}
	maxAge := time.Duration(v.bundle.MaxAttestationAgeSeconds) * time.Second
	if !v.now.Before(decision.VerifiedAt.Add(maxAge)) {
		return fmt.Errorf("remote attestation decision is older than %s", maxAge)
	}
	if err := kernelfabric.VerifySignedBootstrapReceipt(v.bootstrapReceipt, v.bootstrapAttestor); err != nil {
		return fmt.Errorf("verify signed bootstrap receipt: %w", err)
	}
	receipt := v.bootstrapReceipt.Receipt
	if receipt.Host.BootIDHash != v.currentSubject.BootIDHash {
		return fmt.Errorf(
			"bootstrap receipt boot %s does not match current boot %s",
			receipt.Host.BootIDHash,
			v.currentSubject.BootIDHash,
		)
	}
	if receipt.CompletedAt.IsZero() {
		return errors.New("bootstrap receipt completed_at is missing")
	}
	if receipt.CompletedAt.After(decision.VerifiedAt) {
		return errors.New("bootstrap receipt is newer than the remote attestation decision")
	}
	maxAge = time.Duration(v.bundle.MaxAttestationAgeSeconds) * time.Second
	if !v.now.Before(receipt.CompletedAt.UTC().Add(maxAge)) {
		return fmt.Errorf("bootstrap receipt is older than %s", maxAge)
	}
	receiptDigest, err := kernelfabric.SignedBootstrapReceiptDigest(v.bootstrapReceipt)
	if err != nil {
		return err
	}
	if decision.BootstrapDigest != receiptDigest {
		return fmt.Errorf("remote attestation bootstrap digest %s does not bind supplied receipt %s", decision.BootstrapDigest, receiptDigest)
	}
	requiredReasons := []string{
		"TPM_QUOTE_VERIFIED",
		"PLATFORM_EVENT_LOG_VERIFIED",
		"BPF_ARTIFACT_IMA_MEASURED",
		"IMA_PCR10_REPLAY_VERIFIED",
	}
	for _, required := range requiredReasons {
		if !containsString(decision.ReasonCodes, required) {
			return fmt.Errorf("remote attestation decision is missing required assurance reason %s", required)
		}
	}
	return nil
}

func (v *ProductionVerifier) VerifyRevocation(_ context.Context, m genesis.Manifest) error {
	if err := VerifySignedRevocationList(v.revocations, v.revocationAuthority, v.now); err != nil {
		return err
	}
	digest, err := SignedRevocationListDigest(v.revocations)
	if err != nil {
		return err
	}
	if m.Trust.RevocationRef != digest {
		return fmt.Errorf("revocation_ref %q does not bind supplied signed revocation list %q", m.Trust.RevocationRef, digest)
	}
	if m.GenesisEpoch < v.revocations.List.MinimumAcceptedGenesisEpoch {
		return fmt.Errorf("Genesis epoch %d is below revocation floor %d", m.GenesisEpoch, v.revocations.List.MinimumAcceptedGenesisEpoch)
	}
	revocationHash, err := ManifestRevocationHash(m)
	if err != nil {
		return err
	}
	if containsString(v.revocations.List.RevokedManifestHashes, revocationHash) {
		return errors.New("Genesis manifest revocation id is revoked")
	}
	if containsString(v.revocations.List.RevokedSignerKeyIDs, m.Authenticity.SignerKeyID) {
		return errors.New("Genesis manifest signer is revoked")
	}
	if containsString(v.revocations.List.RevokedTrustRootRefs, m.Trust.TrustRootRef) {
		return errors.New("Genesis trust root is revoked")
	}
	return nil
}

func (v *ProductionVerifier) VerifyBuildProvenance(_ context.Context, m genesis.Manifest) error {
	if !strings.HasPrefix(m.SupplyChain.BuildProvenanceRef, "sha256:") {
		return errors.New("production Genesis profile requires build_provenance_ref to be a sha256 digest")
	}
	digest, err := fileDigest(v.bundle.Artifacts.BuildProvenance)
	if err != nil {
		return fmt.Errorf("hash build provenance: %w", err)
	}
	if digest != m.SupplyChain.BuildProvenanceRef {
		return fmt.Errorf("build provenance digest %s does not match manifest %s", digest, m.SupplyChain.BuildProvenanceRef)
	}
	if err := VerifySignedBuildProvenanceStatement(
		v.buildProvenance,
		v.manifestSigner,
		v.now,
	); err != nil {
		return fmt.Errorf("verify signed build provenance: %w", err)
	}
	statement := v.buildProvenance.Statement
	switch {
	case statement.BuilderIdentity != m.SupplyChain.BuilderIdentity:
		return fmt.Errorf(
			"provenance builder %q does not match manifest builder %q",
			statement.BuilderIdentity,
			m.SupplyChain.BuilderIdentity,
		)
	case statement.SourceRevision != m.SupplyChain.SourceRevision:
		return fmt.Errorf(
			"provenance source revision %q does not match manifest source revision %q",
			statement.SourceRevision,
			m.SupplyChain.SourceRevision,
		)
	case statement.SubjectImplementationDigest != m.Implementation.ImplementationDigest:
		return errors.New("provenance subject binary digest does not match Genesis implementation digest")
	case statement.SubjectImplementationDigest != v.executableDigest:
		return errors.New("provenance subject binary digest does not match running executable")
	case statement.MaterialsHash != m.SupplyChain.MaterialsHash:
		return errors.New("provenance materials hash does not match manifest")
	case statement.SBOMHash != m.SupplyChain.SBOMHash:
		return errors.New("provenance SBOM hash does not match manifest")
	case !statement.BuiltAt.Equal(m.Validity.BuiltAt):
		return errors.New("provenance built_at does not match manifest validity.built_at")
	}
	return nil
}

func (v *ProductionVerifier) VerifySpecBuildBinding(_ context.Context, m genesis.Manifest) error {
	if m.Implementation.ConformanceLevel == genesis.ConformanceC4 {
		return errors.New("production Genesis assurance v2 does not implement C4 formal refinement or verified-compilation verification")
	}
	if v.executableDigest != m.Implementation.ImplementationDigest {
		return fmt.Errorf("running executable digest %s does not match manifest %s", v.executableDigest, m.Implementation.ImplementationDigest)
	}
	if err := verifyFileDigest("refinement_mapping_hash", v.bundle.Artifacts.RefinementMapping, m.Implementation.RefinementMappingHash); err != nil {
		return err
	}
	if err := verifyFileDigest("executable_contract_hash", v.bundle.Artifacts.ExecutableContract, m.Implementation.ExecutableContractHash); err != nil {
		return err
	}
	return nil
}

func (v *ProductionVerifier) VerifyDefaultDeny(_ context.Context, m genesis.Manifest) error {
	if !m.Enforcement.DefaultDenyRequired {
		return errors.New("manifest does not require default deny")
	}
	programs := map[string]bool{}
	for _, program := range v.bootstrapReceipt.Receipt.Programs {
		programs[program.PinName] = true
	}
	for _, required := range []string{"aegis_connect4", "aegis_connect6"} {
		if !programs[required] {
			return fmt.Errorf("bootstrap receipt does not attest required enforcement program %s", required)
		}
	}
	maps := map[string]bool{}
	for _, item := range v.bootstrapReceipt.Receipt.Maps {
		maps[item.Name] = true
	}
	for _, required := range []string{"aegis_capsules", "aegis_fences"} {
		if !maps[required] {
			return fmt.Errorf("bootstrap receipt does not attest required enforcement map %s", required)
		}
	}
	switch v.bootstrapReceipt.Receipt.Host.LockdownMode {
	case "integrity", "confidentiality":
	default:
		return fmt.Errorf("kernel lockdown mode %q is not accepted by production Genesis profile", v.bootstrapReceipt.Receipt.Host.LockdownMode)
	}
	return nil
}

func (v *ProductionVerifier) VerifyProofRequirements(_ context.Context, m genesis.Manifest) error {
	checks := []struct {
		name string
		path string
		want string
	}{
		{"spec_hash", v.bundle.Artifacts.Specification, m.Specification.SpecHash},
		{"invariant_set_hash", v.bundle.Artifacts.InvariantSet, m.Specification.InvariantSetHash},
		{"assumption_set_hash", v.bundle.Artifacts.AssumptionSet, m.Specification.AssumptionSetHash},
		{"forbidden_state_set_hash", v.bundle.Artifacts.ForbiddenStateSet, m.Specification.ForbiddenStateSetHash},
		{"tau_bounds_hash", v.bundle.Artifacts.TauBounds, m.Specification.TauBoundsHash},
		{"proof_scope_hash", v.bundle.Artifacts.ProofScope, m.Verification.ProofScopeHash},
		{"threat_model_hash", v.bundle.Artifacts.ThreatModel, m.ThreatModel.ThreatModelHash},
		{"capability_envelope_hash", v.bundle.Artifacts.CapabilityEnvelope, m.ThreatModel.CapabilityEnvelopeHash},
		{"attestation_policy_hash", v.bundle.Artifacts.AttestationPolicy, m.Trust.AttestationPolicyHash},
		{"nonce_policy_hash", v.bundle.Artifacts.NoncePolicy, m.Trust.NoncePolicyHash},
		{"enforcement_policy_hash", v.bundle.Artifacts.EnforcementPolicy, m.Enforcement.EnforcementPolicyHash},
		{"materials_hash", v.bundle.Artifacts.Materials, m.SupplyChain.MaterialsHash},
		{"sbom_hash", v.bundle.Artifacts.SBOM, m.SupplyChain.SBOMHash},
		{"approval_policy_hash", v.bundle.Artifacts.ApprovalPolicy, m.Approval.ApprovalPolicyHash},
	}
	for _, check := range checks {
		if err := verifyFileDigest(check.name, check.path, check.want); err != nil {
			return err
		}
	}
	if len(m.Verification.ProofArtifacts) != len(v.bundle.ProofArtifactPaths) {
		return fmt.Errorf("proof artifact count mismatch: manifest=%d bundle=%d", len(m.Verification.ProofArtifacts), len(v.bundle.ProofArtifactPaths))
	}
	for i, path := range v.bundle.ProofArtifactPaths {
		want := m.Verification.ProofArtifacts[i]
		if !strings.HasPrefix(want, "sha256:") {
			return fmt.Errorf("production Genesis profile requires proof_artifacts[%d] to be a sha256 digest", i)
		}
		if err := verifyFileDigest(fmt.Sprintf("proof_artifacts[%d]", i), path, want); err != nil {
			return err
		}
		if i >= len(v.proofRecords) {
			return fmt.Errorf("proof verification record %d is unavailable", i)
		}
		if err := validateProofVerificationRecord(v.proofRecords[i], m, v.now); err != nil {
			return fmt.Errorf("proof verification record %d: %w", i, err)
		}
	}
	return nil
}

func LoadManifest(path string) (genesis.Manifest, error) {
	var manifest genesis.Manifest
	if err := readStrictJSON(path, &manifest); err != nil {
		return genesis.Manifest{}, err
	}
	return manifest, nil
}

func LoadVerificationBundle(path string) (VerificationBundle, error) {
	var bundle VerificationBundle
	if err := readStrictJSON(path, &bundle); err != nil {
		return VerificationBundle{}, err
	}
	base := filepath.Dir(path)
	resolve := func(p string) string {
		if p == "" || filepath.IsAbs(p) {
			return p
		}
		return filepath.Join(base, p)
	}
	bundle.DoctrineManifest = resolve(bundle.DoctrineManifest)
	bundle.SignedDoctrineAuthorityStatement = resolve(bundle.SignedDoctrineAuthorityStatement)
	bundle.DoctrineAuthorityPublicKey = resolve(bundle.DoctrineAuthorityPublicKey)
	bundle.ManifestSignerPublicKey = resolve(bundle.ManifestSignerPublicKey)
	bundle.RemoteAttestationDecision = resolve(bundle.RemoteAttestationDecision)
	bundle.RemoteAttestationVerifierPublicKey = resolve(bundle.RemoteAttestationVerifierPublicKey)
	bundle.BootstrapReceipt = resolve(bundle.BootstrapReceipt)
	bundle.BootstrapAttestorPublicKey = resolve(bundle.BootstrapAttestorPublicKey)
	bundle.SignedRevocationList = resolve(bundle.SignedRevocationList)
	bundle.RevocationAuthorityPublicKey = resolve(bundle.RevocationAuthorityPublicKey)

	paths := &bundle.Artifacts
	paths.Specification = resolve(paths.Specification)
	paths.InvariantSet = resolve(paths.InvariantSet)
	paths.AssumptionSet = resolve(paths.AssumptionSet)
	paths.ForbiddenStateSet = resolve(paths.ForbiddenStateSet)
	paths.TauBounds = resolve(paths.TauBounds)
	paths.ProofScope = resolve(paths.ProofScope)
	paths.ThreatModel = resolve(paths.ThreatModel)
	paths.CapabilityEnvelope = resolve(paths.CapabilityEnvelope)
	paths.AttestationPolicy = resolve(paths.AttestationPolicy)
	paths.NoncePolicy = resolve(paths.NoncePolicy)
	paths.EnforcementPolicy = resolve(paths.EnforcementPolicy)
	paths.RefinementMapping = resolve(paths.RefinementMapping)
	paths.ExecutableContract = resolve(paths.ExecutableContract)
	paths.BuildProvenance = resolve(paths.BuildProvenance)
	paths.Materials = resolve(paths.Materials)
	paths.SBOM = resolve(paths.SBOM)
	paths.ApprovalPolicy = resolve(paths.ApprovalPolicy)
	for i := range bundle.ProofArtifactPaths {
		bundle.ProofArtifactPaths[i] = resolve(bundle.ProofArtifactPaths[i])
	}
	return bundle, nil
}

func CanonicalManifestPayload(m genesis.Manifest) ([]byte, error) {
	if m.GenesisEpoch > maxExactJSONInteger || m.Sequence > maxExactJSONInteger ||
		m.Doctrine.DoctrineEpoch > maxExactJSONInteger || m.Trust.TrustRootEpoch > maxExactJSONInteger ||
		m.Validity.MinimumAcceptedEpoch > maxExactJSONInteger {
		return nil, errors.New("Genesis integer exceeds RFC8785/JCS exact JSON integer profile")
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	delete(value, "authenticity")
	canonical, err := jcs.Format(value)
	if err != nil {
		return nil, err
	}
	return []byte(canonical), nil
}

func ManifestPayloadHash(m genesis.Manifest) (string, error) {
	payload, err := CanonicalManifestPayload(m)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ManifestRevocationHash(m genesis.Manifest) (string, error) {
	stable := m
	stable.Trust.RevocationRef = ""
	payload, err := CanonicalManifestPayload(stable)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte("aegis-ege/genesis-revocation-id/v1\x00"))
	h.Write(payload)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func SignManifest(m genesis.Manifest, privateKey ed25519.PrivateKey) (genesis.Manifest, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return genesis.Manifest{}, errors.New("invalid Ed25519 private key")
	}
	payload, err := CanonicalManifestPayload(m)
	if err != nil {
		return genesis.Manifest{}, err
	}
	sum := sha256.Sum256(payload)
	keyID, err := kernelfabric.BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return genesis.Manifest{}, err
	}
	m.Authenticity = genesis.Authenticity{
		Canonicalization:   "RFC8785",
		SignatureScope:     "MANIFEST_EXCLUDING_AUTHENTICITY",
		SignedPayloadHash:  "sha256:" + hex.EncodeToString(sum[:]),
		SignatureAlgorithm: "ed25519",
		SignerKeyID:        keyID,
		Signature:          base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}
	return m, nil
}


func SignDoctrineAuthorityStatement(statement DoctrineAuthorityStatement, privateKey ed25519.PrivateKey) (SignedDoctrineAuthorityStatement, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedDoctrineAuthorityStatement{}, errors.New("invalid Ed25519 doctrine authority private key")
	}
	if err := validateDoctrineAuthorityStatement(statement, time.Time{}); err != nil {
		return SignedDoctrineAuthorityStatement{}, err
	}
	payload, err := canonicalDoctrineAuthorityStatementPayload(statement)
	if err != nil {
		return SignedDoctrineAuthorityStatement{}, err
	}
	keyID, err := kernelfabric.BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedDoctrineAuthorityStatement{}, err
	}
	return SignedDoctrineAuthorityStatement{
		Statement: statement,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedDoctrineAuthorityStatement(signed SignedDoctrineAuthorityStatement, publicKey ed25519.PublicKey, now time.Time) error {
	if err := validateDoctrineAuthorityStatement(signed.Statement, now); err != nil {
		return err
	}
	keyID, err := kernelfabric.BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return errors.New("doctrine authority statement key id does not match trusted authority")
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode doctrine authority signature: %w", err)
	}
	payload, err := canonicalDoctrineAuthorityStatementPayload(signed.Statement)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("doctrine authority statement signature is invalid")
	}
	return nil
}

func canonicalDoctrineAuthorityStatementPayload(statement DoctrineAuthorityStatement) ([]byte, error) {
	if statement.DoctrineEpoch > maxExactJSONInteger {
		return nil, errors.New("doctrine epoch exceeds RFC8785/JCS exact JSON integer profile")
	}
	raw, err := json.Marshal(statement)
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
	return append([]byte("aegis-ege/doctrine-authority-statement/v1\x00"), []byte(canonical)...), nil
}

func validateDoctrineAuthorityStatement(statement DoctrineAuthorityStatement, now time.Time) error {
	if statement.Version != DoctrineAuthorityStatementVersion {
		return fmt.Errorf("unsupported doctrine authority statement version %q", statement.Version)
	}
	if strings.TrimSpace(statement.DoctrineID) == "" {
		return errors.New("doctrine_id is required")
	}
	if !strings.HasPrefix(statement.DoctrineManifestHash, "sha256:") {
		return errors.New("doctrine_manifest_hash must be a sha256 digest")
	}
	if statement.IssuedAt.IsZero() || statement.ExpiresAt.IsZero() || !statement.ExpiresAt.After(statement.IssuedAt) {
		return errors.New("doctrine authority statement validity window is invalid")
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(statement.IssuedAt.UTC()) {
			return errors.New("doctrine authority statement is not yet valid")
		}
		if !now.Before(statement.ExpiresAt.UTC()) {
			return errors.New("doctrine authority statement is expired")
		}
	}
	return nil
}

func SignRevocationList(list RevocationList, privateKey ed25519.PrivateKey) (SignedRevocationList, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedRevocationList{}, errors.New("invalid Ed25519 private key")
	}
	if err := validateRevocationList(list, time.Time{}); err != nil {
		return SignedRevocationList{}, err
	}
	payload, err := canonicalRevocationListPayload(list)
	if err != nil {
		return SignedRevocationList{}, err
	}
	keyID, err := kernelfabric.BootstrapKeyID(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return SignedRevocationList{}, err
	}
	return SignedRevocationList{
		List:      list,
		KeyID:     keyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, payload)),
	}, nil
}

func VerifySignedRevocationList(signed SignedRevocationList, publicKey ed25519.PublicKey, now time.Time) error {
	if err := validateRevocationList(signed.List, now); err != nil {
		return err
	}
	keyID, err := kernelfabric.BootstrapKeyID(publicKey)
	if err != nil {
		return err
	}
	if signed.KeyID != keyID {
		return errors.New("revocation-list key id does not match trusted authority")
	}
	signature, err := base64.StdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("decode revocation-list signature: %w", err)
	}
	payload, err := canonicalRevocationListPayload(signed.List)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("revocation-list signature is invalid")
	}
	return nil
}

func SignedRevocationListDigest(signed SignedRevocationList) (string, error) {
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
	sum := sha256.Sum256([]byte(canonical))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func canonicalRevocationListPayload(list RevocationList) ([]byte, error) {
	if list.Epoch > maxExactJSONInteger || list.MinimumAcceptedGenesisEpoch > maxExactJSONInteger ||
		list.MinimumAcceptedDoctrineEpoch > maxExactJSONInteger || list.MinimumTrustRootEpoch > maxExactJSONInteger {
		return nil, errors.New("revocation-list integer exceeds RFC8785/JCS exact JSON integer profile")
	}
	raw, err := json.Marshal(list)
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
	return []byte(canonical), nil
}

func validateRevocationList(list RevocationList, now time.Time) error {
	if list.Version != RevocationListVersion {
		return fmt.Errorf("unsupported revocation-list version %q", list.Version)
	}
	if list.IssuedAt.IsZero() || list.ExpiresAt.IsZero() || !list.ExpiresAt.After(list.IssuedAt) {
		return errors.New("revocation-list validity window is invalid")
	}
	if !now.IsZero() {
		now = now.UTC()
		if now.Before(list.IssuedAt.UTC()) {
			return errors.New("revocation list is not yet valid")
		}
		if !now.Before(list.ExpiresAt.UTC()) {
			return errors.New("revocation list is expired")
		}
	}
	return nil
}

func currentExecutableDigest() (string, error) {
	path, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("resolve running executable: %w", err)
	}
	digest, err := fileDigest(path)
	if err != nil {
		return "", fmt.Errorf("hash running executable: %w", err)
	}
	return digest, nil
}

func verifyFileDigest(name, path, want string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s artifact path is required", name)
	}
	got, err := fileDigest(path)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("%s digest mismatch: got %s want %s", name, got, want)
	}
	return nil
}

func fileDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", errors.New("artifact is not a regular file")
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func readStrictJSON(path string, dst any) error {
	payload, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("JSON document must contain exactly one value")
		}
		return err
	}
	return nil
}

func maxUint64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
