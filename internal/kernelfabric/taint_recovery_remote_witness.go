package kernelfabric

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	remoteTaintRecoveryWitnessProtocolV1  = "aegis-ege/taint-recovery-witness/v1"
	remoteTaintRecoveryWitnessNonceHeader = "X-Aegis-Recovery-Witness-Nonce"
)

type AuthoritySignedTaintRecoveryAuthorization struct {
	Version            string                     `json:"version"`
	Authorization      TaintRecoveryAuthorization `json:"authorization"`
	AuthorityKeyID     string                     `json:"authority_key_id"`
	AuthoritySignature string                     `json:"authority_signature"`
	WitnessKeyID       string                     `json:"witness_key_id"`
}

type RemoteTaintRecoveryWitness struct {
	endpoint     string
	witnessKeyID string
	witnessKey   ed25519.PublicKey
	profile      *VerifiedExternalRecoveryWitnessProfile
	client       *http.Client
}

type TaintRecoveryWitnessPolicy interface {
	AdmitTaintRecoveryWitness(context.Context, TaintRecoveryAuthorization) error
}

type ProfiledTaintRecoveryWitnessPolicy interface {
	TaintRecoveryWitnessPolicy
	RecoveryWitnessPolicyEpoch() uint64
	RecoveryWitnessPolicyHash() (string, error)
}

type TaintRecoveryWitnessPolicyFunc func(context.Context, TaintRecoveryAuthorization) error

func (f TaintRecoveryWitnessPolicyFunc) AdmitTaintRecoveryWitness(
	ctx context.Context,
	auth TaintRecoveryAuthorization,
) error {
	if f == nil {
		return errors.New("taint recovery witness policy is unavailable")
	}
	return f(ctx, auth)
}

type remoteTaintRecoveryWitnessRequest struct {
	Protocol      string                                    `json:"protocol"`
	Authorization AuthoritySignedTaintRecoveryAuthorization `json:"authorization"`
}

type remoteTaintRecoveryWitnessResponse struct {
	Protocol            string                                `json:"protocol"`
	Nonce               string                                `json:"nonce"`
	WitnessKeyID        string                                `json:"witness_key_id"`
	SignedAuthorization JointSignedTaintRecoveryAuthorization `json:"signed_authorization"`
	Receipt             *WitnessRecoveryReceipt               `json:"receipt,omitempty"`
	ResponseSignature   string                                `json:"response_signature"`
}

type remoteTaintRecoveryWitnessStatement struct {
	Protocol            string `json:"protocol"`
	Nonce               string `json:"nonce"`
	WitnessKeyID        string `json:"witness_key_id"`
	AuthorizationID     string `json:"authorization_id"`
	JointCommitmentHash string `json:"joint_commitment_hash"`
}

func (r *TaintRecoveryTrustRoot) SignAuthorityRequest(
	auth TaintRecoveryAuthorization,
	authorityPrivateKey ed25519.PrivateKey,
) (AuthoritySignedTaintRecoveryAuthorization, error) {
	if r == nil {
		return AuthoritySignedTaintRecoveryAuthorization{}, fmt.Errorf(
			"%w: recovery trust root is unavailable",
			ErrTaintRecoveryAuthorization,
		)
	}
	if err := ValidateTaintRecoveryAuthorization(auth); err != nil {
		return AuthoritySignedTaintRecoveryAuthorization{}, err
	}
	if len(authorityPrivateKey) != ed25519.PrivateKeySize {
		return AuthoritySignedTaintRecoveryAuthorization{}, errors.New("invalid Ed25519 recovery authority key")
	}
	authorityKeyID, err := BootstrapKeyID(authorityPrivateKey.Public().(ed25519.PublicKey))
	if err != nil {
		return AuthoritySignedTaintRecoveryAuthorization{}, err
	}
	if authorityKeyID != r.manifest.AuthorityKeyID {
		return AuthoritySignedTaintRecoveryAuthorization{}, fmt.Errorf(
			"%w: recovery authority private key is not pinned by trust root",
			ErrTaintRecoveryAuthorization,
		)
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(auth)
	if err != nil {
		return AuthoritySignedTaintRecoveryAuthorization{}, err
	}
	return AuthoritySignedTaintRecoveryAuthorization{
		Version:            JointTaintRecoveryAuthorizationVersion,
		Authorization:      auth,
		AuthorityKeyID:     authorityKeyID,
		AuthoritySignature: base64.StdEncoding.EncodeToString(ed25519.Sign(authorityPrivateKey, payload)),
		WitnessKeyID:       r.manifest.WitnessKeyID,
	}, nil
}

func NewProfiledRemoteTaintRecoveryWitness(
	endpoint string,
	trustRoot *TaintRecoveryTrustRoot,
	profile *VerifiedExternalRecoveryWitnessProfile,
	tlsTrustAnchorPEM []byte,
	client *http.Client,
) (*RemoteTaintRecoveryWitness, error) {
	remote, err := NewRemoteTaintRecoveryWitness(endpoint, trustRoot, client)
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, fmt.Errorf("%w: external witness profile is required", ErrTaintRecoveryAuthorization)
	}
	expected := profile.profile
	if remote.endpoint != expected.Endpoint {
		return nil, fmt.Errorf("%w: external witness endpoint changed", ErrTaintRecoveryAuthorization)
	}
	if remote.witnessKeyID != expected.WitnessKeyID {
		return nil, fmt.Errorf("%w: external witness key changed", ErrTaintRecoveryAuthorization)
	}
	tlsDigest, err := TLSCertificatePEMSHA256(tlsTrustAnchorPEM)
	if err != nil {
		return nil, err
	}
	if tlsDigest != expected.TLSTrustAnchorSHA256 {
		return nil, fmt.Errorf("%w: external witness TLS trust anchor changed", ErrTaintRecoveryAuthorization)
	}
	remote.profile = profile
	return remote, nil
}

func NewRemoteTaintRecoveryWitness(
	endpoint string,
	trustRoot *TaintRecoveryTrustRoot,
	client *http.Client,
) (*RemoteTaintRecoveryWitness, error) {
	if trustRoot == nil {
		return nil, errors.New("recovery trust root is required")
	}
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse remote recovery witness endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("remote recovery witness endpoint must use HTTPS")
	}
	if client == nil {
		return nil, errors.New("remote recovery witness HTTP client is required")
	}
	return &RemoteTaintRecoveryWitness{
		endpoint:     endpoint,
		witnessKeyID: trustRoot.manifest.WitnessKeyID,
		witnessKey:   append(ed25519.PublicKey(nil), trustRoot.witnessKey...),
		client:       client,
	}, nil
}

func (w *RemoteTaintRecoveryWitness) CoSign(
	ctx context.Context,
	partial AuthoritySignedTaintRecoveryAuthorization,
) (JointSignedTaintRecoveryAuthorization, error) {
	joint, _, err := w.coSign(ctx, partial)
	return joint, err
}

func (w *RemoteTaintRecoveryWitness) CoSignWithReceipt(
	ctx context.Context,
	partial AuthoritySignedTaintRecoveryAuthorization,
) (JointSignedTaintRecoveryAuthorization, WitnessRecoveryReceipt, error) {
	joint, receipt, err := w.coSign(ctx, partial)
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, err
	}
	if w.profile == nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf(
			"%w: profiled remote witness is required for receipt verification",
			ErrTaintRecoveryAuthorization,
		)
	}
	return joint, receipt, nil
}

func (w *RemoteTaintRecoveryWitness) coSign(
	ctx context.Context,
	partial AuthoritySignedTaintRecoveryAuthorization,
) (JointSignedTaintRecoveryAuthorization, WitnessRecoveryReceipt, error) {
	if w == nil || w.client == nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, errors.New("remote recovery witness is unavailable")
	}
	if partial.Version != JointTaintRecoveryAuthorizationVersion {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf(
			"%w: unsupported authority request version %q",
			ErrTaintRecoveryAuthorization,
			partial.Version,
		)
	}
	if partial.WitnessKeyID != w.witnessKeyID {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf(
			"%w: authority request targets an unpinned witness",
			ErrTaintRecoveryAuthorization,
		)
	}
	nonce, err := newTaintRecoveryWitnessNonce()
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, err
	}
	body, err := json.Marshal(remoteTaintRecoveryWitnessRequest{
		Protocol:      remoteTaintRecoveryWitnessProtocolV1,
		Authorization: partial,
	})
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf("encode recovery witness request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		w.endpoint+"/v1/recovery/cosign",
		bytes.NewReader(body),
	)
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf("build recovery witness request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(remoteTaintRecoveryWitnessNonceHeader, nonce)

	response, err := w.client.Do(request)
	if err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf("remote recovery witness request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf(
			"remote recovery witness returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(payload)),
		)
	}
	var result remoteTaintRecoveryWitnessResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf("decode recovery witness response: %w", err)
	}
	if err := w.verifyResponse(partial, nonce, result); err != nil {
		return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, err
	}
	if w.profile != nil {
		if result.Receipt == nil {
			return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, fmt.Errorf(
				"%w: external witness receipt is missing",
				ErrTaintRecoveryAuthorization,
			)
		}
		if err := VerifyWitnessRecoveryReceipt(
			*result.Receipt,
			w.profile,
			result.SignedAuthorization,
			nonce,
			w.witnessKey,
		); err != nil {
			return JointSignedTaintRecoveryAuthorization{}, WitnessRecoveryReceipt{}, err
		}
		return result.SignedAuthorization, *result.Receipt, nil
	}
	return result.SignedAuthorization, WitnessRecoveryReceipt{}, nil
}

func NewProfiledTaintRecoveryWitnessHandler(
	trustRoot *TaintRecoveryTrustRoot,
	witnessPrivateKey ed25519.PrivateKey,
	policy ProfiledTaintRecoveryWitnessPolicy,
	profile *VerifiedExternalRecoveryWitnessProfile,
	now func() time.Time,
) (http.Handler, error) {
	signer, err := NewEd25519RecoveryWitnessSigner(witnessPrivateKey)
	if err != nil {
		return nil, err
	}
	return NewProfiledTaintRecoveryWitnessHandlerWithSigner(
		trustRoot,
		signer,
		policy,
		profile,
		now,
	)
}

func NewProfiledTaintRecoveryWitnessHandlerWithSigner(
	trustRoot *TaintRecoveryTrustRoot,
	signer RecoveryWitnessSigner,
	policy ProfiledTaintRecoveryWitnessPolicy,
	profile *VerifiedExternalRecoveryWitnessProfile,
	now func() time.Time,
) (http.Handler, error) {
	if profile == nil {
		return nil, fmt.Errorf("%w: external witness profile is required", ErrTaintRecoveryAuthorization)
	}
	if trustRoot == nil {
		return nil, fmt.Errorf("%w: recovery trust root is required", ErrTaintRecoveryAuthorization)
	}
	if profile.profile.WitnessKeyID != trustRoot.manifest.WitnessKeyID {
		return nil, fmt.Errorf("%w: external witness profile key does not match trust root", ErrTaintRecoveryAuthorization)
	}
	if policy == nil {
		return nil, fmt.Errorf("%w: profiled witness policy is required", ErrTaintRecoveryAuthorization)
	}
	policyHash, err := policy.RecoveryWitnessPolicyHash()
	if err != nil {
		return nil, fmt.Errorf("%w: compute witness policy hash: %v", ErrTaintRecoveryAuthorization, err)
	}
	if policy.RecoveryWitnessPolicyEpoch() != profile.profile.PolicyEpoch ||
		policyHash != profile.profile.PolicyHash {
		return nil, fmt.Errorf("%w: witness policy continuity does not match external profile", ErrTaintRecoveryAuthorization)
	}
	return newTaintRecoveryWitnessHandlerWithSigner(trustRoot, signer, policy, profile, now)
}

func NewTaintRecoveryWitnessHandler(
	trustRoot *TaintRecoveryTrustRoot,
	witnessPrivateKey ed25519.PrivateKey,
	policy TaintRecoveryWitnessPolicy,
	now func() time.Time,
) (http.Handler, error) {
	signer, err := NewEd25519RecoveryWitnessSigner(witnessPrivateKey)
	if err != nil {
		return nil, err
	}
	return NewTaintRecoveryWitnessHandlerWithSigner(trustRoot, signer, policy, now)
}

func NewTaintRecoveryWitnessHandlerWithSigner(
	trustRoot *TaintRecoveryTrustRoot,
	signer RecoveryWitnessSigner,
	policy TaintRecoveryWitnessPolicy,
	now func() time.Time,
) (http.Handler, error) {
	return newTaintRecoveryWitnessHandlerWithSigner(trustRoot, signer, policy, nil, now)
}

func newTaintRecoveryWitnessHandlerWithSigner(
	trustRoot *TaintRecoveryTrustRoot,
	signer RecoveryWitnessSigner,
	policy TaintRecoveryWitnessPolicy,
	profile *VerifiedExternalRecoveryWitnessProfile,
	now func() time.Time,
) (http.Handler, error) {
	if trustRoot == nil {
		return nil, errors.New("recovery trust root is required")
	}
	if signer == nil || strings.TrimSpace(signer.KeyID()) == "" {
		return nil, errors.New("recovery witness signer is required")
	}
	if signer.KeyID() != trustRoot.manifest.WitnessKeyID {
		return nil, fmt.Errorf(
			"%w: witness signer key is not pinned by recovery trust root",
			ErrTaintRecoveryAuthorization,
		)
	}
	if policy == nil {
		return nil, errors.New("recovery witness policy is required")
	}
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != "/v1/recovery/cosign" {
			http.NotFound(rw, request)
			return
		}
		nonce := strings.TrimSpace(request.Header.Get(remoteTaintRecoveryWitnessNonceHeader))
		if nonce == "" {
			http.Error(rw, "recovery witness nonce required", http.StatusBadRequest)
			return
		}
		var wire remoteTaintRecoveryWitnessRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil {
			http.Error(rw, "invalid recovery witness request", http.StatusBadRequest)
			return
		}
		if wire.Protocol != remoteTaintRecoveryWitnessProtocolV1 {
			http.Error(rw, "recovery witness protocol mismatch", http.StatusBadRequest)
			return
		}
		current := now().UTC()
		if err := verifyAuthorityRecoveryRequest(
			wire.Authorization,
			trustRoot,
			current,
		); err != nil {
			http.Error(rw, "recovery authority verification failed", http.StatusUnauthorized)
			return
		}
		if err := policy.AdmitTaintRecoveryWitness(
			request.Context(),
			wire.Authorization.Authorization,
		); err != nil {
			http.Error(rw, "recovery witness policy denied authorization", http.StatusForbidden)
			return
		}

		payload, err := canonicalJointTaintRecoveryAuthorizationPayload(wire.Authorization.Authorization)
		if err != nil {
			http.Error(rw, "cannot canonicalize recovery authorization", http.StatusInternalServerError)
			return
		}
		witnessSignature, err := signAndVerifyRecoveryWitnessPayload(
			request.Context(),
			signer,
			trustRoot.witnessKey,
			payload,
		)
		if err != nil {
			http.Error(rw, "recovery witness signer unavailable", http.StatusServiceUnavailable)
			return
		}
		joint := JointSignedTaintRecoveryAuthorization{
			Version:            JointTaintRecoveryAuthorizationVersion,
			Authorization:      wire.Authorization.Authorization,
			AuthorityKeyID:     wire.Authorization.AuthorityKeyID,
			AuthoritySignature: wire.Authorization.AuthoritySignature,
			WitnessKeyID:       trustRoot.manifest.WitnessKeyID,
			WitnessSignature:   base64.StdEncoding.EncodeToString(witnessSignature),
		}
		commitment, err := JointTaintRecoveryCommitmentDigest(joint)
		if err != nil {
			http.Error(rw, "cannot commit recovery authorization", http.StatusInternalServerError)
			return
		}
		result := remoteTaintRecoveryWitnessResponse{
			Protocol:            remoteTaintRecoveryWitnessProtocolV1,
			Nonce:               nonce,
			WitnessKeyID:        trustRoot.manifest.WitnessKeyID,
			SignedAuthorization: joint,
		}
		if profile != nil {
			receipt, err := signWitnessRecoveryReceiptWithSigner(
				request.Context(),
				profile.profile,
				joint.Authorization.AuthorizationID,
				commitment,
				nonce,
				current,
				signer,
			)
			if err != nil {
				http.Error(rw, "cannot sign recovery witness receipt", http.StatusServiceUnavailable)
				return
			}
			if err := VerifyWitnessRecoveryReceipt(
				receipt,
				profile,
				joint,
				nonce,
				trustRoot.witnessKey,
			); err != nil {
				http.Error(rw, "recovery witness signer returned invalid receipt signature", http.StatusServiceUnavailable)
				return
			}
			result.Receipt = &receipt
		}
		statement, err := remoteTaintRecoveryWitnessResponsePayload(result, commitment)
		if err != nil {
			http.Error(rw, "cannot sign recovery witness response", http.StatusInternalServerError)
			return
		}
		responseSignature, err := signAndVerifyRecoveryWitnessPayload(
			request.Context(),
			signer,
			trustRoot.witnessKey,
			statement,
		)
		if err != nil {
			http.Error(rw, "recovery witness response signer unavailable", http.StatusServiceUnavailable)
			return
		}
		result.ResponseSignature = base64.StdEncoding.EncodeToString(responseSignature)
		rw.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(rw).Encode(result); err != nil {
			return
		}
	}), nil
}

func signAndVerifyRecoveryWitnessPayload(
	ctx context.Context,
	signer RecoveryWitnessSigner,
	publicKey ed25519.PublicKey,
	payload []byte,
) ([]byte, error) {
	if signer == nil {
		return nil, errors.New("recovery witness signer is unavailable")
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, payload, signature) {
		return nil, errors.New("recovery witness signer returned unverifiable signature")
	}
	return signature, nil
}

func verifyAuthorityRecoveryRequest(
	partial AuthoritySignedTaintRecoveryAuthorization,
	trustRoot *TaintRecoveryTrustRoot,
	now time.Time,
) error {
	if trustRoot == nil {
		return fmt.Errorf("%w: recovery trust root is unavailable", ErrTaintRecoveryAuthorization)
	}
	if partial.Version != JointTaintRecoveryAuthorizationVersion {
		return fmt.Errorf("%w: authority request version mismatch", ErrTaintRecoveryAuthorization)
	}
	if partial.AuthorityKeyID != trustRoot.manifest.AuthorityKeyID ||
		partial.WitnessKeyID != trustRoot.manifest.WitnessKeyID {
		return fmt.Errorf("%w: authority request principal mismatch", ErrTaintRecoveryAuthorization)
	}
	if err := ValidateTaintRecoveryAuthorization(partial.Authorization); err != nil {
		return err
	}
	signature, err := decodeTaintRecoverySignature(partial.AuthoritySignature)
	if err != nil {
		return ErrBootstrapSignatureInvalid
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(partial.Authorization)
	if err != nil {
		return err
	}
	if !ed25519.Verify(trustRoot.authorityKey, payload, signature) {
		return ErrBootstrapSignatureInvalid
	}
	now = now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if now.Before(partial.Authorization.NotBefore.UTC()) ||
		!now.Before(partial.Authorization.ExpiresAt.UTC()) {
		return fmt.Errorf("%w: authorization is outside its validity window", ErrTaintRecoveryAuthorization)
	}
	return nil
}

func (w *RemoteTaintRecoveryWitness) verifyResponse(
	partial AuthoritySignedTaintRecoveryAuthorization,
	nonce string,
	result remoteTaintRecoveryWitnessResponse,
) error {
	if result.Protocol != remoteTaintRecoveryWitnessProtocolV1 {
		return errors.New("remote recovery witness protocol mismatch")
	}
	if result.Nonce != nonce {
		return errors.New("remote recovery witness freshness nonce mismatch")
	}
	if result.WitnessKeyID != w.witnessKeyID {
		return errors.New("remote recovery witness key id mismatch")
	}
	joint := result.SignedAuthorization
	if joint.Version != JointTaintRecoveryAuthorizationVersion ||
		joint.AuthorityKeyID != partial.AuthorityKeyID ||
		joint.AuthoritySignature != partial.AuthoritySignature ||
		joint.WitnessKeyID != partial.WitnessKeyID {
		return errors.New("remote recovery witness changed authorization envelope")
	}
	expectedPayload, err := canonicalJointTaintRecoveryAuthorizationPayload(partial.Authorization)
	if err != nil {
		return err
	}
	observedPayload, err := canonicalJointTaintRecoveryAuthorizationPayload(joint.Authorization)
	if err != nil {
		return err
	}
	if !bytes.Equal(expectedPayload, observedPayload) {
		return errors.New("remote recovery witness changed authorization payload")
	}
	witnessSignature, err := decodeTaintRecoverySignature(joint.WitnessSignature)
	if err != nil {
		return errors.New("remote recovery witness signature is invalid")
	}
	if !ed25519.Verify(w.witnessKey, observedPayload, witnessSignature) {
		return errors.New("remote recovery witness signature verification failed")
	}
	commitment, err := JointTaintRecoveryCommitmentDigest(joint)
	if err != nil {
		return err
	}
	statement, err := remoteTaintRecoveryWitnessResponsePayload(result, commitment)
	if err != nil {
		return err
	}
	responseSignature, err := decodeTaintRecoverySignature(result.ResponseSignature)
	if err != nil {
		return errors.New("remote recovery witness response signature is invalid")
	}
	if !ed25519.Verify(w.witnessKey, statement, responseSignature) {
		return errors.New("remote recovery witness response signature verification failed")
	}
	return nil
}

func remoteTaintRecoveryWitnessResponsePayload(
	response remoteTaintRecoveryWitnessResponse,
	commitment [32]byte,
) ([]byte, error) {
	statement := remoteTaintRecoveryWitnessStatement{
		Protocol:            response.Protocol,
		Nonce:               response.Nonce,
		WitnessKeyID:        response.WitnessKeyID,
		AuthorizationID:     response.SignedAuthorization.Authorization.AuthorizationID,
		JointCommitmentHash: "sha256:" + hex.EncodeToString(commitment[:]),
	}
	body, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode recovery witness response statement: %w", err)
	}
	return append([]byte("aegis-ege/taint-recovery-witness-response/v1\x00"), body...), nil
}

func newTaintRecoveryWitnessNonce() (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("generate recovery witness nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}
