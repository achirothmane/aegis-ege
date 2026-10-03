package kernelfabric

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	RecoveryWitnessSignerProtocolV1 = "aegis.ege/recovery-witness-signer/v1"
	recoveryWitnessSignerPath       = "/v1/sign"
)

var allowedRecoveryWitnessSigningPrefixes = [][]byte{
	[]byte("aegis-ege/taint-recovery-joint/v1\x00"),
	[]byte("aegis-ege/witness-recovery-receipt/v1\x00"),
	[]byte("aegis-ege/taint-recovery-witness-response/v1\x00"),
}

// RecoveryWitnessSigner is the B-key custody boundary. Implementations return a
// signature over the exact domain-separated payload but do not expose private
// key material to the witness policy/runtime.
type RecoveryWitnessSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type Ed25519RecoveryWitnessSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewEd25519RecoveryWitnessSigner(
	privateKey ed25519.PrivateKey,
) (*Ed25519RecoveryWitnessSigner, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid Ed25519 recovery witness private key")
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyID, err := BootstrapKeyID(publicKey)
	if err != nil {
		return nil, err
	}
	return &Ed25519RecoveryWitnessSigner{
		keyID:      keyID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func (s *Ed25519RecoveryWitnessSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *Ed25519RecoveryWitnessSigner) Sign(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("recovery witness signer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isAllowedRecoveryWitnessSigningPayload(payload) {
		return nil, errors.New("recovery witness signer payload domain is not allowed")
	}
	return ed25519.Sign(s.privateKey, payload), nil
}

type RemoteRecoveryWitnessSigner struct {
	endpoint string
	keyID    string
	verifier RecoveryWitnessVerifier
	client   *http.Client
}

type recoveryWitnessSignerRequest struct {
	Protocol string `json:"protocol"`
	KeyID    string `json:"key_id"`
	Payload  string `json:"payload"`
}

type recoveryWitnessSignerResponse struct {
	Protocol  string `json:"protocol"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func NewRemoteRecoveryWitnessSigner(
	endpoint string,
	keyID string,
	publicKey ed25519.PublicKey,
	client *http.Client,
) (*RemoteRecoveryWitnessSigner, error) {
	verifier, err := NewRecoveryWitnessVerifier(
		RecoveryWitnessSignatureEd25519,
		base64.StdEncoding.EncodeToString(publicKey),
	)
	if err != nil {
		return nil, err
	}
	return NewRemoteRecoveryWitnessSignerWithVerifier(
		endpoint,
		keyID,
		verifier,
		client,
	)
}

func NewRemoteRecoveryWitnessSignerWithVerifier(
	endpoint string,
	keyID string,
	verifier RecoveryWitnessVerifier,
	client *http.Client,
) (*RemoteRecoveryWitnessSigner, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("recovery witness signer endpoint must be an absolute HTTPS URL")
	}
	if client == nil {
		return nil, errors.New("recovery witness signer HTTP client is required")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || keyID != verifier.KeyID() {
		return nil, errors.New("recovery witness signer key id does not match verifier")
	}
	return &RemoteRecoveryWitnessSigner{
		endpoint: endpoint,
		keyID:    keyID,
		verifier: verifier,
		client:   client,
	}, nil
}

func (s *RemoteRecoveryWitnessSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *RemoteRecoveryWitnessSigner) Sign(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("remote recovery witness signer is unavailable")
	}
	if !isAllowedRecoveryWitnessSigningPayload(payload) {
		return nil, errors.New("recovery witness signer payload domain is not allowed")
	}
	body, err := json.Marshal(recoveryWitnessSignerRequest{
		Protocol: RecoveryWitnessSignerProtocolV1,
		KeyID:    s.keyID,
		Payload:  base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("encode recovery witness signer request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint+recoveryWitnessSignerPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, fmt.Errorf("build recovery witness signer request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("recovery witness signer request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		payload, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return nil, fmt.Errorf(
			"recovery witness signer returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(payload)),
		)
	}
	var result recoveryWitnessSignerResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode recovery witness signer response: %w", err)
	}
	if result.Protocol != RecoveryWitnessSignerProtocolV1 || result.KeyID != s.keyID {
		return nil, errors.New("recovery witness signer response identity mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) == 0 {
		return nil, errors.New("recovery witness signer returned invalid signature encoding")
	}
	if !s.verifier.Verify(payload, signature) {
		return nil, errors.New("recovery witness signer returned unverifiable signature")
	}
	return signature, nil
}

func NewRecoveryWitnessSignerHandler(
	privateKey ed25519.PrivateKey,
) (http.Handler, error) {
	signer, err := NewEd25519RecoveryWitnessSigner(privateKey)
	if err != nil {
		return nil, err
	}
	return NewRecoveryWitnessSignerHandlerWithSigner(signer)
}

func NewRecoveryWitnessSignerHandlerWithSigner(
	signer RecoveryWitnessSigner,
) (http.Handler, error) {
	if signer == nil || strings.TrimSpace(signer.KeyID()) == "" {
		return nil, errors.New("recovery witness signer is unavailable")
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost || request.URL.Path != recoveryWitnessSignerPath {
			http.NotFound(rw, request)
			return
		}
		var wire recoveryWitnessSignerRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil {
			http.Error(rw, "invalid signer request", http.StatusBadRequest)
			return
		}
		if wire.Protocol != RecoveryWitnessSignerProtocolV1 || wire.KeyID != signer.KeyID() {
			http.Error(rw, "signer identity mismatch", http.StatusUnauthorized)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(wire.Payload)
		if err != nil || !isAllowedRecoveryWitnessSigningPayload(payload) {
			http.Error(rw, "signer payload domain denied", http.StatusForbidden)
			return
		}
		signature, err := signer.Sign(request.Context(), payload)
		if err != nil {
			http.Error(rw, "signer unavailable", http.StatusServiceUnavailable)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(recoveryWitnessSignerResponse{
			Protocol:  RecoveryWitnessSignerProtocolV1,
			KeyID:     signer.KeyID(),
			Signature: base64.StdEncoding.EncodeToString(signature),
		})
	}), nil
}

func isAllowedRecoveryWitnessSigningPayload(payload []byte) bool {
	for _, prefix := range allowedRecoveryWitnessSigningPrefixes {
		if bytes.HasPrefix(payload, prefix) {
			return true
		}
	}
	return false
}
