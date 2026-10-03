package journal

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
	ExternalHeadWitnessSignerProtocolV1 = "aegis.ege/external-head-witness-signer/v1"
	externalHeadWitnessSignerPath       = "/v1/sign"

	ExternalHeadWitnessSigningKindHead   = "head"
	ExternalHeadWitnessSigningKindPolicy = "policy"
)

type ExternalHeadWitnessSigner interface {
	KeyID() string
	Sign(context.Context, string, string, []byte) ([]byte, error)
}

type Ed25519ExternalHeadWitnessSigner struct {
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewEd25519ExternalHeadWitnessSigner(
	keyID string,
	privateKey ed25519.PrivateKey,
) (*Ed25519ExternalHeadWitnessSigner, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, errors.New("external head witness signer key id is required")
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid external head witness signer private key")
	}
	return &Ed25519ExternalHeadWitnessSigner{
		keyID:      keyID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func (s *Ed25519ExternalHeadWitnessSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *Ed25519ExternalHeadWitnessSigner) Sign(
	ctx context.Context,
	kind string,
	operation string,
	payload []byte,
) ([]byte, error) {
	if s == nil || len(s.privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("external head witness signer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateExternalHeadWitnessSigningPayload(
		s.keyID,
		kind,
		operation,
		payload,
	); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.privateKey, payload), nil
}

type RemoteExternalHeadWitnessSigner struct {
	endpoint  string
	keyID     string
	publicKey ed25519.PublicKey
	client    *http.Client
}

type externalHeadWitnessSignerRequest struct {
	Protocol  string `json:"protocol"`
	KeyID     string `json:"key_id"`
	Kind      string `json:"kind"`
	Operation string `json:"operation"`
	Payload   string `json:"payload"`
}

type externalHeadWitnessSignerResponse struct {
	Protocol  string `json:"protocol"`
	KeyID     string `json:"key_id"`
	Signature string `json:"signature"`
}

func NewRemoteExternalHeadWitnessSigner(
	endpoint string,
	keyID string,
	publicKey ed25519.PublicKey,
	client *http.Client,
) (*RemoteExternalHeadWitnessSigner, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("external head witness signer endpoint must be an absolute HTTPS URL")
	}
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return nil, errors.New("external head witness signer key id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("external head witness signer public key is invalid")
	}
	if client == nil {
		return nil, errors.New("external head witness signer HTTP client is required")
	}
	return &RemoteExternalHeadWitnessSigner{
		endpoint:  endpoint,
		keyID:     keyID,
		publicKey: append(ed25519.PublicKey(nil), publicKey...),
		client:    client,
	}, nil
}

func (s *RemoteExternalHeadWitnessSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

func (s *RemoteExternalHeadWitnessSigner) Sign(
	ctx context.Context,
	kind string,
	operation string,
	payload []byte,
) ([]byte, error) {
	if s == nil || s.client == nil {
		return nil, errors.New("remote external head witness signer is unavailable")
	}
	if err := validateExternalHeadWitnessSigningPayload(
		s.keyID,
		kind,
		operation,
		payload,
	); err != nil {
		return nil, err
	}
	body, err := json.Marshal(externalHeadWitnessSignerRequest{
		Protocol:  ExternalHeadWitnessSignerProtocolV1,
		KeyID:     s.keyID,
		Kind:      kind,
		Operation: operation,
		Payload:   base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint+externalHeadWitnessSignerPath,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("external head witness signer request: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return nil, fmt.Errorf(
			"external head witness signer returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}
	var result externalHeadWitnessSignerResponse
	decoder := json.NewDecoder(io.LimitReader(response.Body, 16*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode external head witness signer response: %w", err)
	}
	if result.Protocol != ExternalHeadWitnessSignerProtocolV1 ||
		result.KeyID != s.keyID {
		return nil, errors.New("external head witness signer response identity mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return nil, errors.New("external head witness signer returned invalid signature encoding")
	}
	if !ed25519.Verify(s.publicKey, payload, signature) {
		return nil, errors.New("external head witness signer returned unverifiable signature")
	}
	return signature, nil
}

func NewExternalHeadWitnessSignerHandler(
	keyID string,
	privateKey ed25519.PrivateKey,
) (http.Handler, error) {
	signer, err := NewEd25519ExternalHeadWitnessSigner(keyID, privateKey)
	if err != nil {
		return nil, err
	}
	return http.HandlerFunc(func(rw http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPost ||
			request.URL.Path != externalHeadWitnessSignerPath {
			http.NotFound(rw, request)
			return
		}
		var wire externalHeadWitnessSignerRequest
		decoder := json.NewDecoder(io.LimitReader(request.Body, 64*1024))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&wire); err != nil {
			http.Error(rw, "invalid signer request", http.StatusBadRequest)
			return
		}
		if wire.Protocol != ExternalHeadWitnessSignerProtocolV1 ||
			wire.KeyID != signer.KeyID() {
			http.Error(rw, "signer identity mismatch", http.StatusUnauthorized)
			return
		}
		payload, err := base64.StdEncoding.DecodeString(wire.Payload)
		if err != nil {
			http.Error(rw, "invalid signer payload", http.StatusBadRequest)
			return
		}
		signature, err := signer.Sign(
			request.Context(),
			wire.Kind,
			wire.Operation,
			payload,
		)
		if err != nil {
			http.Error(rw, "signer payload domain denied", http.StatusForbidden)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(externalHeadWitnessSignerResponse{
			Protocol:  ExternalHeadWitnessSignerProtocolV1,
			KeyID:     signer.KeyID(),
			Signature: base64.StdEncoding.EncodeToString(signature),
		})
	}), nil
}

func validateExternalHeadWitnessSigningPayload(
	keyID string,
	kind string,
	operation string,
	payload []byte,
) error {
	keyID = strings.TrimSpace(keyID)
	operation = strings.TrimSpace(operation)
	switch kind {
	case ExternalHeadWitnessSigningKindHead:
		if operation != "load" &&
			operation != "advance" &&
			operation != "rotation-observe" {
			return errors.New("external head witness signer operation is not allowed")
		}
		var statement remoteWitnessStatement
		if err := decodeStrictRemoteJSON(bytes.NewReader(payload), &statement); err != nil {
			return errors.New("external head witness signer head payload is invalid")
		}
		if statement.Protocol != remoteWitnessProtocolV1 ||
			statement.Operation != operation ||
			statement.WitnessKeyID != keyID ||
			strings.TrimSpace(statement.Nonce) == "" ||
			strings.TrimSpace(statement.JournalID) == "" ||
			strings.TrimSpace(statement.StoreVersion) == "" {
			return errors.New("external head witness signer head statement mismatch")
		}
		return nil

	case ExternalHeadWitnessSigningKindPolicy:
		if operation != "policy-current" && operation != "policy-transition" {
			return errors.New("external head witness signer policy operation is not allowed")
		}
		var statement remotePolicyStatement
		if err := decodeStrictRemoteJSON(bytes.NewReader(payload), &statement); err != nil {
			return errors.New("external head witness signer policy payload is invalid")
		}
		if statement.Protocol != remoteWitnessProtocolV1 ||
			statement.Operation != operation ||
			statement.WitnessKeyID != keyID ||
			strings.TrimSpace(statement.Nonce) == "" {
			return errors.New("external head witness signer policy statement mismatch")
		}
		if err := validateQuorumPolicyState(statement.Policy); err != nil {
			return errors.New("external head witness signer policy state is invalid")
		}
		return nil

	default:
		return errors.New("external head witness signer kind is not allowed")
	}
}
