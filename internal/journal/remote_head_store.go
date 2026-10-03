package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	remoteWitnessProtocolV1 = "aegis-ege/external-witness/v1"
	remoteWitnessNonceHeader = "X-Aegis-Witness-Nonce"
)

type RemoteHeadStore struct {
	endpoint       string
	witnessKeyID   string
	witnessKey     ed25519.PublicKey
	client         *http.Client
}


type RemoteWitnessIdentity struct {
	Endpoint             string `json:"endpoint"`
	WitnessKeyID         string `json:"witness_key_id"`
	WitnessPublicKeyHash string `json:"witness_public_key_hash"`
}

func (s *RemoteHeadStore) TrustIdentity() (RemoteWitnessIdentity, error) {
	if s == nil {
		return RemoteWitnessIdentity{}, errors.New("remote witness store is unavailable")
	}
	if s.endpoint == "" || s.witnessKeyID == "" || len(s.witnessKey) != ed25519.PublicKeySize {
		return RemoteWitnessIdentity{}, errors.New("remote witness store has incomplete trust identity")
	}
	sum := sha256.Sum256(s.witnessKey)
	return RemoteWitnessIdentity{
		Endpoint:             s.endpoint,
		WitnessKeyID:         s.witnessKeyID,
		WitnessPublicKeyHash: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

type remoteHeadWire struct {
	JournalID    string `json:"journal_id"`
	Sequence     uint64 `json:"sequence"`
	HeadHash     string `json:"head_hash"`
	KeyID        string `json:"key_id"`
	StoreVersion string `json:"store_version"`
}

type remoteHeadResponse struct {
	Protocol     string         `json:"protocol"`
	Nonce        string         `json:"nonce"`
	WitnessKeyID string         `json:"witness_key_id"`
	Head         remoteHeadWire `json:"head"`
	Signature    string         `json:"signature"`
}

type remoteAdvanceRequest struct {
	Protocol string         `json:"protocol"`
	Expected remoteHeadWire `json:"expected"`
	Next     remoteHeadWire `json:"next"`
}

type remoteWitnessStatement struct {
	Protocol     string `json:"protocol"`
	Operation    string `json:"operation"`
	Nonce        string `json:"nonce"`
	WitnessKeyID string `json:"witness_key_id"`
	JournalID    string `json:"journal_id"`
	Sequence     uint64 `json:"sequence"`
	HeadHash     string `json:"head_hash"`
	KeyID        string `json:"key_id"`
	StoreVersion string `json:"store_version"`
}

func NewRemoteHeadStore(
	endpoint string,
	witnessKeyID string,
	witnessPublicKey ed25519.PublicKey,
	client *http.Client,
) (*RemoteHeadStore, error) {
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	witnessKeyID = strings.TrimSpace(witnessKeyID)
	if endpoint == "" {
		return nil, errors.New("remote witness endpoint is required")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse remote witness endpoint: %w", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return nil, errors.New("remote witness endpoint must use HTTPS")
	}
	if witnessKeyID == "" {
		return nil, errors.New("remote witness key id is required")
	}
	if len(witnessPublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid remote witness public key length: %d", len(witnessPublicKey))
	}
	if client == nil {
		return nil, errors.New("remote witness HTTP client is required")
	}
	return &RemoteHeadStore{
		endpoint:     endpoint,
		witnessKeyID: witnessKeyID,
		witnessKey:   append(ed25519.PublicKey(nil), witnessPublicKey...),
		client:       client,
	}, nil
}

func (s *RemoteHeadStore) Load(
	ctx context.Context,
	journalID string,
) (ExternalHead, error) {
	if s == nil || s.client == nil {
		return ExternalHead{}, errors.New("remote witness store is unavailable")
	}
	journalID = strings.TrimSpace(journalID)
	if journalID == "" {
		return ExternalHead{}, errors.New("journal id is required")
	}
	nonce, err := newRemoteWitnessNonce()
	if err != nil {
		return ExternalHead{}, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		s.endpoint+"/v1/heads/"+url.PathEscape(journalID),
		nil,
	)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("build remote witness load request: %w", err)
	}
	request.Header.Set(remoteWitnessNonceHeader, nonce)

	response, err := s.client.Do(request)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("remote witness load request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusNotFound {
		return ExternalHead{}, ErrExternalHeadNotFound
	}
	if response.StatusCode != http.StatusOK {
		return ExternalHead{}, remoteWitnessHTTPError("load", response)
	}

	result, err := decodeRemoteHeadResponse(response.Body)
	if err != nil {
		return ExternalHead{}, err
	}
	return s.verifyResponse("load", journalID, nonce, result)
}

func (s *RemoteHeadStore) CompareAndAdvance(
	ctx context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	if s == nil || s.client == nil {
		return ExternalHead{}, errors.New("remote witness store is unavailable")
	}
	if strings.TrimSpace(next.JournalID) == "" {
		return ExternalHead{}, errors.New("journal id is required")
	}
	if previous.JournalID != "" && previous.JournalID != next.JournalID {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	nonce, err := newRemoteWitnessNonce()
	if err != nil {
		return ExternalHead{}, err
	}
	payload, err := json.Marshal(remoteAdvanceRequest{
		Protocol: remoteWitnessProtocolV1,
		Expected: externalHeadToRemoteWire(previous),
		Next:     externalHeadToRemoteWire(next),
	})
	if err != nil {
		return ExternalHead{}, fmt.Errorf("encode remote witness advance request: %w", err)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint+"/v1/heads/"+url.PathEscape(next.JournalID)+"/advance",
		bytes.NewReader(payload),
	)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("build remote witness advance request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(remoteWitnessNonceHeader, nonce)

	response, err := s.client.Do(request)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("remote witness advance request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusConflict || response.StatusCode == http.StatusPreconditionFailed {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if response.StatusCode != http.StatusOK {
		return ExternalHead{}, remoteWitnessHTTPError("advance", response)
	}

	result, err := decodeRemoteHeadResponse(response.Body)
	if err != nil {
		return ExternalHead{}, err
	}
	return s.verifyResponse("advance", next.JournalID, nonce, result)
}

func (s *RemoteHeadStore) verifyResponse(
	operation string,
	journalID string,
	nonce string,
	result remoteHeadResponse,
) (ExternalHead, error) {
	if result.Protocol != remoteWitnessProtocolV1 {
		return ExternalHead{}, fmt.Errorf(
			"remote witness protocol mismatch: got %q want %q",
			result.Protocol,
			remoteWitnessProtocolV1,
		)
	}
	if result.Nonce != nonce {
		return ExternalHead{}, errors.New("remote witness freshness nonce mismatch")
	}
	if result.WitnessKeyID != s.witnessKeyID {
		return ExternalHead{}, fmt.Errorf(
			"remote witness key id mismatch: got %q want %q",
			result.WitnessKeyID,
			s.witnessKeyID,
		)
	}
	if result.Head.JournalID != journalID {
		return ExternalHead{}, fmt.Errorf(
			"remote witness journal id mismatch: got %q want %q",
			result.Head.JournalID,
			journalID,
		)
	}
	if strings.TrimSpace(result.Head.StoreVersion) == "" {
		return ExternalHead{}, errors.New("remote witness response is missing CAS store version")
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return ExternalHead{}, fmt.Errorf("decode remote witness signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize {
		return ExternalHead{}, fmt.Errorf("invalid remote witness signature length: %d", len(signature))
	}
	payload, err := remoteWitnessSigningPayload(operation, result)
	if err != nil {
		return ExternalHead{}, err
	}
	if !ed25519.Verify(s.witnessKey, payload, signature) {
		return ExternalHead{}, errors.New("remote witness signature verification failed")
	}
	return remoteWireToExternalHead(result.Head), nil
}

func remoteWitnessSigningPayload(
	operation string,
	response remoteHeadResponse,
) ([]byte, error) {
	statement := remoteWitnessStatement{
		Protocol:     response.Protocol,
		Operation:    operation,
		Nonce:        response.Nonce,
		WitnessKeyID: response.WitnessKeyID,
		JournalID:    response.Head.JournalID,
		Sequence:     response.Head.Sequence,
		HeadHash:     response.Head.HeadHash,
		KeyID:        response.Head.KeyID,
		StoreVersion: response.Head.StoreVersion,
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, fmt.Errorf("encode remote witness signing statement: %w", err)
	}
	return payload, nil
}

func decodeRemoteHeadResponse(body io.Reader) (remoteHeadResponse, error) {
	var result remoteHeadResponse
	decoder := json.NewDecoder(io.LimitReader(body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return remoteHeadResponse{}, fmt.Errorf("decode remote witness response: %w", err)
	}
	return result, nil
}

func newRemoteWitnessNonce() (string, error) {
	var raw [32]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return "", fmt.Errorf("generate remote witness nonce: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func remoteWitnessHTTPError(operation string, response *http.Response) error {
	body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
	return fmt.Errorf(
		"remote witness %s returned HTTP %d: %s",
		operation,
		response.StatusCode,
		strings.TrimSpace(string(body)),
	)
}

func externalHeadToRemoteWire(head ExternalHead) remoteHeadWire {
	return remoteHeadWire{
		JournalID:    head.JournalID,
		Sequence:     head.Sequence,
		HeadHash:     head.HeadHash,
		KeyID:        head.KeyID,
		StoreVersion: head.StoreVersion,
	}
}

func remoteWireToExternalHead(head remoteHeadWire) ExternalHead {
	return ExternalHead{
		JournalID:    head.JournalID,
		Sequence:     head.Sequence,
		HeadHash:     head.HeadHash,
		KeyID:        head.KeyID,
		StoreVersion: head.StoreVersion,
	}
}
