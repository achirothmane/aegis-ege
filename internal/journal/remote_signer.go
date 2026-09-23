package journal

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type RemoteSigner struct {
	keyID    string
	endpoint string
	client   *http.Client
}

func NewRemoteSigner(
	keyID string,
	endpoint string,
	client *http.Client,
) (*RemoteSigner, error) {
	keyID = strings.TrimSpace(keyID)
	endpoint = strings.TrimRight(strings.TrimSpace(endpoint), "/")
	if keyID == "" {
		return nil, fmt.Errorf("remote signer key id is required")
	}
	if endpoint == "" {
		return nil, fmt.Errorf("remote signer endpoint is required")
	}
	if !strings.HasPrefix(endpoint, "https://") {
		return nil, fmt.Errorf("remote signer endpoint must use HTTPS")
	}
	if client == nil {
		return nil, fmt.Errorf("remote signer HTTP client is required")
	}
	return &RemoteSigner{keyID: keyID, endpoint: endpoint, client: client}, nil
}

func (s *RemoteSigner) KeyID() string {
	return s.keyID
}

func (s *RemoteSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	requestBody, err := json.Marshal(struct {
		KeyID   string `json:"key_id"`
		Payload string `json:"payload"`
	}{
		KeyID:   s.keyID,
		Payload: base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return nil, fmt.Errorf("encode remote signing request: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		s.endpoint+"/v1/sign",
		bytes.NewReader(requestBody),
	)
	if err != nil {
		return nil, fmt.Errorf("build remote signing request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")

	response, err := s.client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("remote signing request: %w", err)
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 2048))
		return nil, fmt.Errorf(
			"remote signer returned HTTP %d: %s",
			response.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var result struct {
		KeyID     string `json:"key_id"`
		Signature string `json:"signature"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return nil, fmt.Errorf("decode remote signing response: %w", err)
	}
	if result.KeyID != s.keyID {
		return nil, fmt.Errorf(
			"remote signer key id mismatch: expected %q got %q",
			s.keyID,
			result.KeyID,
		)
	}
	signature, err := base64.StdEncoding.DecodeString(result.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode remote signature: %w", err)
	}
	if len(signature) == 0 {
		return nil, fmt.Errorf("remote signer returned empty signature")
	}
	return signature, nil
}
