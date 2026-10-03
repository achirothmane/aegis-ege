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

const remoteWitnessQuorumPolicyHeader = "X-Aegis-Witness-Quorum-Policy"

type remotePolicyResponse struct {
	Protocol     string            `json:"protocol"`
	Nonce        string            `json:"nonce"`
	WitnessKeyID string            `json:"witness_key_id"`
	Policy       QuorumPolicyState `json:"policy"`
	Signature    string            `json:"signature"`
}

type remotePolicyStatement struct {
	Protocol     string            `json:"protocol"`
	Operation    string            `json:"operation"`
	Nonce        string            `json:"nonce"`
	WitnessKeyID string            `json:"witness_key_id"`
	Policy       QuorumPolicyState `json:"policy"`
}

type remotePolicyTransitionRequest struct {
	Protocol     string            `json:"protocol"`
	Expected     QuorumPolicyState `json:"expected_policy"`
	Next         QuorumPolicyState `json:"next_policy"`
	JournalID    string            `json:"journal_id"`
	ExpectedHead remoteHeadWire    `json:"expected_head"`
}

type governedRemoteWitnessHandler struct {
	stateStore GovernedWitnessStateStore
	keyID      string
	privateKey ed25519.PrivateKey
}

func NewGovernedRemoteWitnessHandler(
	stateStore GovernedWitnessStateStore,
	witnessKeyID string,
	witnessPrivateKey ed25519.PrivateKey,
) (http.Handler, error) {
	witnessKeyID = strings.TrimSpace(witnessKeyID)
	if stateStore == nil {
		return nil, errors.New("governed witness state store is required")
	}
	if witnessKeyID == "" {
		return nil, errors.New("remote witness key id is required")
	}
	if len(witnessPrivateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid remote witness private key")
	}
	return &governedRemoteWitnessHandler{
		stateStore: stateStore,
		keyID:      witnessKeyID,
		privateKey: append(ed25519.PrivateKey(nil), witnessPrivateKey...),
	}, nil
}

func (h *governedRemoteWitnessHandler) ServeHTTP(
	w http.ResponseWriter,
	r *http.Request,
) {
	nonce := strings.TrimSpace(r.Header.Get(remoteWitnessNonceHeader))
	if nonce == "" {
		http.Error(w, "missing witness freshness nonce", http.StatusBadRequest)
		return
	}

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/v1/quorum-policy":
		h.handleCurrentPolicy(w, r, nonce)
		return
	case r.Method == http.MethodPost &&
		r.URL.Path == "/v1/quorum-policy/transition":
		h.handlePolicyTransition(w, r, nonce)
		return
	}

	journalID, operation, ok := parseGovernedWitnessHeadPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.Method == http.MethodGet && operation == "load":
		h.handleHeadLoad(w, r, nonce, journalID)
	case r.Method == http.MethodGet && operation == "rotation-observe":
		h.handleRotationObserve(w, r, nonce, journalID)
	case r.Method == http.MethodPost && operation == "advance":
		h.handleHeadAdvance(w, r, nonce, journalID)
	default:
		http.NotFound(w, r)
	}
}

func (h *governedRemoteWitnessHandler) handleHeadLoad(
	w http.ResponseWriter,
	r *http.Request,
	nonce string,
	journalID string,
) {
	policy, err := requireRemoteQuorumPolicy(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusPreconditionRequired)
		return
	}
	state, err := h.stateStore.Load(r.Context())
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	if state.Policy != policy || policy.Phase != QuorumPolicyPhaseActive {
		http.Error(w, ErrQuorumPolicyMismatch.Error(), http.StatusPreconditionFailed)
		return
	}
	head, ok := state.Heads[journalID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	head.StoreVersion = state.StoreVersion
	h.writeSignedHead(w, "load", nonce, head, &state.Policy)
}

func (h *governedRemoteWitnessHandler) handleRotationObserve(
	w http.ResponseWriter,
	r *http.Request,
	nonce string,
	journalID string,
) {
	state, err := h.stateStore.Load(r.Context())
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	head, ok := state.Heads[journalID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	head.StoreVersion = state.StoreVersion
	h.writeSignedHead(
		w,
		"rotation-observe",
		nonce,
		head,
		&state.Policy,
	)
}

func (h *governedRemoteWitnessHandler) handleHeadAdvance(
	w http.ResponseWriter,
	r *http.Request,
	nonce string,
	journalID string,
) {
	policy, err := requireRemoteQuorumPolicy(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusPreconditionRequired)
		return
	}
	var request remoteAdvanceRequest
	if err := decodeStrictRemoteJSON(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Protocol != remoteWitnessProtocolV1 {
		http.Error(w, "remote witness protocol mismatch", http.StatusBadRequest)
		return
	}
	if request.Next.JournalID != journalID {
		http.Error(w, "journal id mismatch", http.StatusBadRequest)
		return
	}

	state, err := h.stateStore.Load(r.Context())
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	if state.Policy != policy || policy.Phase != QuorumPolicyPhaseActive {
		http.Error(w, ErrQuorumPolicyMismatch.Error(), http.StatusPreconditionFailed)
		return
	}

	current, exists := state.Heads[journalID]
	if exists {
		current.StoreVersion = state.StoreVersion
		expected := remoteWireToExternalHead(request.Expected)
		if expected.StoreVersion != state.StoreVersion ||
			!sameSemanticHead(expected, current) {
			http.Error(w, ErrExternalHeadConflict.Error(), http.StatusConflict)
			return
		}
	} else if !remoteHeadWireIsZero(request.Expected) {
		http.Error(w, ErrExternalHeadConflict.Error(), http.StatusConflict)
		return
	}

	next := remoteWireToExternalHead(request.Next)
	next.StoreVersion = ""
	if exists {
		if next.Sequence < current.Sequence ||
			(next.Sequence == current.Sequence &&
				!sameSemanticHead(next, current)) {
			http.Error(w, ErrExternalHeadConflict.Error(), http.StatusConflict)
			return
		}
	} else if next.Sequence != 0 {
		http.Error(w, ErrExternalHeadConflict.Error(), http.StatusConflict)
		return
	}

	if state.Heads == nil {
		state.Heads = map[string]ExternalHead{}
	}
	state.Heads[journalID] = next
	saved, err := h.stateStore.CompareAndSwap(
		r.Context(),
		state.StoreVersion,
		state,
	)
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	savedHead := saved.Heads[journalID]
	savedHead.StoreVersion = saved.StoreVersion
	h.writeSignedHead(w, "advance", nonce, savedHead, &saved.Policy)
}

func (h *governedRemoteWitnessHandler) handleCurrentPolicy(
	w http.ResponseWriter,
	r *http.Request,
	nonce string,
) {
	state, err := h.stateStore.Load(r.Context())
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	h.writeSignedPolicy(w, "policy-current", nonce, state.Policy)
}

func (h *governedRemoteWitnessHandler) handlePolicyTransition(
	w http.ResponseWriter,
	r *http.Request,
	nonce string,
) {
	var request remotePolicyTransitionRequest
	if err := decodeStrictRemoteJSON(r.Body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if request.Protocol != remoteWitnessProtocolV1 {
		http.Error(w, "remote witness protocol mismatch", http.StatusBadRequest)
		return
	}
	request.JournalID = strings.TrimSpace(request.JournalID)
	if request.JournalID == "" ||
		request.ExpectedHead.JournalID != request.JournalID {
		http.Error(w, "transition journal id mismatch", http.StatusBadRequest)
		return
	}

	state, err := h.stateStore.Load(r.Context())
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	if state.Policy != request.Expected {
		http.Error(w, ErrQuorumPolicyMismatch.Error(), http.StatusPreconditionFailed)
		return
	}
	if err := ValidateQuorumPolicyTransition(
		request.Expected,
		request.Next,
	); err != nil {
		http.Error(w, err.Error(), http.StatusPreconditionFailed)
		return
	}

	head, ok := state.Heads[request.JournalID]
	if !ok {
		http.NotFound(w, r)
		return
	}
	expectedHead := remoteWireToExternalHead(request.ExpectedHead)
	if expectedHead.StoreVersion != state.StoreVersion ||
		!sameSemanticHead(expectedHead, head) {
		http.Error(
			w,
			ErrQuorumRotationContinuity.Error(),
			http.StatusConflict,
		)
		return
	}

	state.Policy = request.Next
	saved, err := h.stateStore.CompareAndSwap(
		r.Context(),
		state.StoreVersion,
		state,
	)
	if err != nil {
		h.writeStateError(w, err)
		return
	}
	h.writeSignedPolicy(
		w,
		"policy-transition",
		nonce,
		saved.Policy,
	)
}

func (h *governedRemoteWitnessHandler) writeSignedHead(
	w http.ResponseWriter,
	operation string,
	nonce string,
	head ExternalHead,
	policy *QuorumPolicyState,
) {
	result := remoteHeadResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        nonce,
		WitnessKeyID: h.keyID,
		Head:         externalHeadToRemoteWire(head),
		Policy:       policy,
	}
	payload, err := remoteWitnessSigningPayload(operation, result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(h.privateKey, payload),
	)
	writeRemoteJSON(w, result)
}

func (h *governedRemoteWitnessHandler) writeSignedPolicy(
	w http.ResponseWriter,
	operation string,
	nonce string,
	policy QuorumPolicyState,
) {
	result := remotePolicyResponse{
		Protocol:     remoteWitnessProtocolV1,
		Nonce:        nonce,
		WitnessKeyID: h.keyID,
		Policy:       policy,
	}
	payload, err := remotePolicySigningPayload(operation, result)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result.Signature = base64.StdEncoding.EncodeToString(
		ed25519.Sign(h.privateKey, payload),
	)
	writeRemoteJSON(w, result)
}

func (h *governedRemoteWitnessHandler) writeStateError(
	w http.ResponseWriter,
	err error,
) {
	switch {
	case errors.Is(err, ErrGovernedWitnessStateNotFound):
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	case errors.Is(err, ErrGovernedWitnessStateConflict),
		errors.Is(err, ErrExternalHeadConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func parseGovernedWitnessHeadPath(path string) (string, string, bool) {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "heads" {
		return "", "", false
	}
	journalID, err := url.PathUnescape(parts[2])
	if err != nil || strings.TrimSpace(journalID) == "" {
		return "", "", false
	}
	switch len(parts) {
	case 3:
		return journalID, "load", true
	case 4:
		if parts[3] == "advance" || parts[3] == "rotation-observe" {
			return journalID, parts[3], true
		}
	}
	return "", "", false
}

func requireRemoteQuorumPolicy(
	r *http.Request,
) (QuorumPolicyState, error) {
	encoded := strings.TrimSpace(
		r.Header.Get(remoteWitnessQuorumPolicyHeader),
	)
	if encoded == "" {
		return QuorumPolicyState{}, errors.New(
			"governed quorum policy is required",
		)
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return QuorumPolicyState{}, errors.New(
			"decode governed quorum policy",
		)
	}
	var policy QuorumPolicyState
	if err := decodeStrictRemoteJSON(bytes.NewReader(raw), &policy); err != nil {
		return QuorumPolicyState{}, err
	}
	if err := validateQuorumPolicyState(policy); err != nil {
		return QuorumPolicyState{}, err
	}
	return policy, nil
}

func encodeRemoteQuorumPolicy(
	policy QuorumPolicyState,
) (string, error) {
	if err := validateQuorumPolicyState(policy); err != nil {
		return "", err
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func remotePolicySigningPayload(
	operation string,
	response remotePolicyResponse,
) ([]byte, error) {
	statement := remotePolicyStatement{
		Protocol:     response.Protocol,
		Operation:    operation,
		Nonce:        response.Nonce,
		WitnessKeyID: response.WitnessKeyID,
		Policy:       response.Policy,
	}
	return json.Marshal(statement)
}

func decodeStrictRemoteJSON(
	reader io.Reader,
	dst any,
) error {
	decoder := json.NewDecoder(io.LimitReader(reader, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func remoteHeadWireIsZero(head remoteHeadWire) bool {
	return head.JournalID == "" &&
		head.Sequence == 0 &&
		head.HeadHash == "" &&
		head.KeyID == "" &&
		head.StoreVersion == ""
}

func writeRemoteJSON(w http.ResponseWriter, value any) {
	payload, err := json.Marshal(value)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func decodeRemotePolicyResponse(
	body io.Reader,
) (remotePolicyResponse, error) {
	var result remotePolicyResponse
	if err := decodeStrictRemoteJSON(body, &result); err != nil {
		return remotePolicyResponse{}, fmt.Errorf(
			"decode remote witness policy response: %w",
			err,
		)
	}
	return result, nil
}

func postRemotePolicyRequest(
	ctx context.Context,
	client *http.Client,
	endpoint string,
	path string,
	nonce string,
	requestBody any,
) (*http.Response, error) {
	payload, err := json.Marshal(requestBody)
	if err != nil {
		return nil, err
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		endpoint+path,
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(remoteWitnessNonceHeader, nonce)
	return client.Do(request)
}
