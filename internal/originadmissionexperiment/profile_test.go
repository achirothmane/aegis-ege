// This package is a cooperative, test-only admission experiment. It is not a
// production extension loader or a new shared kernel record family.
package originadmissionexperiment

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
	"sync"
)

const originProfile = "extension-origin-admission/experiment-v0.1"
const originValidator = "origin-grant/ed25519-v0.1"

type artifact struct {
	Path string `json:"path"`
	Data string `json:"data"`
}

// All executable/configuration dependencies in the bounded fixture are in this
// snapshot. Remote mutable dependencies and real filesystem races are excluded.
func bundleHash(files []artifact) (string, error) {
	if len(files) == 0 {
		return "", errors.New("missing source snapshot")
	}
	ordered := append([]artifact(nil), files...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Path < ordered[j].Path })
	for i, file := range ordered {
		if file.Path == "" || file.Path == "." || path.IsAbs(file.Path) ||
			path.Clean(file.Path) != file.Path || file.Path == ".." ||
			strings.HasPrefix(file.Path, "../") || strings.Contains(file.Path, "\\") {
			return "", errors.New("non-canonical artifact path")
		}
		if i > 0 && ordered[i-1].Path == file.Path {
			return "", errors.New("duplicate artifact path")
		}
	}
	payload, err := json.Marshal(ordered)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:]), nil
}

type executionOrigin struct {
	ID        string `json:"origin_id"`
	Kind      string `json:"origin_type"`
	SourceRef string `json:"source_ref"`
}

// These are owner-issued bindings, not requester-supplied trust flags.
type grantBody struct {
	Issuer          string          `json:"issuer"`
	Profile         string          `json:"profile"`
	Validator       string          `json:"validator"`
	Actor           string          `json:"actor"`
	Origin          executionOrigin `json:"origin"`
	SourceHash      string          `json:"source_hash"`
	Capability      string          `json:"capability"`
	Target          string          `json:"target"`
	Namespace       string          `json:"namespace"`
	PolicyHash      string          `json:"policy_hash"`
	RevocationEpoch uint64          `json:"revocation_epoch"`
	NotBefore       int64           `json:"not_before"`
	ExpiresAt       int64           `json:"expires_at"`
}

type signedGrant struct {
	Body      grantBody
	Signature []byte
}

func signGrant(body grantBody, key ed25519.PrivateKey) signedGrant {
	payload, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return signedGrant{Body: body, Signature: ed25519.Sign(key, payload)}
}

type activationRequest struct {
	ActionID   string
	Profile    string
	Actor      string
	Origin     executionOrigin
	SourceHash string
	Capability string
	Target     string
	Namespace  string
	Grant      *signedGrant
}

// This is a profile-specific witness in DecisionBasis, not a universal schema.
type originWitness struct {
	ActionID        string
	ActionRevision  string
	Profile         string
	Validator       string
	SourceHash      string
	GrantHash       string
	PolicyHash      string
	RevocationEpoch uint64
}

type decision struct {
	Allowed bool
	Reason  string
	Witness originWitness
}

type auditEvent struct {
	Sequence     uint64
	Parent       uint64
	Kind         string
	ActionID     string
	SourceHash   string
	Epoch        uint64
	RewindTarget uint64
}

type capabilityKey struct {
	Actor      string
	OriginID   string
	Capability string
}

type fixtureBoundary struct {
	mu                 sync.Mutex
	owner              string
	ownerKey           ed25519.PublicKey
	origin             executionOrigin
	files              []artifact
	sourceKnown        bool
	policyStatus       string
	policyHash         string
	epoch              uint64
	now                int64
	target             string
	namespace          string
	actorScopes        map[string]map[string]bool
	registry           map[capabilityKey]string
	activations        int
	invocations        int
	history            []auditEvent
	optionalCostMicros *int64
}

func knownCapability(scope string) bool {
	switch scope {
	case "instructions", "tools", "hooks", "code":
		return true
	default:
		return false
	}
}

func (b *fixtureBoundary) evaluateLocked(req activationRequest) decision {
	deny := func(reason string) decision { return decision{Reason: reason} }
	if req.ActionID == "" || req.Profile != originProfile {
		return deny("UNKNOWN_ACTION_OR_PROFILE")
	}
	if !knownCapability(req.Capability) {
		return deny("UNSUPPORTED_CAPABILITY")
	}
	if !b.sourceKnown {
		return deny("UNKNOWN_SOURCE")
	}
	currentHash, err := bundleHash(b.files)
	if err != nil {
		return deny("UNKNOWN_SOURCE")
	}
	if req.Origin != b.origin || req.SourceHash != currentHash {
		return deny("SOURCE_BINDING_CHANGED")
	}
	if b.policyStatus != "READY" || b.policyHash == "" || b.epoch == 0 {
		return deny("MANDATORY_EVALUATION_UNAVAILABLE")
	}
	if req.Target != b.target || req.Namespace != b.namespace {
		return deny("WRONG_BOUNDARY")
	}
	if req.Grant == nil {
		return deny("MISSING_GRANT")
	}
	g := req.Grant.Body
	payload, err := json.Marshal(g)
	if err != nil || len(b.ownerKey) != ed25519.PublicKeySize ||
		g.Issuer != b.owner || !ed25519.Verify(b.ownerKey, payload, req.Grant.Signature) {
		return deny("UNAUTHENTICATED_GRANT")
	}
	if g.Profile != originProfile || g.Validator != originValidator {
		return deny("UNKNOWN_GRANT_PROFILE_OR_VALIDATOR")
	}
	if g.Actor != req.Actor || g.Origin != req.Origin || g.SourceHash != currentHash ||
		g.Capability != req.Capability || g.Target != req.Target || g.Namespace != req.Namespace {
		return deny("GRANT_BINDING_MISMATCH")
	}
	if g.PolicyHash != b.policyHash || g.RevocationEpoch != b.epoch {
		return deny("REVOKED_OR_SUPERSEDED_GRANT")
	}
	if g.NotBefore >= g.ExpiresAt || b.now < g.NotBefore || b.now >= g.ExpiresAt {
		return deny("GRANT_OUTSIDE_VALIDITY")
	}
	if !b.actorScopes[req.Actor][req.Capability] {
		return deny("ACTOR_SCOPE_DENIED")
	}
	revisionPayload, _ := json.Marshal(struct {
		ActionID   string          `json:"action_id"`
		Profile    string          `json:"profile"`
		Actor      string          `json:"actor"`
		Origin     executionOrigin `json:"origin"`
		SourceHash string          `json:"source_hash"`
		Capability string          `json:"capability"`
		Target     string          `json:"target"`
		Namespace  string          `json:"namespace"`
	}{req.ActionID, req.Profile, req.Actor, req.Origin, currentHash, req.Capability, req.Target, req.Namespace})
	revisionHash := sha256.Sum256(revisionPayload)
	grantHash := sha256.Sum256(payload)
	return decision{Allowed: true, Reason: "ALLOW_BOUND_CAPABILITY", Witness: originWitness{
		ActionID: req.ActionID, ActionRevision: hex.EncodeToString(revisionHash[:]),
		Profile: originProfile, Validator: originValidator, SourceHash: currentHash,
		GrantHash: hex.EncodeToString(grantHash[:]), PolicyHash: b.policyHash,
		RevocationEpoch: b.epoch,
	}}
}

func (b *fixtureBoundary) admit(req activationRequest) decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.evaluateLocked(req)
}

func (b *fixtureBoundary) appendLocked(kind string, req activationRequest, target uint64) {
	sequence := uint64(len(b.history)) + 1
	b.history = append(b.history, auditEvent{
		Sequence: sequence, Parent: sequence - 1, Kind: kind, ActionID: req.ActionID,
		SourceHash: req.SourceHash, Epoch: b.epoch, RewindTarget: target,
	})
}

func registryKey(req activationRequest) capabilityKey {
	return capabilityKey{Actor: req.Actor, OriginID: req.Origin.ID, Capability: req.Capability}
}

func (b *fixtureBoundary) activate(req activationRequest) decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := b.evaluateLocked(req)
	if !result.Allowed {
		b.appendLocked("ACTIVATION_DENIED", req, 0)
		return result
	}
	b.registry[registryKey(req)] = result.Witness.SourceHash
	b.activations++
	b.appendLocked("ACTIVATED", req, 0)
	return result
}

// Every use crosses the same cooperative boundary; registration alone cannot
// carry an obsolete authorization into the next effect.
func (b *fixtureBoundary) invoke(req activationRequest) decision {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := b.evaluateLocked(req)
	if !result.Allowed {
		b.appendLocked("INVOCATION_DENIED", req, 0)
		return result
	}
	if b.registry[registryKey(req)] != result.Witness.SourceHash {
		b.appendLocked("INVOCATION_DENIED", req, 0)
		return decision{Reason: "CAPABILITY_NOT_ACTIVATED"}
	}
	b.invocations++
	b.appendLocked("INVOKED", req, 0)
	return result
}

func (b *fixtureBoundary) revoke(req activationRequest) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.epoch++
	b.appendLocked("REVOKED", req, 0)
}

// Rewind restores only fixture data. Authority/policy epochs and effect facts
// live outside that snapshot and are never restored from it.
func (b *fixtureBoundary) rewindRegistry(req activationRequest, snapshot map[capabilityKey]string, target uint64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.registry = make(map[capabilityKey]string, len(snapshot))
	for key, value := range snapshot {
		b.registry[key] = value
	}
	b.appendLocked("REWIND", req, target)
}
