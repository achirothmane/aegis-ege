package ege

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const (
	EvidenceManifestVersion = "aegis.ege/evidence/v0alpha1"
	PermitVersion           = "aegis.ege/permit/v0alpha1"
)

type Target struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type EvidenceManifest struct {
	APIVersion      string    `json:"api_version"`
	IntentID        string    `json:"intent_id"`
	Kind            string    `json:"kind"`
	Target          Target    `json:"target"`
	ResourceVersion string    `json:"resource_version"`
	EvidenceDigest  string    `json:"evidence_digest"`
	PlanDigest      string    `json:"plan_digest"`
	ObservedAt      time.Time `json:"observed_at"`
	EvidenceClasses []string  `json:"evidence_classes"`
}

type PermitClaims struct {
	IntentID               string    `json:"intent_id"`
	Kind                   string    `json:"kind"`
	Target                 Target    `json:"target"`
	Action                 string    `json:"action"`
	ResourceVersion        string    `json:"resource_version"`
	EvidenceDigest         string    `json:"evidence_digest"`
	EvidenceManifestDigest string    `json:"evidence_manifest_digest"`
	PlanDigest             string    `json:"plan_digest"`
	ValidUntil             time.Time `json:"valid_until"`
}

type Permit struct {
	APIVersion string       `json:"api_version"`
	KeyID      string       `json:"key_id"`
	Claims     PermitClaims `json:"claims"`
	Signature  string       `json:"signature"`
}

type PermitAuthority interface {
	Sign(context.Context, []byte) (string, []byte, error)
	Verify(context.Context, string, []byte, []byte) error
}

type Ed25519Authority struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewEphemeralEd25519Authority() (*Ed25519Authority, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate EGE permit key: %w", err)
	}
	sum := sha256.Sum256(publicKey)
	return &Ed25519Authority{
		keyID:      "ed25519:" + hex.EncodeToString(sum[:12]),
		privateKey: privateKey,
		publicKey:  publicKey,
	}, nil
}

func (a *Ed25519Authority) Sign(ctx context.Context, payload []byte) (string, []byte, error) {
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	return a.keyID, ed25519.Sign(a.privateKey, payload), nil
}

func (a *Ed25519Authority) Verify(ctx context.Context, keyID string, payload, signature []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if keyID != a.keyID {
		return fmt.Errorf("unknown EGE permit key %q", keyID)
	}
	if !ed25519.Verify(a.publicKey, payload, signature) {
		return errors.New("EGE permit signature verification failed")
	}
	return nil
}

func DigestEvidenceManifest(manifest EvidenceManifest) (string, error) {
	normalized := manifest
	normalized.ObservedAt = normalized.ObservedAt.UTC()
	normalized.EvidenceClasses = append([]string(nil), normalized.EvidenceClasses...)
	sort.Strings(normalized.EvidenceClasses)
	payload, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal evidence manifest: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func SignPermit(ctx context.Context, authority PermitAuthority, claims PermitClaims) (Permit, error) {
	if authority == nil {
		return Permit{}, errors.New("EGE permit authority is required")
	}
	claims.ValidUntil = claims.ValidUntil.UTC()
	payload, err := canonicalPermitPayload(claims)
	if err != nil {
		return Permit{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return Permit{}, fmt.Errorf("sign EGE permit: %w", err)
	}
	return Permit{
		APIVersion: PermitVersion,
		KeyID:      keyID,
		Claims:     claims,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyPermit(ctx context.Context, authority PermitAuthority, permit Permit) error {
	if authority == nil {
		return errors.New("EGE permit authority is required")
	}
	if permit.APIVersion != PermitVersion {
		return fmt.Errorf("unsupported EGE permit version %q", permit.APIVersion)
	}
	if permit.KeyID == "" || permit.Signature == "" {
		return errors.New("EGE permit key_id and signature are required")
	}
	signature, err := base64.StdEncoding.DecodeString(permit.Signature)
	if err != nil {
		return fmt.Errorf("decode EGE permit signature: %w", err)
	}
	payload, err := canonicalPermitPayload(permit.Claims)
	if err != nil {
		return err
	}
	if err := authority.Verify(ctx, permit.KeyID, payload, signature); err != nil {
		return err
	}
	return nil
}

func canonicalPermitPayload(claims PermitClaims) ([]byte, error) {
	claims.ValidUntil = claims.ValidUntil.UTC()
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal EGE permit claims: %w", err)
	}
	const domain = "aegis-ege/execution-permit/v0alpha1\x00"
	return append([]byte(domain), body...), nil
}
