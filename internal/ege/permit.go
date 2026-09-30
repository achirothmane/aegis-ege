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
	EvidenceManifestVersion            = "aegis.ege/evidence/v0alpha2"
	EvidenceCompositionProfileVersion  = "aegis.ege/evidence-composition/v1"
	PermitVersion                      = "aegis.ege/permit/v0alpha1"
)

type Target struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type EvidenceDeclarationAssurance string

const (
	EvidenceDeclarationUnknown      EvidenceDeclarationAssurance = "UNKNOWN"
	EvidenceDeclarationAsserted     EvidenceDeclarationAssurance = "ASSERTED"
	EvidenceDeclarationCorroborated EvidenceDeclarationAssurance = "CORROBORATED"
)

type EvidenceIndependenceStatus string

const (
	EvidenceIndependenceUnknown      EvidenceIndependenceStatus = "UNKNOWN"
	EvidenceIndependenceDependent    EvidenceIndependenceStatus = "DEPENDENT"
	EvidenceIndependenceAsserted     EvidenceIndependenceStatus = "ASSERTED"
	EvidenceIndependenceCorroborated EvidenceIndependenceStatus = "CORROBORATED"
)

type EvidenceDependency struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Material bool   `json:"material"`
}

type EvidenceSourceDeclaration struct {
	ProducerID          string                       `json:"producer_id"`
	Subject             string                       `json:"subject"`
	ObservationPath     string                       `json:"observation_path"`
	DependencyCoverage  []string                     `json:"dependency_coverage,omitempty"`
	Dependencies        []EvidenceDependency         `json:"dependencies,omitempty"`
	Assurance           EvidenceDeclarationAssurance `json:"assurance"`
	CorroborationRefs   []string                     `json:"corroboration_refs,omitempty"`
}

type EvidenceSource struct {
	Name        string                     `json:"name"`
	TrustDomain string                     `json:"trust_domain"`
	Digest      string                     `json:"digest"`
	ObservedAt  time.Time                  `json:"observed_at"`
	Classes     []string                   `json:"classes"`
	Declaration *EvidenceSourceDeclaration `json:"declaration,omitempty"`
}

type EvidencePairAssessment struct {
	LeftSource         string                     `json:"left_source"`
	RightSource        string                     `json:"right_source"`
	Status             EvidenceIndependenceStatus `json:"status"`
	SharedDependencies []EvidenceDependency       `json:"shared_dependencies,omitempty"`
	ReasonCodes        []string                   `json:"reason_codes,omitempty"`
}

type EvidenceCompositionAssessment struct {
	ProfileVersion          string                     `json:"profile_version"`
	RequiredIndependence    EvidenceIndependenceStatus `json:"required_independence"`
	IndependentSourceCount  int                        `json:"independent_source_count"`
	OverallIndependence     EvidenceIndependenceStatus `json:"overall_independence"`
	PairAssessments         []EvidencePairAssessment   `json:"pair_assessments,omitempty"`
}

type EvidenceManifest struct {
	APIVersion      string                         `json:"api_version"`
	IntentID        string                         `json:"intent_id"`
	Kind            string                         `json:"kind"`
	Target          Target                         `json:"target"`
	ResourceVersion string                         `json:"resource_version"`
	EvidenceDigest  string                         `json:"evidence_digest"`
	PlanDigest      string                         `json:"plan_digest"`
	ObservedAt      time.Time                      `json:"observed_at"`
	EvidenceClasses []string                       `json:"evidence_classes"`
	Sources         []EvidenceSource               `json:"sources,omitempty"`
	Composition     *EvidenceCompositionAssessment `json:"composition,omitempty"`
}

type ExecutionBindingClaims struct {
	DestinationID          string `json:"destination_id"`
	AccountID              string `json:"account_id"`
	Endpoint               string `json:"endpoint"`
	AdapterProfile         string `json:"adapter_profile"`
	ExpectedResourceVersion string `json:"expected_resource_version"`
}

type PermitClaims struct {
	IntentID               string                 `json:"intent_id"`
	Kind                   string                 `json:"kind"`
	Target                 Target                 `json:"target"`
	Action                 string                 `json:"action"`
	ResourceVersion        string                 `json:"resource_version"`
	EvidenceDigest         string                 `json:"evidence_digest"`
	EvidenceManifestDigest string                 `json:"evidence_manifest_digest"`
	EvidencePacketDigest   string                 `json:"evidence_packet_digest,omitempty"`
	PlanDigest             string                 `json:"plan_digest"`
	ApprovalRefs           []string               `json:"approval_refs,omitempty"`
	ExecutionBinding       *ExecutionBindingClaims `json:"execution_binding,omitempty"`
	EBAContextProfile      string                 `json:"eba_context_profile,omitempty"`
	EBATraceID             string                 `json:"eba_trace_id,omitempty"`
	EBAAudience            string                 `json:"eba_audience,omitempty"`
	EBANamespace           string                 `json:"eba_namespace,omitempty"`
	EBAAssumptionRefs      []string               `json:"eba_assumption_refs,omitempty"`
	EBAAuthorityRef        string                 `json:"eba_authority_ref,omitempty"`
	CapabilityFence        *CapabilityFenceClaims `json:"capability_fence,omitempty"`
	ValidUntil             time.Time              `json:"valid_until"`
}

type Permit struct {
	APIVersion string       `json:"api_version"`
	KeyID      string       `json:"key_id"`
	Claims     PermitClaims `json:"claims"`
	Signature  string       `json:"signature"`
}

type SignatureVerifier interface {
	Verify(context.Context, string, []byte, []byte) error
}

type PermitAuthority interface {
	SignatureVerifier
	Sign(context.Context, []byte) (string, []byte, error)
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
	normalized.Sources = append([]EvidenceSource(nil), normalized.Sources...)
	for i := range normalized.Sources {
		normalized.Sources[i].ObservedAt = normalized.Sources[i].ObservedAt.UTC()
		normalized.Sources[i].Classes = append([]string(nil), normalized.Sources[i].Classes...)
		sort.Strings(normalized.Sources[i].Classes)
		if normalized.Sources[i].Declaration != nil {
			declaration := *normalized.Sources[i].Declaration
			declaration.DependencyCoverage = append([]string(nil), declaration.DependencyCoverage...)
			sort.Strings(declaration.DependencyCoverage)
			declaration.Dependencies = append([]EvidenceDependency(nil), declaration.Dependencies...)
			sort.Slice(declaration.Dependencies, func(a, b int) bool {
				if declaration.Dependencies[a].Kind != declaration.Dependencies[b].Kind {
					return declaration.Dependencies[a].Kind < declaration.Dependencies[b].Kind
				}
				if declaration.Dependencies[a].ID != declaration.Dependencies[b].ID {
					return declaration.Dependencies[a].ID < declaration.Dependencies[b].ID
				}
				return !declaration.Dependencies[a].Material && declaration.Dependencies[b].Material
			})
			declaration.CorroborationRefs = append([]string(nil), declaration.CorroborationRefs...)
			sort.Strings(declaration.CorroborationRefs)
			normalized.Sources[i].Declaration = &declaration
		}
	}
	sort.Slice(normalized.Sources, func(i, j int) bool {
		if normalized.Sources[i].Name != normalized.Sources[j].Name {
			return normalized.Sources[i].Name < normalized.Sources[j].Name
		}
		if normalized.Sources[i].TrustDomain != normalized.Sources[j].TrustDomain {
			return normalized.Sources[i].TrustDomain < normalized.Sources[j].TrustDomain
		}
		return normalized.Sources[i].Digest < normalized.Sources[j].Digest
	})
	if normalized.Composition != nil {
		composition := *normalized.Composition
		composition.PairAssessments = append([]EvidencePairAssessment(nil), composition.PairAssessments...)
		for i := range composition.PairAssessments {
			composition.PairAssessments[i].SharedDependencies = append(
				[]EvidenceDependency(nil),
				composition.PairAssessments[i].SharedDependencies...,
			)
			sort.Slice(composition.PairAssessments[i].SharedDependencies, func(a, b int) bool {
				if composition.PairAssessments[i].SharedDependencies[a].Kind != composition.PairAssessments[i].SharedDependencies[b].Kind {
					return composition.PairAssessments[i].SharedDependencies[a].Kind < composition.PairAssessments[i].SharedDependencies[b].Kind
				}
				return composition.PairAssessments[i].SharedDependencies[a].ID < composition.PairAssessments[i].SharedDependencies[b].ID
			})
			composition.PairAssessments[i].ReasonCodes = append(
				[]string(nil),
				composition.PairAssessments[i].ReasonCodes...,
			)
			sort.Strings(composition.PairAssessments[i].ReasonCodes)
		}
		sort.Slice(composition.PairAssessments, func(i, j int) bool {
			if composition.PairAssessments[i].LeftSource != composition.PairAssessments[j].LeftSource {
				return composition.PairAssessments[i].LeftSource < composition.PairAssessments[j].LeftSource
			}
			return composition.PairAssessments[i].RightSource < composition.PairAssessments[j].RightSource
		})
		normalized.Composition = &composition
	}
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

func VerifyPermit(ctx context.Context, authority SignatureVerifier, permit Permit) error {
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
	claims.ApprovalRefs = append([]string(nil), claims.ApprovalRefs...)
	sort.Strings(claims.ApprovalRefs)
	claims.EBAAssumptionRefs = append([]string(nil), claims.EBAAssumptionRefs...)
	sort.Strings(claims.EBAAssumptionRefs)
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal EGE permit claims: %w", err)
	}
	const domain = "aegis-ege/execution-permit/v0alpha1\x00"
	return append([]byte(domain), body...), nil
}
