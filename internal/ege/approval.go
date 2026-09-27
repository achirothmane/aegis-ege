package ege

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

const ApprovalVersion = "aegis.ege/approval/v0alpha1"

type ApprovalClaims struct {
	ApprovalID      string    `json:"approval_id"`
	IntentID        string    `json:"intent_id"`
	ApproverID      string    `json:"approver_id"`
	Kind            string    `json:"kind"`
	Target          Target    `json:"target"`
	Action          string    `json:"action"`
	ResourceVersion string    `json:"resource_version"`
	PlanDigest      string    `json:"plan_digest"`
	ValidUntil      time.Time `json:"valid_until"`
}

type ApprovalAttestation struct {
	APIVersion string         `json:"api_version"`
	KeyID      string         `json:"key_id"`
	Claims     ApprovalClaims `json:"claims"`
	Signature  string         `json:"signature"`
}

func SignApproval(ctx context.Context, authority PermitAuthority, claims ApprovalClaims) (ApprovalAttestation, error) {
	if authority == nil {
		return ApprovalAttestation{}, errors.New("approval authority is required")
	}
	if err := validateApprovalClaims(claims); err != nil {
		return ApprovalAttestation{}, err
	}
	claims.ValidUntil = claims.ValidUntil.UTC()
	payload, err := canonicalApprovalPayload(claims)
	if err != nil {
		return ApprovalAttestation{}, err
	}
	keyID, signature, err := authority.Sign(ctx, payload)
	if err != nil {
		return ApprovalAttestation{}, fmt.Errorf("sign approval attestation: %w", err)
	}
	return ApprovalAttestation{
		APIVersion: ApprovalVersion,
		KeyID:      keyID,
		Claims:     claims,
		Signature:  base64.StdEncoding.EncodeToString(signature),
	}, nil
}

func VerifyApproval(ctx context.Context, authority SignatureVerifier, approval ApprovalAttestation) error {
	if authority == nil {
		return errors.New("approval authority is required")
	}
	if approval.APIVersion != ApprovalVersion {
		return fmt.Errorf("unsupported approval version %q", approval.APIVersion)
	}
	if approval.KeyID == "" || approval.Signature == "" {
		return errors.New("approval key_id and signature are required")
	}
	if err := validateApprovalClaims(approval.Claims); err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(approval.Signature)
	if err != nil {
		return fmt.Errorf("decode approval signature: %w", err)
	}
	payload, err := canonicalApprovalPayload(approval.Claims)
	if err != nil {
		return err
	}
	if err := authority.Verify(ctx, approval.KeyID, payload, signature); err != nil {
		return err
	}
	return nil
}

func ApprovalRef(approval ApprovalAttestation) (string, error) {
	normalized := approval
	normalized.Claims.ValidUntil = normalized.Claims.ValidUntil.UTC()
	body, err := json.Marshal(normalized)
	if err != nil {
		return "", fmt.Errorf("marshal approval attestation: %w", err)
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateApprovalForPermit(
	ctx context.Context,
	authority SignatureVerifier,
	approval ApprovalAttestation,
	claims PermitClaims,
	now time.Time,
) error {
	if err := VerifyApproval(ctx, authority, approval); err != nil {
		return fmt.Errorf("verify approval: %w", err)
	}
	a := approval.Claims
	if !now.IsZero() && now.UTC().After(a.ValidUntil.UTC()) {
		return errors.New("approval expired")
	}
	if a.IntentID != claims.IntentID {
		return errors.New("approval intent mismatch")
	}
	if a.Kind != claims.Kind {
		return errors.New("approval kind mismatch")
	}
	if a.Target != claims.Target {
		return errors.New("approval target mismatch")
	}
	if a.Action != claims.Action {
		return errors.New("approval action mismatch")
	}
	if a.ResourceVersion != claims.ResourceVersion {
		return errors.New("approval resource version mismatch")
	}
	if a.PlanDigest != claims.PlanDigest {
		return errors.New("approval plan digest mismatch")
	}
	return nil
}

func SignPermitWithApprovals(
	ctx context.Context,
	permitAuthority PermitAuthority,
	approvalAuthority SignatureVerifier,
	claims PermitClaims,
	approvals []ApprovalAttestation,
	now time.Time,
) (Permit, error) {
	refs, err := validatedApprovalRefs(ctx, approvalAuthority, approvals, claims, now)
	if err != nil {
		return Permit{}, err
	}
	claims.ApprovalRefs = refs
	return SignPermit(ctx, permitAuthority, claims)
}

func VerifyPermitWithApprovals(
	ctx context.Context,
	permitAuthority SignatureVerifier,
	approvalAuthority SignatureVerifier,
	permit Permit,
	approvals []ApprovalAttestation,
	now time.Time,
) error {
	if err := VerifyPermit(ctx, permitAuthority, permit); err != nil {
		return err
	}
	refs, err := validatedApprovalRefs(ctx, approvalAuthority, approvals, permit.Claims, now)
	if err != nil {
		return err
	}
	expected := append([]string(nil), permit.Claims.ApprovalRefs...)
	sort.Strings(expected)
	if len(refs) != len(expected) {
		return errors.New("approval reference set mismatch")
	}
	for i := range refs {
		if refs[i] != expected[i] {
			return errors.New("approval reference set mismatch")
		}
	}
	return nil
}

func validatedApprovalRefs(
	ctx context.Context,
	authority SignatureVerifier,
	approvals []ApprovalAttestation,
	claims PermitClaims,
	now time.Time,
) ([]string, error) {
	refs := make([]string, 0, len(approvals))
	seen := make(map[string]struct{}, len(approvals))
	for _, approval := range approvals {
		if err := ValidateApprovalForPermit(ctx, authority, approval, claims, now); err != nil {
			return nil, err
		}
		ref, err := ApprovalRef(approval)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[ref]; exists {
			return nil, errors.New("duplicate approval attestation")
		}
		seen[ref] = struct{}{}
		refs = append(refs, ref)
	}
	sort.Strings(refs)
	return refs, nil
}

func validateApprovalClaims(claims ApprovalClaims) error {
	switch {
	case claims.ApprovalID == "":
		return errors.New("approval_id is required")
	case claims.IntentID == "":
		return errors.New("intent_id is required")
	case claims.ApproverID == "":
		return errors.New("approver_id is required")
	case claims.Kind == "":
		return errors.New("kind is required")
	case claims.Target.Type == "" || claims.Target.Name == "":
		return errors.New("approval target is required")
	case claims.Action == "":
		return errors.New("approval action is required")
	case claims.ResourceVersion == "":
		return errors.New("approval resource_version is required")
	case claims.PlanDigest == "":
		return errors.New("approval plan_digest is required")
	case claims.ValidUntil.IsZero():
		return errors.New("approval valid_until is required")
	default:
		return nil
	}
}

func canonicalApprovalPayload(claims ApprovalClaims) ([]byte, error) {
	claims.ValidUntil = claims.ValidUntil.UTC()
	body, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal approval claims: %w", err)
	}
	const domain = "aegis-ege/approval-attestation/v0alpha1\x00"
	return append([]byte(domain), body...), nil
}
