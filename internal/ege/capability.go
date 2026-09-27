package ege

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const CapabilityFenceVersion = "aegis.ege/capability-fence/v0alpha1"

var (
	ErrCapabilityFenceInvalid        = errors.New("capability fence is invalid")
	ErrCapabilityAuthorityChanged    = errors.New("capability authority term changed")
	ErrCapabilityRevoked             = errors.New("capability revocation epoch changed")
	ErrCapabilityTargetChanged       = errors.New("capability target identity changed")
	ErrCapabilityStateChanged        = errors.New("capability state binding changed")
)

type CapabilityFenceClaims struct {
	Version            string `json:"version"`
	AuthorityDomain    string `json:"authority_domain"`
	AuthorityTerm      uint64 `json:"authority_term"`
	DecisionEpoch      uint64 `json:"decision_epoch"`
	RevocationEpoch    uint64 `json:"revocation_epoch"`
	TargetIdentity     string `json:"target_identity"`
	StateBindingDigest string `json:"state_binding_digest"`
}

type CapabilityAuthoritySnapshot struct {
	AuthorityDomain string
	AuthorityTerm   uint64
	RevocationEpoch uint64
}

type CapabilityStateBinding struct {
	Target          Target `json:"target"`
	TargetIdentity  string `json:"target_identity"`
	ResourceVersion string `json:"resource_version"`
	PlanDigest      string `json:"plan_digest"`
}

func DigestCapabilityStateBinding(binding CapabilityStateBinding) (string, error) {
	binding.Target.Type = strings.TrimSpace(binding.Target.Type)
	binding.Target.Name = strings.TrimSpace(binding.Target.Name)
	binding.TargetIdentity = strings.TrimSpace(binding.TargetIdentity)
	binding.ResourceVersion = strings.TrimSpace(binding.ResourceVersion)
	binding.PlanDigest = strings.TrimSpace(binding.PlanDigest)

	switch {
	case binding.Target.Type == "" || binding.Target.Name == "":
		return "", fmt.Errorf("%w: target is required", ErrCapabilityFenceInvalid)
	case binding.TargetIdentity == "":
		return "", fmt.Errorf("%w: target identity is required", ErrCapabilityFenceInvalid)
	case binding.ResourceVersion == "":
		return "", fmt.Errorf("%w: resource version is required", ErrCapabilityFenceInvalid)
	case binding.PlanDigest == "":
		return "", fmt.Errorf("%w: plan digest is required", ErrCapabilityFenceInvalid)
	}

	payload, err := json.Marshal(binding)
	if err != nil {
		return "", fmt.Errorf("marshal capability state binding: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func ValidateCapabilityFenceClaims(claims CapabilityFenceClaims) error {
	switch {
	case claims.Version != CapabilityFenceVersion:
		return fmt.Errorf("%w: unsupported version %q", ErrCapabilityFenceInvalid, claims.Version)
	case strings.TrimSpace(claims.AuthorityDomain) == "":
		return fmt.Errorf("%w: authority domain is required", ErrCapabilityFenceInvalid)
	case claims.AuthorityTerm == 0:
		return fmt.Errorf("%w: authority term must be non-zero", ErrCapabilityFenceInvalid)
	case claims.DecisionEpoch == 0:
		return fmt.Errorf("%w: decision epoch must be non-zero", ErrCapabilityFenceInvalid)
	case claims.TargetIdentity == "":
		return fmt.Errorf("%w: target identity is required", ErrCapabilityFenceInvalid)
	case claims.StateBindingDigest == "":
		return fmt.Errorf("%w: state binding digest is required", ErrCapabilityFenceInvalid)
	default:
		return nil
	}
}

func ValidateCapabilityFence(
	claims CapabilityFenceClaims,
	current CapabilityAuthoritySnapshot,
	state CapabilityStateBinding,
) error {
	if err := ValidateCapabilityFenceClaims(claims); err != nil {
		return err
	}
	if strings.TrimSpace(current.AuthorityDomain) == "" || current.AuthorityTerm == 0 {
		return fmt.Errorf("%w: current authority snapshot is incomplete", ErrCapabilityFenceInvalid)
	}
	if claims.AuthorityDomain != current.AuthorityDomain || claims.AuthorityTerm != current.AuthorityTerm {
		return ErrCapabilityAuthorityChanged
	}
	if claims.RevocationEpoch != current.RevocationEpoch {
		return ErrCapabilityRevoked
	}
	if claims.TargetIdentity != strings.TrimSpace(state.TargetIdentity) {
		return ErrCapabilityTargetChanged
	}
	digest, err := DigestCapabilityStateBinding(state)
	if err != nil {
		return err
	}
	if claims.StateBindingDigest != digest {
		return ErrCapabilityStateChanged
	}
	return nil
}
