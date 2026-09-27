package server

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

type CapabilityFenceScope struct {
	IntentID string
	Kind     string
	Target   egeproto.Target
}

type CapabilityFenceIssue struct {
	AuthorityDomain string
	AuthorityTerm   uint64
	DecisionEpoch   uint64
	RevocationEpoch uint64
}

type CapabilityFenceAuthority interface {
	Issue(context.Context, CapabilityFenceScope) (CapabilityFenceIssue, error)
	Current(context.Context, CapabilityFenceScope) (egeproto.CapabilityAuthoritySnapshot, error)
}

func capabilityFenceScope(intentID, kind string, target egeTargetDTO) CapabilityFenceScope {
	return CapabilityFenceScope{
		IntentID: intentID,
		Kind:     kind,
		Target:   egeproto.Target{Type: target.Type, Name: target.Name},
	}
}

func capabilityStateBindingFromProduction(
	target egeTargetDTO,
	production egeEvidenceProduction,
) (egeproto.CapabilityStateBinding, error) {
	if production.Decision != decision.Allow || production.PermitBinding == nil {
		return egeproto.CapabilityStateBinding{}, errors.New("capability state requires ALLOW evidence production")
	}
	if production.Snapshot == nil || strings.TrimSpace(production.Snapshot.NodeUID) == "" {
		return egeproto.CapabilityStateBinding{}, errors.New("capability state requires stable target identity")
	}
	return egeproto.CapabilityStateBinding{
		Target: egeproto.Target{
			Type: target.Type,
			Name: target.Name,
		},
		TargetIdentity:  strings.TrimSpace(production.Snapshot.NodeUID),
		ResourceVersion: production.PermitBinding.ResourceVersion,
		PlanDigest:      production.PermitBinding.PlanDigest,
	}, nil
}

func (s *Server) issueExecutionCapabilityFence(
	ctx context.Context,
	intentID string,
	kind string,
	target egeTargetDTO,
	production egeEvidenceProduction,
) (*egeproto.CapabilityFenceClaims, error) {
	if !s.config.RequireCapabilityFencing {
		return nil, nil
	}
	if s.config.CapabilityFenceAuthority == nil {
		return nil, errors.New("capability fence authority is unavailable")
	}

	state, err := capabilityStateBindingFromProduction(target, production)
	if err != nil {
		return nil, err
	}
	stateDigest, err := egeproto.DigestCapabilityStateBinding(state)
	if err != nil {
		return nil, err
	}

	issue, err := s.config.CapabilityFenceAuthority.Issue(
		ctx,
		capabilityFenceScope(intentID, kind, target),
	)
	if err != nil {
		return nil, fmt.Errorf("issue capability fence coordinates: %w", err)
	}

	claims := egeproto.CapabilityFenceClaims{
		Version:            egeproto.CapabilityFenceVersion,
		AuthorityDomain:    strings.TrimSpace(issue.AuthorityDomain),
		AuthorityTerm:      issue.AuthorityTerm,
		DecisionEpoch:      issue.DecisionEpoch,
		RevocationEpoch:    issue.RevocationEpoch,
		TargetIdentity:     state.TargetIdentity,
		StateBindingDigest: stateDigest,
	}
	if err := egeproto.ValidateCapabilityFenceClaims(claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

func (s *Server) revalidateExecutionCapabilityFence(
	ctx context.Context,
	intentID string,
	kind string,
	target egeTargetDTO,
	claims *egeproto.CapabilityFenceClaims,
) error {
	if !s.config.RequireCapabilityFencing {
		return nil
	}
	if claims == nil {
		return errors.New("execution capability fence is required")
	}
	if s.config.CapabilityFenceAuthority == nil {
		return errors.New("capability fence authority is unavailable")
	}

	currentAuthority, err := s.config.CapabilityFenceAuthority.Current(
		ctx,
		capabilityFenceScope(intentID, kind, target),
	)
	if err != nil {
		return fmt.Errorf("read current capability authority: %w", err)
	}

	currentProduction, err := s.egeEvidenceComposer.Compose(ctx, intentID, kind, target)
	if err != nil {
		return fmt.Errorf("refresh capability state evidence: %w", err)
	}
	if currentProduction.Decision != decision.Allow {
		return fmt.Errorf(
			"capability state revalidation is not ALLOW: %s",
			currentProduction.Decision,
		)
	}
	currentState, err := capabilityStateBindingFromProduction(target, currentProduction)
	if err != nil {
		return err
	}

	return egeproto.ValidateCapabilityFence(*claims, currentAuthority, currentState)
}
