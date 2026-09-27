package server

import (
	"context"
	"fmt"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func (s *Server) issueCapabilityClaim(
	ctx context.Context,
	adapter egeExecutionAdapter,
	intentID string,
	target egeTargetDTO,
	claims egeproto.PermitClaims,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	auth, err := adapter.AuthorizationFromPermit(intentID, target, claims)
	if err != nil {
		return fmt.Errorf("derive execution capability authorization: %w", err)
	}
	if err := s.capabilityClaims.Issue(ctx, auth); err != nil {
		return err
	}
	return nil
}

func (s *Server) abortCapabilityClaim(
	auth decision.Authorization,
	reason string,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
	defer cancel()
	return s.capabilityClaims.Abort(ctx, auth, reason)
}

func (s *Server) consumeCapabilityClaim(
	auth decision.Authorization,
	outcome string,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
	defer cancel()
	return s.capabilityClaims.Consume(ctx, auth, outcome)
}

func (s *Server) capabilityClaimState(
	auth decision.Authorization,
) (ExecutionClaimState, error) {
	if s.capabilityClaims == nil {
		return "", nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.RequestTimeout)
	defer cancel()
	record, err := s.capabilityClaims.State(ctx, auth)
	if err != nil {
		return "", err
	}
	return record.State, nil
}
