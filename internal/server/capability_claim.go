package server

import (
	"context"
	"errors"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

const capabilityClaimFinalizationTimeout = 5 * time.Second

func (s *Server) issueCapabilityClaim(
	ctx context.Context,
	adapter egeAdapter,
	intentID string,
	target egeTargetDTO,
	claims egeproto.PermitClaims,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	auth, err := adapter.AuthorizationFromPermit(intentID, target, claims)
	if err != nil {
		return err
	}
	return s.capabilityClaims.Issue(ctx, auth)
}

func (s *Server) consumeCapabilityClaim(
	auth decision.Authorization,
	outcome string,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityClaimFinalizationTimeout)
	defer cancel()
	return s.capabilityClaims.Consume(ctx, auth, outcome)
}

func (s *Server) abortCapabilityClaim(
	auth decision.Authorization,
	reason string,
) error {
	if s.capabilityClaims == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityClaimFinalizationTimeout)
	defer cancel()
	return s.capabilityClaims.Abort(ctx, auth, reason)
}

func (s *Server) capabilityClaimState(
	auth decision.Authorization,
) (ExecutionClaimState, error) {
	if s.capabilityClaims == nil {
		return "", errors.New("capability claim lifecycle is disabled")
	}
	ctx, cancel := context.WithTimeout(context.Background(), capabilityClaimFinalizationTimeout)
	defer cancel()
	record, err := s.capabilityClaims.State(ctx, auth)
	if err != nil {
		return "", err
	}
	return record.State, nil
}
