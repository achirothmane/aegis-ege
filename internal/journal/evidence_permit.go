package journal

import (
	"context"
	"errors"
	"fmt"
	"time"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

// AuthorizationEventFromEvidenceBoundPermit verifies a signed execution permit
// and projects its EEP binding into a tamper-evident journal event.
func AuthorizationEventFromEvidenceBoundPermit(
	ctx context.Context,
	verifier egeproto.SignatureVerifier,
	permit egeproto.Permit,
	occurredAt time.Time,
) (Event, error) {
	if err := egeproto.VerifyPermit(ctx, verifier, permit); err != nil {
		return Event{}, fmt.Errorf("verify execution permit: %w", err)
	}
	if permit.Claims.EvidencePacketDigest == "" {
		return Event{}, errors.New("execution permit is not bound to an evidence packet")
	}

	payloadDigest, err := DigestPayload(permit)
	if err != nil {
		return Event{}, fmt.Errorf("digest execution permit: %w", err)
	}

	return Event{
		Type:                 EventAuthorization,
		ActionID:             permit.Claims.IntentID,
		Target:               permit.Claims.Target.Type + "/" + permit.Claims.Target.Name,
		EvidenceDigest:       permit.Claims.EvidenceDigest,
		EvidencePacketDigest: permit.Claims.EvidencePacketDigest,
		PlanDigest:           permit.Claims.PlanDigest,
		PayloadDigest:        payloadDigest,
		OccurredAt:           occurredAt,
	}, nil
}
