package evidencepipeline

import (
	"context"
	"errors"
	"fmt"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

// BindPermitClaims verifies that an Evidence Packet describes the exact
// consequential action represented by the permit claims, then binds the
// packet's integrity digest into those claims.
func BindPermitClaims(packet Packet, claims egeproto.PermitClaims) (egeproto.PermitClaims, error) {
	if err := Verify(packet); err != nil {
		return egeproto.PermitClaims{}, fmt.Errorf("verify evidence packet: %w", err)
	}
	if packet.IntentID == "" || packet.IntentID != claims.IntentID {
		return egeproto.PermitClaims{}, errors.New("evidence packet intent mismatch")
	}
	if packet.Action.Kind != claims.Kind {
		return egeproto.PermitClaims{}, errors.New("evidence packet kind mismatch")
	}
	if packet.Action.Operation != claims.Action {
		return egeproto.PermitClaims{}, errors.New("evidence packet action mismatch")
	}
	expectedTarget := claims.Target.Type + "/" + claims.Target.Name
	if packet.Action.Target != expectedTarget {
		return egeproto.PermitClaims{}, errors.New("evidence packet target mismatch")
	}
	if !packet.Action.SideEffect {
		return egeproto.PermitClaims{}, errors.New("evidence packet is not bound to a side-effecting action")
	}
	if packet.Context.AuthorityRef == "" {
		return egeproto.PermitClaims{}, errors.New("evidence packet authority_ref is required")
	}
	if packet.Context.PolicyRef == "" {
		return egeproto.PermitClaims{}, errors.New("evidence packet policy_ref is required")
	}
	if packet.Context.RedactionProfileRef == "" {
		return egeproto.PermitClaims{}, errors.New("evidence packet redaction_profile_ref is required")
	}
	if packet.Context.ConsequenceClass == "" {
		return egeproto.PermitClaims{}, errors.New("evidence packet consequence_class is required")
	}

	claims.EvidencePacketDigest = packet.Integrity.Digest
	return claims, nil
}

// SignEvidenceBoundPermit refuses to mint a permit unless the supplied packet
// verifies and is bound to the same intent/action/target.
func SignEvidenceBoundPermit(
	ctx context.Context,
	authority egeproto.PermitAuthority,
	packet Packet,
	claims egeproto.PermitClaims,
) (egeproto.Permit, error) {
	bound, err := BindPermitClaims(packet, claims)
	if err != nil {
		return egeproto.Permit{}, err
	}
	return egeproto.SignPermit(ctx, authority, bound)
}
