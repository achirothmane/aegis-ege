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
	switch {
	case packet.Context.ExecutionBinding == nil && claims.ExecutionBinding == nil:
	case packet.Context.ExecutionBinding == nil || claims.ExecutionBinding == nil:
		return egeproto.PermitClaims{}, errors.New("execution binding presence mismatch")
	default:
		expected := packet.Context.ExecutionBinding
		actual := claims.ExecutionBinding
		if expected.DestinationID != actual.DestinationID ||
			expected.AccountID != actual.AccountID ||
			expected.Endpoint != actual.Endpoint ||
			expected.AdapterProfile != actual.AdapterProfile ||
			expected.ExpectedResourceVersion != actual.ExpectedResourceVersion {
			return egeproto.PermitClaims{}, errors.New("execution binding mismatch")
		}
		if claims.ResourceVersion != actual.ExpectedResourceVersion {
			return egeproto.PermitClaims{}, errors.New("execution binding resource version mismatch")
		}
	}

	claims.EvidencePacketDigest = packet.Integrity.Digest
	return claims, nil
}


// VerifyPermitPacketBinding proves that an already-signed permit still refers
// to the exact Evidence Packet and consequential action it claims to authorize.
func VerifyPermitPacketBinding(packet Packet, claims egeproto.PermitClaims) error {
	if claims.EvidencePacketDigest == "" {
		return errors.New("execution permit is not bound to an evidence packet")
	}
	if claims.EvidencePacketDigest != packet.Integrity.Digest {
		return errors.New("execution permit evidence packet digest mismatch")
	}
	bound, err := BindPermitClaims(packet, claims)
	if err != nil {
		return err
	}
	if bound.EvidencePacketDigest != claims.EvidencePacketDigest {
		return errors.New("execution permit evidence packet binding changed")
	}
	return nil
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
