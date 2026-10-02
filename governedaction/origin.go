package governedaction

import (
	"errors"
	"fmt"
	"strings"
)

// Execution-origin checks are an experimental hardening extension around the
// frozen governed-action v1 relations. They do not change the K01-K05 oracle.
//
// The purpose is narrow: an already-admitted action must not silently inherit
// capabilities from a different repository, plugin, MCP server, tool bundle,
// user-supplied hook, or other execution origin at the effect boundary.
var (
	ErrMissingOrigin            = errors.New("execution origin binding is incomplete")
	ErrOriginChanged            = errors.New("execution origin binding changed")
	ErrOriginCapabilityExpanded = errors.New("execution origin capability expanded")
	ErrUnknownOriginCapability  = errors.New("execution origin capability is unknown")
)

// OriginCapability describes authority-relevant behavior that an origin may
// contribute to an execution runtime. These bits do not grant external action
// authority by themselves; they only bound what the admitted origin is allowed
// to contribute.
//
// Keep this set intentionally small. Domain-specific tool/action semantics stay
// in the trusted adapter profile.
type OriginCapability uint32

const (
	OriginSupplyInstructions OriginCapability = 1 << iota
	OriginRegisterTools
	OriginRegisterConnectors
	OriginUseCredentialHandles
	OriginNetworkEgress
)

const knownOriginCapabilities = OriginSupplyInstructions |
	OriginRegisterTools |
	OriginRegisterConnectors |
	OriginUseCredentialHandles |
	OriginNetworkEgress

// OriginBinding is the minimum immutable provenance relation checked at an
// effect boundary. The adapter is responsible for deriving these values from a
// trusted provenance mechanism rather than caller-provided labels.
//
// SourceDigest should bind the executable/instruction-bearing artifact whose
// change could alter behavior. TrustDomain identifies the authority that vouches
// for that provenance. TrustEpoch makes revocation or trust-root rotation
// invalidate older admissions without pretending that a digest is authority.
type OriginBinding struct {
	OriginID     string
	OriginType   string
	SourceDigest string
	TrustDomain  string
	TrustEpoch   string
	Capabilities OriginCapability
}

type OriginField string

const (
	OriginIDField     OriginField = "origin_id"
	OriginTypeField   OriginField = "origin_type"
	SourceDigestField OriginField = "source_digest"
	TrustDomainField  OriginField = "trust_domain"
	TrustEpochField   OriginField = "trust_epoch"
	CapabilitiesField OriginField = "capabilities"
)

type OriginError struct {
	Field OriginField
	Cause error
}

func (e *OriginError) Error() string { return fmt.Sprintf("%s: %s", e.Field, e.Cause) }
func (e *OriginError) Unwrap() error { return e.Cause }

// CheckOrigin enforces NO_SILENT_CAPABILITY_EXPANSION.
//
// Identity/provenance fields must match exactly. The current runtime may use a
// strict subset of the capabilities admitted for the origin, but it may not add
// a capability without a fresh admission. Unknown capability bits fail closed.
//
// This function does not decide whether an origin is trustworthy, verify a
// signature, scan code, issue authority, broker credentials, or prove complete
// mediation. Those are profile/enforcement responsibilities.
func CheckOrigin(admitted, current OriginBinding) error {
	fields := []struct {
		name              OriginField
		admitted, current string
	}{
		{OriginIDField, admitted.OriginID, current.OriginID},
		{OriginTypeField, admitted.OriginType, current.OriginType},
		{SourceDigestField, admitted.SourceDigest, current.SourceDigest},
		{TrustDomainField, admitted.TrustDomain, current.TrustDomain},
		{TrustEpochField, admitted.TrustEpoch, current.TrustEpoch},
	}

	for _, field := range fields {
		if strings.TrimSpace(field.admitted) == "" || strings.TrimSpace(field.current) == "" {
			return &OriginError{Field: field.name, Cause: ErrMissingOrigin}
		}
		if field.admitted != field.current {
			return &OriginError{Field: field.name, Cause: ErrOriginChanged}
		}
	}

	if admitted.Capabilities&^knownOriginCapabilities != 0 ||
		current.Capabilities&^knownOriginCapabilities != 0 {
		return &OriginError{Field: CapabilitiesField, Cause: ErrUnknownOriginCapability}
	}

	if current.Capabilities&^admitted.Capabilities != 0 {
		return &OriginError{Field: CapabilitiesField, Cause: ErrOriginCapabilityExpanded}
	}

	return nil
}
