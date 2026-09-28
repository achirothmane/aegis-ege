package kernelfabric

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func MarshalScopeKey(key ScopeKey) ([]byte, error) {
	if err := validateScopeKey(key); err != nil {
		return nil, err
	}
	return marshalFixed(key, ScopeKeySize)
}

func MarshalScopeFenceKey(key ScopeFenceKey) ([]byte, error) {
	if key.CgroupID == 0 || key.ActionClass == 0 {
		return nil, ErrInvalidScope
	}
	return marshalFixed(key, ScopeFenceKeySize)
}

func MarshalScopeFenceState(state ScopeFenceState) ([]byte, error) {
	if state.AuthorityTerm == 0 || state.DecisionEpoch == 0 {
		return nil, fmt.Errorf("%w: invalid scope fence state", ErrInvalidCapsule)
	}
	return marshalFixed(state, ScopeFenceStateSize)
}

func DecodeScopeFenceState(payload []byte) (ScopeFenceState, error) {
	if len(payload) != ScopeFenceStateSize {
		return ScopeFenceState{}, fmt.Errorf(
			"scope fence state size mismatch: got %d want %d",
			len(payload),
			ScopeFenceStateSize,
		)
	}
	var state ScopeFenceState
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &state); err != nil {
		return ScopeFenceState{}, fmt.Errorf("decode scope fence state: %w", err)
	}
	if state.AuthorityTerm == 0 || state.DecisionEpoch == 0 {
		return ScopeFenceState{}, fmt.Errorf("%w: invalid scope fence state", ErrInvalidCapsule)
	}
	if state.BootIDHash == [32]byte{} {
		return ScopeFenceState{}, fmt.Errorf("%w: scope fence boot id hash is required", ErrInvalidCapsule)
	}
	return state, nil
}

func MarshalDecisionCapsule(capsule DecisionCapsule) ([]byte, error) {
	if err := ValidateCapsule(capsule); err != nil {
		return nil, err
	}
	return marshalFixed(capsule, DecisionCapsuleSize)
}

func MarshalEvidenceEvent(event EvidenceEvent) ([]byte, error) {
	if event.ABIVersion != EvidenceEventVersion {
		return nil, fmt.Errorf("unsupported evidence event ABI version %d", event.ABIVersion)
	}
	if event.EventType != EvidenceEventEnforcement {
		return nil, fmt.Errorf("unsupported evidence event type %d", event.EventType)
	}
	if event.Sequence == 0 {
		return nil, fmt.Errorf("evidence event sequence must be non-zero")
	}
	return marshalFixed(event, EvidenceEventSize)
}

func DecodeEvidenceEvent(payload []byte) (EvidenceEvent, error) {
	if len(payload) != EvidenceEventSize {
		return EvidenceEvent{}, fmt.Errorf("kernel evidence event size mismatch: got %d want %d", len(payload), EvidenceEventSize)
	}
	var event EvidenceEvent
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &event); err != nil {
		return EvidenceEvent{}, fmt.Errorf("decode kernel evidence event: %w", err)
	}
	if event.ABIVersion != EvidenceEventVersion {
		return EvidenceEvent{}, fmt.Errorf("unsupported evidence event ABI version %d", event.ABIVersion)
	}
	if event.EventType != EvidenceEventEnforcement {
		return EvidenceEvent{}, fmt.Errorf("unsupported evidence event type %d", event.EventType)
	}
	if event.Sequence == 0 {
		return EvidenceEvent{}, fmt.Errorf("kernel evidence event has zero sequence")
	}
	return event, nil
}

func MarshalEvidenceAccounting(accounting EvidenceAccounting) ([]byte, error) {
	return marshalFixed(accounting, EvidenceAccountingSize)
}

func DecodeEvidenceAccounting(payload []byte) (EvidenceAccounting, error) {
	if len(payload) != EvidenceAccountingSize {
		return EvidenceAccounting{}, fmt.Errorf("kernel evidence accounting size mismatch: got %d want %d", len(payload), EvidenceAccountingSize)
	}
	var accounting EvidenceAccounting
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &accounting); err != nil {
		return EvidenceAccounting{}, fmt.Errorf("decode kernel evidence accounting: %w", err)
	}
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return EvidenceAccounting{}, fmt.Errorf(
			"kernel evidence accounting is inconsistent: emitted=%d lost=%d sequence=%d",
			accounting.Emitted,
			accounting.Lost,
			accounting.Sequence,
		)
	}
	return accounting, nil
}

func marshalFixed(value any, want int) ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, value); err != nil {
		return nil, err
	}
	if buf.Len() != want {
		return nil, fmt.Errorf("kernel ABI size mismatch: got %d want %d", buf.Len(), want)
	}
	return buf.Bytes(), nil
}
