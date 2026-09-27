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

func MarshalDecisionCapsule(capsule DecisionCapsule) ([]byte, error) {
	if err := ValidateCapsule(capsule); err != nil {
		return nil, err
	}
	return marshalFixed(capsule, DecisionCapsuleSize)
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
