package kernelfabric

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

func MarshalTaintFileKey(key TaintFileKey) ([]byte, error) {
	if key.Device == 0 || key.Inode == 0 {
		return nil, fmt.Errorf("%w: taint file identity is incomplete", ErrTaintABIInvalid)
	}
	return marshalFixed(key, TaintFileKeySize)
}

func DecodeTaintEvent(payload []byte) (TaintEvent, error) {
	if len(payload) != TaintEventSize {
		return TaintEvent{}, fmt.Errorf(
			"kernel taint event size mismatch: got %d want %d",
			len(payload),
			TaintEventSize,
		)
	}
	var event TaintEvent
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &event); err != nil {
		return TaintEvent{}, fmt.Errorf("decode kernel taint event: %w", err)
	}
	if event.ABIVersion != TaintABIVersion {
		return TaintEvent{}, fmt.Errorf("%w: unsupported taint ABI version %d", ErrTaintABIInvalid, event.ABIVersion)
	}
	if event.Sequence == 0 || event.CgroupID == 0 || event.TGID == 0 {
		return TaintEvent{}, fmt.Errorf("%w: taint event identity is incomplete", ErrTaintABIInvalid)
	}
	if event.EventType < TaintEventSourceRead || event.EventType > TaintEventEgressDeny {
		return TaintEvent{}, fmt.Errorf("%w: unsupported event type %d", ErrTaintABIInvalid, event.EventType)
	}
	if event.Operation < TaintOperationRead || event.Operation > TaintOperationConnect {
		return TaintEvent{}, fmt.Errorf("%w: unsupported operation %d", ErrTaintABIInvalid, event.Operation)
	}
	if event.Reserved != 0 {
		return TaintEvent{}, fmt.Errorf("%w: reserved field is non-zero", ErrTaintABIInvalid)
	}
	return event, nil
}

func MarshalTaintAccounting(accounting TaintAccounting) ([]byte, error) {
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return nil, fmt.Errorf("%w: taint accounting is inconsistent", ErrTaintABIInvalid)
	}
	return marshalFixed(accounting, TaintAccountingSize)
}

func DecodeTaintAccounting(payload []byte) (TaintAccounting, error) {
	if len(payload) != TaintAccountingSize {
		return TaintAccounting{}, fmt.Errorf(
			"kernel taint accounting size mismatch: got %d want %d",
			len(payload),
			TaintAccountingSize,
		)
	}
	var accounting TaintAccounting
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &accounting); err != nil {
		return TaintAccounting{}, fmt.Errorf("decode kernel taint accounting: %w", err)
	}
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return TaintAccounting{}, fmt.Errorf(
			"%w: emitted=%d lost=%d sequence=%d",
			ErrTaintABIInvalid,
			accounting.Emitted,
			accounting.Lost,
			accounting.Sequence,
		)
	}
	return accounting, nil
}
