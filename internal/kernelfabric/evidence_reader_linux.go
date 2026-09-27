//go:build linux

package kernelfabric

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

const (
	DefaultEvidenceEventsMapPath     = "/sys/fs/bpf/aegis-ege/maps/aegis_evidence_events"
	DefaultEvidenceAccountingMapPath = "/sys/fs/bpf/aegis-ege/maps/aegis_evidence_accounting"
)

type EvidenceReader struct {
	eventsMap     *ebpf.Map
	accountingMap *ebpf.Map
	stream        *ringbuf.Reader
	tracker       *ContinuityTracker
}

func OpenPinnedEvidenceReader(
	eventsMapPath string,
	accountingMapPath string,
) (*EvidenceReader, error) {
	eventsMapPath = strings.TrimSpace(eventsMapPath)
	if eventsMapPath == "" {
		eventsMapPath = DefaultEvidenceEventsMapPath
	}
	accountingMapPath = strings.TrimSpace(accountingMapPath)
	if accountingMapPath == "" {
		accountingMapPath = DefaultEvidenceAccountingMapPath
	}

	eventsMap, err := ebpf.LoadPinnedMap(eventsMapPath, nil)
	if err != nil {
		return nil, fmt.Errorf("open pinned kernel evidence ring buffer: %w", err)
	}
	accountingMap, err := ebpf.LoadPinnedMap(accountingMapPath, nil)
	if err != nil {
		eventsMap.Close()
		return nil, fmt.Errorf("open pinned kernel evidence accounting map: %w", err)
	}
	stream, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		accountingMap.Close()
		eventsMap.Close()
		return nil, fmt.Errorf("open kernel evidence ring buffer reader: %w", err)
	}

	reader := &EvidenceReader{
		eventsMap:     eventsMap,
		accountingMap: accountingMap,
		stream:        stream,
	}
	initial, err := reader.Accounting()
	if err != nil {
		reader.Close()
		return nil, err
	}
	tracker, err := NewContinuityTracker(initial)
	if err != nil {
		reader.Close()
		return nil, err
	}
	reader.tracker = tracker
	return reader, nil
}

func (r *EvidenceReader) ReadContext(
	ctx context.Context,
) (EvidenceEvent, ContinuityAssessment, error) {
	if r == nil || r.stream == nil || r.tracker == nil {
		return EvidenceEvent{}, ContinuityAssessment{}, errors.New("kernel evidence reader is not initialized")
	}

	for {
		if err := ctx.Err(); err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, err
		}

		deadline := time.Now().Add(250 * time.Millisecond)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		r.stream.SetDeadline(deadline)

		record, err := r.stream.Read()
		if errors.Is(err, os.ErrDeadlineExceeded) {
			continue
		}
		if err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, fmt.Errorf("read kernel evidence ring buffer: %w", err)
		}

		event, err := DecodeEvidenceEvent(record.RawSample)
		if err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, err
		}
		if err := r.tracker.Observe(event); err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, err
		}
		accounting, err := r.Accounting()
		if err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, err
		}
		assessment, err := r.tracker.Assess(accounting)
		if err != nil {
			return EvidenceEvent{}, ContinuityAssessment{}, err
		}
		return event, assessment, nil
	}
}

func (r *EvidenceReader) Accounting() (EvidenceAccounting, error) {
	if r == nil || r.accountingMap == nil {
		return EvidenceAccounting{}, errors.New("kernel evidence accounting map is unavailable")
	}
	var key uint32
	var accounting EvidenceAccounting
	if err := r.accountingMap.Lookup(&key, &accounting); err != nil {
		return EvidenceAccounting{}, fmt.Errorf("read kernel evidence accounting: %w", err)
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

func (r *EvidenceReader) Assessment() (ContinuityAssessment, error) {
	if r == nil || r.tracker == nil {
		return ContinuityAssessment{}, errors.New("kernel evidence reader is not initialized")
	}
	accounting, err := r.Accounting()
	if err != nil {
		return ContinuityAssessment{}, err
	}
	return r.tracker.Assess(accounting)
}

func (r *EvidenceReader) Checkpoint() error {
	if r == nil || r.tracker == nil {
		return errors.New("kernel evidence reader is not initialized")
	}
	accounting, err := r.Accounting()
	if err != nil {
		return err
	}
	return r.tracker.Checkpoint(accounting)
}

func (r *EvidenceReader) Close() error {
	if r == nil {
		return nil
	}
	var errs []error
	if r.stream != nil {
		if err := r.stream.Close(); err != nil {
			errs = append(errs, err)
		}
		r.stream = nil
	}
	if r.accountingMap != nil {
		if err := r.accountingMap.Close(); err != nil {
			errs = append(errs, err)
		}
		r.accountingMap = nil
	}
	if r.eventsMap != nil {
		if err := r.eventsMap.Close(); err != nil {
			errs = append(errs, err)
		}
		r.eventsMap = nil
	}
	return errors.Join(errs...)
}
