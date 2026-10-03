//go:build linux

package kernelfabric

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

type TaintEvidenceReader struct {
	eventsMap     *ebpf.Map
	accountingMap *ebpf.Map
	stream        *ringbuf.Reader
	tracker       *TaintContinuityTracker
}

func OpenPinnedTaintEvidenceReader(bpffsRoot string) (*TaintEvidenceReader, error) {
	root := filepath.Clean(strings.TrimSpace(bpffsRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	mapDir := filepath.Join(root, "maps")
	eventsMap, err := openExactTaintMap(
		filepath.Join(mapDir, "aegis_tevents"),
		ebpf.RingBuf,
		0,
		0,
		1<<20,
	)
	if err != nil {
		return nil, err
	}
	accountingMap, err := openExactTaintMap(
		filepath.Join(mapDir, "aegis_tacct"),
		ebpf.Array,
		4,
		TaintAccountingSize,
		1,
	)
	if err != nil {
		eventsMap.Close()
		return nil, err
	}
	stream, err := ringbuf.NewReader(eventsMap)
	if err != nil {
		accountingMap.Close()
		eventsMap.Close()
		return nil, fmt.Errorf("open taint evidence ring buffer reader: %w", err)
	}
	reader := &TaintEvidenceReader{
		eventsMap:     eventsMap,
		accountingMap: accountingMap,
		stream:        stream,
	}
	initial, err := reader.Accounting()
	if err != nil {
		reader.Close()
		return nil, err
	}
	tracker, err := NewTaintContinuityTracker(initial)
	if err != nil {
		reader.Close()
		return nil, err
	}
	reader.tracker = tracker
	return reader, nil
}

func (r *TaintEvidenceReader) ReadContext(
	ctx context.Context,
) (TaintEvent, ContinuityAssessment, error) {
	if r == nil || r.stream == nil || r.tracker == nil {
		return TaintEvent{}, ContinuityAssessment{}, errors.New("taint evidence reader is not initialized")
	}
	for {
		if err := ctx.Err(); err != nil {
			return TaintEvent{}, ContinuityAssessment{}, err
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
			return TaintEvent{}, ContinuityAssessment{}, fmt.Errorf("read taint evidence ring buffer: %w", err)
		}
		event, err := DecodeTaintEvent(record.RawSample)
		if err != nil {
			return TaintEvent{}, ContinuityAssessment{}, err
		}
		if err := r.tracker.Observe(event); err != nil {
			return TaintEvent{}, ContinuityAssessment{}, err
		}
		accounting, err := r.Accounting()
		if err != nil {
			return TaintEvent{}, ContinuityAssessment{}, err
		}
		assessment, err := r.tracker.Assess(accounting)
		if err != nil {
			return TaintEvent{}, ContinuityAssessment{}, err
		}
		return event, assessment, nil
	}
}

func (r *TaintEvidenceReader) Accounting() (TaintAccounting, error) {
	if r == nil || r.accountingMap == nil {
		return TaintAccounting{}, errors.New("taint evidence accounting map is unavailable")
	}
	var key uint32
	var accounting TaintAccounting
	if err := r.accountingMap.Lookup(&key, &accounting); err != nil {
		return TaintAccounting{}, fmt.Errorf("read taint evidence accounting: %w", err)
	}
	if accounting.Emitted+accounting.Lost > accounting.Sequence {
		return TaintAccounting{}, fmt.Errorf(
			"taint evidence accounting is inconsistent: emitted=%d lost=%d sequence=%d",
			accounting.Emitted,
			accounting.Lost,
			accounting.Sequence,
		)
	}
	return accounting, nil
}

func (r *TaintEvidenceReader) Checkpoint() error {
	if r == nil || r.tracker == nil {
		return errors.New("taint evidence reader is not initialized")
	}
	accounting, err := r.Accounting()
	if err != nil {
		return err
	}
	return r.tracker.Checkpoint(accounting)
}

func (r *TaintEvidenceReader) Close() error {
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
