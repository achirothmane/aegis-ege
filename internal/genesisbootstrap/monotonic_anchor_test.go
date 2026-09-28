package genesisbootstrap

import (
	"context"
	"errors"
	"sync"
)

type memoryMonotonicAnchor struct {
	mu          sync.Mutex
	id          string
	value       uint64
	advanceErr  error
	readErr     error
	identityErr error
}

func (a *memoryMonotonicAnchor) Identity(context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.identityErr != nil {
		return "", a.identityErr
	}
	if a.id == "" {
		return "memory-anchor:test", nil
	}
	return a.id, nil
}

func (a *memoryMonotonicAnchor) Read(context.Context) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.readErr != nil {
		return 0, a.readErr
	}
	return a.value, nil
}

func (a *memoryMonotonicAnchor) Advance(_ context.Context, expected uint64) (uint64, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.advanceErr != nil {
		return 0, a.advanceErr
	}
	if a.value != expected {
		return 0, errors.New("memory monotonic anchor expected-current mismatch")
	}
	a.value++
	return a.value, nil
}
