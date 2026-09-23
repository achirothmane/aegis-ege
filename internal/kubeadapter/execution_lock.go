package kubeadapter

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

var (
	ErrExecutionLockHeld = errors.New("execution lock is held by another executor")
	ErrExecutionLockLost = errors.New("execution lock ownership was lost")
)

const (
	ReasonExecutionLockUnavailable decision.ReasonCode = "EXECUTION_LOCK_UNAVAILABLE"
	ReasonExecutionLockHeld        decision.ReasonCode = "EXECUTION_LOCK_HELD"
	ReasonExecutionLockLost        decision.ReasonCode = "EXECUTION_LOCK_LOST"
)

type ExecutionLease struct {
	Namespace string
	Name      string
	Target    string
	Holder    string
}

type ExecutionLockManager interface {
	AcquireExecutionLock(
		ctx context.Context,
		namespace string,
		target string,
		holder string,
		duration time.Duration,
	) (ExecutionLease, error)
	RenewExecutionLock(
		ctx context.Context,
		lease ExecutionLease,
		duration time.Duration,
	) error
	ReleaseExecutionLock(
		ctx context.Context,
		lease ExecutionLease,
	) error
}

type executionLeaseGuard struct {
	manager ExecutionLockManager
	lease   ExecutionLease
	duration time.Duration

	mu      sync.Mutex
	lostErr error
	cancel  context.CancelFunc
	done    chan struct{}
}

func acquireExecutionLeaseGuard(
	ctx context.Context,
	manager ExecutionLockManager,
	namespace string,
	target string,
	duration time.Duration,
) (*executionLeaseGuard, error) {
	if manager == nil {
		return nil, fmt.Errorf("%w: lock manager is not configured", ErrExecutionLockLost)
	}

	holder, err := newExecutionHolderIdentity()
	if err != nil {
		return nil, fmt.Errorf("create execution lock holder: %w", err)
	}

	lease, err := manager.AcquireExecutionLock(ctx, namespace, target, holder, duration)
	if err != nil {
		return nil, err
	}

	renewCtx, cancel := context.WithCancel(ctx)
	guard := &executionLeaseGuard{
		manager:  manager,
		lease:    lease,
		duration: duration,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go guard.renewLoop(renewCtx)
	return guard, nil
}

func (g *executionLeaseGuard) renewLoop(ctx context.Context) {
	defer close(g.done)

	interval := g.duration / 3
	if interval < time.Second {
		interval = time.Second
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := g.manager.RenewExecutionLock(ctx, g.lease, g.duration); err != nil {
				g.mu.Lock()
				if g.lostErr == nil {
					g.lostErr = err
				}
				g.mu.Unlock()
				return
			}
		}
	}
}

func (g *executionLeaseGuard) EnsureHeld(ctx context.Context) error {
	g.mu.Lock()
	if g.lostErr != nil {
		err := g.lostErr
		g.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrExecutionLockLost, err)
	}
	g.mu.Unlock()

	if err := g.manager.RenewExecutionLock(ctx, g.lease, g.duration); err != nil {
		g.mu.Lock()
		if g.lostErr == nil {
			g.lostErr = err
		}
		g.mu.Unlock()
		return fmt.Errorf("%w: %v", ErrExecutionLockLost, err)
	}
	return nil
}

func (g *executionLeaseGuard) Close(ctx context.Context) error {
	g.cancel()
	<-g.done

	g.mu.Lock()
	lostErr := g.lostErr
	g.mu.Unlock()
	if lostErr != nil {
		return fmt.Errorf("%w: %v", ErrExecutionLockLost, lostErr)
	}
	return g.manager.ReleaseExecutionLock(ctx, g.lease)
}

func newExecutionHolderIdentity() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "state-latch-" + hex.EncodeToString(raw[:]), nil
}

func executionLockNamespace(policy NodeDrainPolicy) string {
	if policy.ExecutionLockNamespace != "" {
		return policy.ExecutionLockNamespace
	}
	return "kube-system"
}

func executionLockDuration(policy NodeDrainPolicy) time.Duration {
	if policy.ExecutionLockDuration > 0 {
		return policy.ExecutionLockDuration
	}
	return 30 * time.Second
}
