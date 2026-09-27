package kernelfabric

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

const DefaultBootIDPath = "/proc/sys/kernel/random/boot_id"

type ExternalLease struct {
	IssuedAt    time.Time
	NotAfter    time.Time
	MaxLifetime time.Duration
}

type ClockSnapshot struct {
	WallNow    time.Time
	MonoNowNS  uint64
	BootIDHash [32]byte
}

type LocalLease struct {
	InstalledAtMonoNS uint64
	DeadlineMonoNS    uint64
	BootIDHash        [32]byte
}

func BindExternalLease(lease ExternalLease, clock ClockSnapshot) (LocalLease, error) {
	if clock.WallNow.IsZero() {
		return LocalLease{}, fmt.Errorf("%w: wall clock snapshot is required", ErrLeaseInvalid)
	}
	if lease.NotAfter.IsZero() {
		return LocalLease{}, fmt.Errorf("%w: not_after is required", ErrLeaseInvalid)
	}
	if lease.MaxLifetime <= 0 {
		return LocalLease{}, fmt.Errorf("%w: max lifetime must be positive", ErrLeaseInvalid)
	}
	if !lease.IssuedAt.IsZero() && lease.IssuedAt.After(lease.NotAfter) {
		return LocalLease{}, fmt.Errorf("%w: issued_at is after not_after", ErrLeaseInvalid)
	}

	remaining := lease.NotAfter.Sub(clock.WallNow)
	if remaining <= 0 {
		return LocalLease{}, ErrLeaseExpired
	}
	if remaining > lease.MaxLifetime {
		remaining = lease.MaxLifetime
	}

	ns := remaining.Nanoseconds()
	if ns <= 0 {
		return LocalLease{}, ErrLeaseExpired
	}
	if uint64(ns) > math.MaxUint64-clock.MonoNowNS {
		return LocalLease{}, fmt.Errorf("%w: monotonic deadline overflow", ErrLeaseInvalid)
	}

	return LocalLease{
		InstalledAtMonoNS: clock.MonoNowNS,
		DeadlineMonoNS:    clock.MonoNowNS + uint64(ns),
		BootIDHash:        clock.BootIDHash,
	}, nil
}

func ReadBootIDHash(path string) ([32]byte, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		path = DefaultBootIDPath
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(payload))
	if bootID == "" {
		return [32]byte{}, errors.New("boot id is empty")
	}
	return sha256.Sum256([]byte(bootID)), nil
}
