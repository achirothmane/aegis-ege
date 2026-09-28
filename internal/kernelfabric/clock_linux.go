//go:build linux

package kernelfabric

import (
	"fmt"
	"time"

	"golang.org/x/sys/unix"
)

func CaptureClockSnapshot(wallNow time.Time, bootIDPath string) (ClockSnapshot, error) {
	if wallNow.IsZero() {
		wallNow = time.Now().UTC()
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return ClockSnapshot{}, fmt.Errorf("read CLOCK_MONOTONIC: %w", err)
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return ClockSnapshot{}, fmt.Errorf("invalid monotonic clock value")
	}
	bootHash, err := ReadBootIDHash(bootIDPath)
	if err != nil {
		return ClockSnapshot{}, err
	}
	return ClockSnapshot{
		WallNow:    wallNow.UTC(),
		MonoNowNS:  uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec),
		BootIDHash: bootHash,
	}, nil
}


func CaptureBootClockSnapshot(wallNow time.Time, bootIDPath string) (ClockSnapshot, error) {
	if wallNow.IsZero() {
		wallNow = time.Now().UTC()
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return ClockSnapshot{}, fmt.Errorf("read CLOCK_BOOTTIME: %w", err)
	}
	if ts.Sec < 0 || ts.Nsec < 0 {
		return ClockSnapshot{}, fmt.Errorf("invalid boot clock value")
	}
	bootHash, err := ReadBootIDHash(bootIDPath)
	if err != nil {
		return ClockSnapshot{}, err
	}
	return ClockSnapshot{
		WallNow:    wallNow.UTC(),
		MonoNowNS:  uint64(ts.Sec)*1_000_000_000 + uint64(ts.Nsec),
		BootIDHash: bootHash,
	}, nil
}
