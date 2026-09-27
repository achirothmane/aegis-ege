//go:build linux

package kernelfabric

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	DefaultKernelLockdownPath = "/sys/kernel/security/lockdown"
	bpfFSMagic                = 0xcafe4a11
)

func CaptureBootstrapHostSnapshot(
	bpffsRoot string,
	bootIDPath string,
	lockdownPath string,
) (BootstrapHostSnapshot, error) {
	bpffsRoot = filepath.Clean(strings.TrimSpace(bpffsRoot))
	if bpffsRoot == "." || bpffsRoot == "" {
		return BootstrapHostSnapshot{}, errors.New("bpffs root is required")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(bpffsRoot, &fs); err != nil {
		return BootstrapHostSnapshot{}, fmt.Errorf("stat bpffs root: %w", err)
	}
	if uint64(fs.Type) != uint64(bpfFSMagic) {
		return BootstrapHostSnapshot{}, fmt.Errorf("%s is not a BPF filesystem", bpffsRoot)
	}

	bootHash, err := ReadBootIDHash(bootIDPath)
	if err != nil {
		return BootstrapHostSnapshot{}, err
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return BootstrapHostSnapshot{}, fmt.Errorf("read kernel release: %w", err)
	}

	if strings.TrimSpace(lockdownPath) == "" {
		lockdownPath = DefaultKernelLockdownPath
	}
	lockdownMode := "unavailable"
	if payload, err := os.ReadFile(lockdownPath); err == nil {
		lockdownMode = normalizeKernelLockdown(string(payload))
	}

	return BootstrapHostSnapshot{
		BootIDHash:    "sha256:" + hex.EncodeToString(bootHash[:]),
		KernelRelease: utsReleaseString(uts.Release),
		LockdownMode:  lockdownMode,
		BPFFSRoot:     bpffsRoot,
	}, nil
}

func normalizeKernelLockdown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unavailable"
	}
	for _, candidate := range []string{"none", "integrity", "confidentiality"} {
		if strings.Contains(value, "["+candidate+"]") {
			return candidate
		}
	}
	return value
}

func utsReleaseString(release [65]int8) string {
	buf := make([]byte, 0, len(release))
	for _, value := range release {
		if value == 0 {
			break
		}
		buf = append(buf, byte(value))
	}
	return string(buf)
}
