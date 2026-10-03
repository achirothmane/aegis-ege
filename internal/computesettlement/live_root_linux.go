//go:build linux

package computesettlement

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

// CaptureLiveAegisExecutionRoot reads the current Linux process/cgroup identity
// and executable bytes from /proc, then feeds those observations into the
// portable Aegis execution-root producer.
func CaptureLiveAegisExecutionRoot(
	pid int,
	state kernelfabric.WorkloadLifecycleState,
	activation kernelfabric.SignedWorkloadActivationReceipt,
	runtimeLease kernelfabric.SignedRuntimeTrustLease,
	expectedProfile WorkloadPerformanceProfile,
	trust AegisExecutionRootTrust,
	now time.Time,
) (LiveAegisExecutionRoot, error) {
	observation, err := kernelfabric.ObserveLinuxProcess(pid)
	if err != nil {
		return LiveAegisExecutionRoot{}, fmt.Errorf("observe live linux process: %w", err)
	}
	if !observation.Exists {
		return LiveAegisExecutionRoot{}, fmt.Errorf("live linux process %d does not exist", pid)
	}

	artifactDigest, err := liveLinuxExecutableDigest(pid)
	if err != nil {
		return LiveAegisExecutionRoot{}, err
	}

	return ProduceLiveAegisExecutionRoot(
		state,
		activation,
		runtimeLease,
		AegisRuntimeObservation{
			ProcessIdentity:          observation.Identity,
			CgroupID:                 observation.ObservedCgroupID,
			ExecutableArtifactDigest: artifactDigest,
		},
		expectedProfile,
		trust,
		now,
	)
}

func liveLinuxExecutableDigest(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("process id must be positive")
	}
	f, err := os.Open(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "", fmt.Errorf("open live process executable: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash live process executable: %w", err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
