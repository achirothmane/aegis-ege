//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const cgroup2FSMagic = 0x63677270

type AttestedWorkloadLaunchRequest struct {
	SignedGrant       SignedWorkloadAdmissionGrant
	IssuerPublicKey   ed25519.PublicKey
	LaunchSpec        WorkloadLaunchSpec
	ConsumptionDir    string
	DeviceID          string
	HostAttestorKey   ed25519.PrivateKey
	Now               time.Time
}

type AttestedWorkloadProcess struct {
	Command        *exec.Cmd
	SignedReceipt  SignedWorkloadActivationReceipt
}

func StartAttestedWorkload(
	ctx context.Context,
	req AttestedWorkloadLaunchRequest,
) (AttestedWorkloadProcess, error) {
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := req.LaunchSpec.Validate(); err != nil {
		return AttestedWorkloadProcess{}, err
	}
	if len(req.HostAttestorKey) != ed25519.PrivateKeySize {
		return AttestedWorkloadProcess{}, errors.New("host activation attestor private key is required")
	}
	if err := VerifySignedWorkloadAdmissionGrant(
		req.SignedGrant,
		req.IssuerPublicKey,
		now,
	); err != nil {
		return AttestedWorkloadProcess{}, err
	}
	specDigest, err := WorkloadLaunchSpecDigest(req.LaunchSpec)
	if err != nil {
		return AttestedWorkloadProcess{}, err
	}
	grant := req.SignedGrant.Grant
	if grant.DeviceID != strings.TrimSpace(req.DeviceID) ||
		grant.WorkloadSpecDigest != specDigest {
		return AttestedWorkloadProcess{}, ErrAdmissionBindingMismatch
	}

	targetCgroup := filepath.Clean(grant.TargetCgroup)
	var statfs unix.Statfs_t
	if err := unix.Statfs(targetCgroup, &statfs); err != nil {
		return AttestedWorkloadProcess{}, fmt.Errorf("stat target cgroup: %w", err)
	}
	if uint64(statfs.Type) != uint64(cgroup2FSMagic) {
		return AttestedWorkloadProcess{}, fmt.Errorf("%s is not on cgroup v2", targetCgroup)
	}
	cgroupFD, err := unix.Open(targetCgroup, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return AttestedWorkloadProcess{}, fmt.Errorf("open target cgroup: %w", err)
	}
	defer unix.Close(cgroupFD)
	var cgroupStat unix.Stat_t
	if err := unix.Fstat(cgroupFD, &cgroupStat); err != nil {
		return AttestedWorkloadProcess{}, fmt.Errorf("stat opened target cgroup: %w", err)
	}
	if cgroupStat.Ino == 0 || uint64(cgroupStat.Ino) != grant.TargetCgroupID {
		return AttestedWorkloadProcess{}, ErrAdmissionBindingMismatch
	}
	cgroupID := uint64(cgroupStat.Ino)

	executable := filepath.Clean(req.LaunchSpec.Executable)
	info, err := os.Stat(executable)
	if err != nil {
		return AttestedWorkloadProcess{}, fmt.Errorf("stat workload executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return AttestedWorkloadProcess{}, errors.New("workload executable is not an executable regular file")
	}
	if req.LaunchSpec.WorkingDir != "" {
		wdInfo, err := os.Stat(filepath.Clean(req.LaunchSpec.WorkingDir))
		if err != nil {
			return AttestedWorkloadProcess{}, fmt.Errorf("stat workload working directory: %w", err)
		}
		if !wdInfo.IsDir() {
			return AttestedWorkloadProcess{}, errors.New("workload working_dir is not a directory")
		}
	}

	// All non-mutating validation is complete. Claim the one-shot grant
	// immediately before process creation. Any later failure is terminal and
	// requires a fresh remote attestation + admission grant.
	consumption, err := ConsumeWorkloadAdmissionGrant(
		req.ConsumptionDir,
		req.SignedGrant,
		req.IssuerPublicKey,
		req.LaunchSpec,
		targetCgroup,
		cgroupID,
		req.DeviceID,
		now,
	)
	if err != nil {
		return AttestedWorkloadProcess{}, err
	}

	cmd := exec.CommandContext(ctx, executable, req.LaunchSpec.Args...)
	if req.LaunchSpec.WorkingDir != "" {
		cmd.Dir = filepath.Clean(req.LaunchSpec.WorkingDir)
	}
	cmd.Env = workloadEnvironment(req.LaunchSpec.Environment)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		UseCgroupFD: true,
		CgroupFD:    cgroupFD,
	}
	if err := cmd.Start(); err != nil {
		return AttestedWorkloadProcess{}, fmt.Errorf(
			"start attested workload after terminal grant claim %s: %w",
			consumption.GrantID,
			err,
		)
	}

	activationID, err := randomToken(24)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return AttestedWorkloadProcess{}, err
	}
	receipt, err := SignWorkloadActivationReceipt(
		WorkloadActivationReceipt{
			Version:            WorkloadActivationReceiptVersion,
			ActivationID:       activationID,
			GrantID:            grant.GrantID,
			GrantDigest:        consumption.GrantDigest,
			DeviceID:           grant.DeviceID,
			WorkloadID:         grant.WorkloadID,
			WorkloadSpecDigest: grant.WorkloadSpecDigest,
			TargetCgroup:       targetCgroup,
			TargetCgroupID:     cgroupID,
			ProcessID:          cmd.Process.Pid,
			StartedAt:          time.Now().UTC(),
		},
		req.HostAttestorKey,
	)
	if err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return AttestedWorkloadProcess{}, fmt.Errorf("sign activation receipt after process start: %w", err)
	}
	return AttestedWorkloadProcess{
		Command:       cmd,
		SignedReceipt: receipt,
	}, nil
}

func workloadEnvironment(env []WorkloadEnvironmentVariable) []string {
	normalized := append([]WorkloadEnvironmentVariable(nil), env...)
	sort.Slice(normalized, func(i, j int) bool {
		return normalized[i].Name < normalized[j].Name
	})
	out := make([]string, 0, len(normalized))
	for _, item := range normalized {
		out = append(out, item.Name+"="+item.Value)
	}
	return out
}

func ResolveCgroupV2ID(path string) (uint64, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return 0, errors.New("cgroup path must be absolute")
	}
	var statfs unix.Statfs_t
	if err := unix.Statfs(path, &statfs); err != nil {
		return 0, fmt.Errorf("stat cgroup filesystem: %w", err)
	}
	if uint64(statfs.Type) != uint64(cgroup2FSMagic) {
		return 0, fmt.Errorf("%s is not on cgroup v2", path)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, fmt.Errorf("open cgroup path: %w", err)
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return 0, fmt.Errorf("stat cgroup path: %w", err)
	}
	if stat.Ino == 0 {
		return 0, errors.New("cgroup identity is zero")
	}
	return uint64(stat.Ino), nil
}
