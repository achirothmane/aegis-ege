//go:build linux

package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

type LinuxProcessObservation struct {
	Exists          bool
	Identity        LinuxProcessIdentity
	ObservedCgroup  string
	ObservedCgroupID uint64
}

func CaptureLinuxProcessIdentity(pid int, expectedCgroupID uint64) (LinuxProcessIdentity, error) {
	obs, err := ObserveLinuxProcess(pid)
	if err != nil {
		return LinuxProcessIdentity{}, err
	}
	if !obs.Exists {
		return LinuxProcessIdentity{}, errors.New("process exited before identity capture")
	}
	if expectedCgroupID != 0 && obs.ObservedCgroupID != expectedCgroupID {
		return LinuxProcessIdentity{}, ErrAdmissionBindingMismatch
	}
	return obs.Identity, nil
}

func ObserveLinuxProcess(pid int) (LinuxProcessObservation, error) {
	if pid <= 0 {
		return LinuxProcessObservation{}, errors.New("process id must be positive")
	}
	bootHash, err := ReadBootIDHash(DefaultBootIDPath)
	if err != nil {
		return LinuxProcessObservation{}, err
	}
	bootDigest := "sha256:" + hex.EncodeToString(bootHash[:])

	startTicks, exists, err := readLinuxProcessStartTicks(pid)
	if err != nil {
		return LinuxProcessObservation{}, err
	}
	if !exists {
		return LinuxProcessObservation{Exists: false}, nil
	}

	exeInfo, err := os.Stat(fmt.Sprintf("/proc/%d/exe", pid))
	if errors.Is(err, os.ErrNotExist) {
		return LinuxProcessObservation{}, errors.New("process vanished while reading executable identity")
	}
	if err != nil {
		return LinuxProcessObservation{}, fmt.Errorf("stat process executable: %w", err)
	}
	exeStat, ok := exeInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return LinuxProcessObservation{}, errors.New("process executable stat is not syscall.Stat_t")
	}

	cgroupPath, err := readUnifiedProcessCgroup(pid)
	if err != nil {
		return LinuxProcessObservation{}, err
	}
	cgroupResolved, err := resolveUnifiedCgroupPath(cgroupPath)
	if err != nil {
		return LinuxProcessObservation{}, err
	}
	cgroupInfo, err := os.Stat(cgroupResolved)
	if err != nil {
		return LinuxProcessObservation{}, fmt.Errorf("stat observed process cgroup: %w", err)
	}
	cgroupStat, ok := cgroupInfo.Sys().(*syscall.Stat_t)
	if !ok || cgroupStat.Ino == 0 {
		return LinuxProcessObservation{}, errors.New("observed process cgroup identity unavailable")
	}

	finalStartTicks, stillExists, err := readLinuxProcessStartTicks(pid)
	if err != nil {
		return LinuxProcessObservation{}, err
	}
	if !stillExists || finalStartTicks != startTicks {
		return LinuxProcessObservation{}, errors.New("process identity changed while observation was collected")
	}

	return LinuxProcessObservation{
		Exists: true,
		Identity: LinuxProcessIdentity{
			BootIDHash:            bootDigest,
			ProcessStartTimeTicks: startTicks,
			ExecutableDevice:      uint64(exeStat.Dev),
			ExecutableInode:       uint64(exeStat.Ino),
		},
		ObservedCgroup:   cgroupResolved,
		ObservedCgroupID: uint64(cgroupStat.Ino),
	}, nil
}

func readLinuxProcessStartTicks(pid int) (uint64, bool, error) {
	payload, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("read process stat: %w", err)
	}
	line := string(payload)
	endComm := strings.LastIndex(line, ") ")
	if endComm < 0 {
		return 0, false, errors.New("malformed /proc process stat")
	}
	fields := strings.Fields(line[endComm+2:])
	// fields[0] is original field 3 (state), so original field 22 is index 19.
	if len(fields) <= 19 {
		return 0, false, errors.New("process stat missing starttime")
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, false, fmt.Errorf("parse process starttime: %w", err)
	}
	if start == 0 {
		return 0, false, errors.New("process starttime is zero")
	}
	return start, true, nil
}

func readUnifiedProcessCgroup(pid int) (string, error) {
	payload, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return "", fmt.Errorf("read process cgroup membership: %w", err)
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if strings.HasPrefix(line, "0::") {
			path := strings.TrimPrefix(line, "0::")
			if path == "" {
				path = "/"
			}
			return filepath.Clean(path), nil
		}
	}
	return "", errors.New("process is not attached to unified cgroup v2 hierarchy")
}

func resolveUnifiedCgroupPath(cgroupPath string) (string, error) {
	payload, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", fmt.Errorf("read mountinfo: %w", err)
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, " - ")
		if len(parts) != 2 {
			continue
		}
		post := strings.Fields(parts[1])
		if len(post) < 1 || post[0] != "cgroup2" {
			continue
		}
		pre := strings.Fields(parts[0])
		if len(pre) < 5 {
			continue
		}
		root := unescapeMountInfo(pre[3])
		mountPoint := unescapeMountInfo(pre[4])
		clean := filepath.Clean(cgroupPath)
		if root != "/" {
			root = filepath.Clean(root)
			if clean != root && !strings.HasPrefix(clean, root+"/") {
				continue
			}
			clean = strings.TrimPrefix(clean, root)
			if clean == "" {
				clean = "/"
			}
		}
		return filepath.Join(mountPoint, strings.TrimPrefix(clean, "/")), nil
	}
	return "", errors.New("cgroup v2 mountpoint not found")
}

func unescapeMountInfo(value string) string {
	replacer := strings.NewReplacer(
		"\\040", " ",
		"\\011", "\t",
		"\\012", "\n",
		"\\134", "\\",
	)
	return replacer.Replace(value)
}

func LinuxProcessIdentityDigest(identity LinuxProcessIdentity) (string, error) {
	if err := ValidateLinuxProcessIdentity(identity); err != nil {
		return "", err
	}
	raw := fmt.Sprintf(
		"%s\x00%d\x00%d\x00%d",
		identity.BootIDHash,
		identity.ProcessStartTimeTicks,
		identity.ExecutableDevice,
		identity.ExecutableInode,
	)
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
