//go:build linux

package kernelfabric

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

var ErrTaintSourceProbe = errors.New("kernel taint source identity probe failed")

// ResolveTaintFileKeysObserved resolves the identities that the loaded BPF-LSM
// file_permission hook actually observes for one controlled read of path.
//
// This is intentionally different from ResolveTaintFileKey. On stacked
// filesystems a userspace stat(2) device identity can differ from one or more
// inode/superblock identities traversed by the LSM hook. The source plan must
// therefore bind the kernel-observed identities, not guess a dev_t translation.
//
// The caller must run this after the signed taint artifact has been loaded and
// pinned, but it does not require the target cgroup to be activated.
func ResolveTaintFileKeysObserved(bpffsRoot, path string) ([]TaintFileKey, error) {
	root := filepath.Clean(strings.TrimSpace(bpffsRoot))
	if root == "." || root == "" {
		root = DefaultTaintBPFFSRoot
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("%w: bpffs root must be absolute", ErrTaintSourceProbe)
	}

	path = filepath.Clean(strings.TrimSpace(path))
	if path == "." || !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: source path must be absolute", ErrTaintSourceProbe)
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("%w: open source without symlink following: %v", ErrTaintSourceProbe, err)
	}
	defer unix.Close(fd)

	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return nil, fmt.Errorf("%w: stat opened source: %v", ErrTaintSourceProbe, err)
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Ino == 0 {
		return nil, fmt.Errorf("%w: source must be a regular file with non-zero inode", ErrTaintSourceProbe)
	}

	mapDir := filepath.Join(root, "maps")
	probe, err := openExactTaintMap(
		filepath.Join(mapDir, "aegis_tprobe"),
		ebpf.Hash,
		4,
		8,
		4096,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTaintSourceProbe, err)
	}
	defer probe.Close()

	results, err := openExactTaintMap(
		filepath.Join(mapDir, "aegis_tprobe_results"),
		ebpf.Hash,
		TaintProbeKeySize,
		8,
		16384,
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTaintSourceProbe, err)
	}
	defer results.Close()

	token, err := randomProbeToken()
	if err != nil {
		return nil, err
	}

	// TID, not TGID, is the probe identity. Keep the goroutine on one kernel
	// thread from arm through the controlled pread so sibling goroutines cannot
	// contribute unrelated file_permission observations.
	runtime.LockOSThread()
	tid := uint32(unix.Gettid())
	if tid == 0 {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("%w: current tid is zero", ErrTaintSourceProbe)
	}

	if err := probe.Update(&tid, &token, ebpf.UpdateNoExist); err != nil {
		runtime.UnlockOSThread()
		return nil, fmt.Errorf("%w: arm tid %d: %v", ErrTaintSourceProbe, tid, err)
	}

	buf := []byte{0}
	_, readErr := unix.Pread(fd, buf, 0)
	disarmErr := probe.Delete(&tid)
	runtime.UnlockOSThread()

	if readErr != nil {
		return nil, fmt.Errorf("%w: controlled source read: %v", ErrTaintSourceProbe, readErr)
	}
	if disarmErr != nil && !errors.Is(disarmErr, ebpf.ErrKeyNotExist) {
		return nil, fmt.Errorf("%w: disarm tid %d: %v", ErrTaintSourceProbe, tid, disarmErr)
	}

	var (
		probeKey TaintProbeKey
		gotToken uint64
		matched  []TaintProbeKey
	)
	iter := results.Iterate()
	for iter.Next(&probeKey, &gotToken) {
		if probeKey.TID == tid && gotToken == token {
			matched = append(matched, probeKey)
		}
	}
	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("%w: iterate probe results: %v", ErrTaintSourceProbe, err)
	}

	// Results are token-scoped, so stale observations from older probes cannot
	// be mistaken for the current enrollment. Remove only this probe's records.
	for _, key := range matched {
		_ = results.Delete(&key)
	}

	if len(matched) == 0 {
		return nil, fmt.Errorf(
			"%w: kernel emitted no file identity for tid=%d source_inode=%d",
			ErrTaintSourceProbe,
			tid,
			stat.Ino,
		)
	}

	unique := make(map[TaintFileKey]struct{}, len(matched))
	keys := make([]TaintFileKey, 0, len(matched))
	for _, observed := range matched {
		if observed.Reserved != 0 || observed.Device == 0 || observed.Inode == 0 {
			return nil, fmt.Errorf("%w: invalid kernel observation %+v", ErrTaintSourceProbe, observed)
		}
		key := TaintFileKey{Device: observed.Device, Inode: observed.Inode}
		if _, exists := unique[key]; exists {
			continue
		}
		unique[key] = struct{}{}
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].Device != keys[j].Device {
			return keys[i].Device < keys[j].Device
		}
		return keys[i].Inode < keys[j].Inode
	})
	if len(keys) == 0 {
		return nil, fmt.Errorf("%w: all kernel observations were invalid", ErrTaintSourceProbe)
	}
	return keys, nil
}

func randomProbeToken() (uint64, error) {
	var payload [8]byte
	for {
		if _, err := rand.Read(payload[:]); err != nil {
			return 0, fmt.Errorf("%w: generate probe token: %v", ErrTaintSourceProbe, err)
		}
		token := binary.LittleEndian.Uint64(payload[:])
		if token != 0 {
			return token, nil
		}
	}
}

