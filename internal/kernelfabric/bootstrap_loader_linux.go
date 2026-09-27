//go:build linux

package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type BootstrapLoader struct {
	BPFToolPath string
	Runner      BPFToolRunner
}

type BootstrapLoadRequest struct {
	ArtifactPath          string
	CgroupPath            string
	BPFFSRoot             string
	SignedManifest        SignedBootstrapManifest
	Trust                 BootstrapTrustStore
	Host                  BootstrapHostSnapshot
	AttestationPrivateKey ed25519.PrivateKey
	Now                   time.Time
}

type BootstrapLoadResult struct {
	SignedReceipt SignedBootstrapReceipt
}

func (l BootstrapLoader) LoadAndAttach(
	ctx context.Context,
	req BootstrapLoadRequest,
) (BootstrapLoadResult, error) {
	if err := ctx.Err(); err != nil {
		return BootstrapLoadResult{}, err
	}
	if len(req.AttestationPrivateKey) != ed25519.PrivateKeySize {
		return BootstrapLoadResult{}, errors.New("bootstrap attestation private key is required")
	}
	now := req.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedBootstrapManifest(req.SignedManifest, req.Trust, now); err != nil {
		return BootstrapLoadResult{}, err
	}
	if err := VerifyBootstrapArtifact(req.ArtifactPath, req.SignedManifest.Manifest); err != nil {
		return BootstrapLoadResult{}, err
	}

	cgroupPath := filepath.Clean(strings.TrimSpace(req.CgroupPath))
	info, err := os.Stat(cgroupPath)
	if err != nil {
		return BootstrapLoadResult{}, fmt.Errorf("stat bootstrap cgroup: %w", err)
	}
	if !info.IsDir() {
		return BootstrapLoadResult{}, errors.New("bootstrap cgroup target is not a directory")
	}

	root := filepath.Clean(strings.TrimSpace(req.BPFFSRoot))
	if root == "." || root == "" {
		return BootstrapLoadResult{}, errors.New("bootstrap bpffs root is required")
	}
	if filepath.Clean(req.Host.BPFFSRoot) != root {
		return BootstrapLoadResult{}, errors.New("bootstrap host snapshot bpffs root mismatch")
	}
	if strings.TrimSpace(req.Host.BootIDHash) == "" || strings.TrimSpace(req.Host.KernelRelease) == "" {
		return BootstrapLoadResult{}, errors.New("bootstrap host snapshot is incomplete")
	}

	programDir := filepath.Join(root, "programs")
	mapDir := filepath.Join(root, "maps")
	if err := os.MkdirAll(programDir, 0o755); err != nil {
		return BootstrapLoadResult{}, fmt.Errorf("create BPF program pin directory: %w", err)
	}
	if err := os.MkdirAll(mapDir, 0o755); err != nil {
		return BootstrapLoadResult{}, fmt.Errorf("create BPF map pin directory: %w", err)
	}
	if err := ensureBootstrapPinsVacant(programDir, mapDir, req.SignedManifest.Manifest); err != nil {
		return BootstrapLoadResult{}, err
	}

	runner := l.runner()
	bpftoolPath := strings.TrimSpace(l.BPFToolPath)
	if bpftoolPath == "" {
		bpftoolPath = "bpftool"
	}

	output, err := runner.Run(
		ctx,
		bpftoolPath,
		"prog", "loadall",
		req.ArtifactPath,
		programDir,
		"pinmaps", mapDir,
	)
	if err != nil {
		return BootstrapLoadResult{}, fmt.Errorf(
			"load signed BPF artifact: %w: %s",
			err,
			strings.TrimSpace(string(output)),
		)
	}

	programs, maps, err := l.inspectLoadedState(
		ctx,
		req.SignedManifest.Manifest,
		programDir,
		mapDir,
	)
	if err != nil {
		_ = cleanupBootstrapPins(programDir, mapDir, req.SignedManifest.Manifest)
		return BootstrapLoadResult{}, err
	}

	attached := make([]BootstrapProgram, 0, len(req.SignedManifest.Manifest.Programs))
	for _, expected := range req.SignedManifest.Manifest.Programs {
		pinPath := filepath.Join(programDir, expected.PinName)
		output, err := runner.Run(
			ctx,
			bpftoolPath,
			"cgroup", "attach",
			cgroupPath,
			expected.AttachType,
			"pinned", pinPath,
			"multi",
		)
		if err != nil {
			rollbackErr := l.detachAttached(
				context.WithoutCancel(ctx),
				cgroupPath,
				programDir,
				attached,
			)
			return BootstrapLoadResult{}, errors.Join(
				fmt.Errorf(
					"attach BPF program %s: %w: %s",
					expected.PinName,
					err,
					strings.TrimSpace(string(output)),
				),
				rollbackErr,
			)
		}
		attached = append(attached, expected)
	}

	manifestDigest, err := BootstrapManifestDigest(req.SignedManifest.Manifest)
	if err != nil {
		_ = l.detachAttached(context.WithoutCancel(ctx), cgroupPath, programDir, attached)
		return BootstrapLoadResult{}, err
	}
	receipt := BootstrapReceipt{
		Version:        BootstrapReceiptVersion,
		ManifestDigest: manifestDigest,
		ArtifactSHA256: req.SignedManifest.Manifest.ArtifactSHA256,
		ArtifactSize:   req.SignedManifest.Manifest.ArtifactSize,
		Host:           req.Host,
		CgroupPath:     cgroupPath,
		Programs:       programs,
		Maps:           maps,
		CompletedAt:    now,
	}
	signedReceipt, err := SignBootstrapReceipt(receipt, req.AttestationPrivateKey)
	if err != nil {
		_ = l.detachAttached(context.WithoutCancel(ctx), cgroupPath, programDir, attached)
		return BootstrapLoadResult{}, err
	}
	return BootstrapLoadResult{SignedReceipt: signedReceipt}, nil
}

func (l BootstrapLoader) detachAttached(
	ctx context.Context,
	cgroupPath string,
	programDir string,
	programs []BootstrapProgram,
) error {
	runner := l.runner()
	bpftoolPath := strings.TrimSpace(l.BPFToolPath)
	if bpftoolPath == "" {
		bpftoolPath = "bpftool"
	}
	var errs []error
	for i := len(programs) - 1; i >= 0; i-- {
		program := programs[i]
		pinPath := filepath.Join(programDir, program.PinName)
		output, err := runner.Run(
			ctx,
			bpftoolPath,
			"cgroup", "detach",
			cgroupPath,
			program.AttachType,
			"pinned", pinPath,
		)
		if err != nil {
			errs = append(errs, fmt.Errorf(
				"rollback BPF attach %s: %w: %s",
				program.PinName,
				err,
				strings.TrimSpace(string(output)),
			))
		}
	}
	return errors.Join(errs...)
}

func (l BootstrapLoader) inspectLoadedState(
	ctx context.Context,
	manifest BootstrapManifest,
	programDir string,
	mapDir string,
) ([]PinnedProgramAttestation, []PinnedMapAttestation, error) {
	runner := l.runner()
	bpftoolPath := strings.TrimSpace(l.BPFToolPath)
	if bpftoolPath == "" {
		bpftoolPath = "bpftool"
	}

	programs := make([]PinnedProgramAttestation, 0, len(manifest.Programs))
	for _, expected := range manifest.Programs {
		pinPath := filepath.Join(programDir, expected.PinName)
		output, err := runner.Run(ctx, bpftoolPath, "-j", "prog", "show", "pinned", pinPath)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect pinned BPF program %s: %w", expected.PinName, err)
		}
		var info struct {
			ID   uint32 `json:"id"`
			Type string `json:"type"`
			Name string `json:"name"`
			Tag  string `json:"tag"`
		}
		if err := decodeBPFToolSingle(output, &info); err != nil {
			return nil, nil, fmt.Errorf("decode pinned BPF program %s: %w", expected.PinName, err)
		}
		if info.ID == 0 ||
			info.Name != expected.Name ||
			info.Type != expected.Type ||
			strings.TrimSpace(info.Tag) == "" {
			return nil, nil, fmt.Errorf(
				"%w: program %s loaded as id=%d name=%q type=%q tag=%q",
				ErrBootstrapPostloadMismatch,
				expected.PinName,
				info.ID,
				info.Name,
				info.Type,
				info.Tag,
			)
		}
		programs = append(programs, PinnedProgramAttestation{
			PinName:    expected.PinName,
			ID:         info.ID,
			Name:       info.Name,
			Type:       info.Type,
			Tag:        info.Tag,
			AttachType: expected.AttachType,
		})
	}

	maps := make([]PinnedMapAttestation, 0, len(manifest.Maps))
	for _, expected := range manifest.Maps {
		pinPath := filepath.Join(mapDir, expected.Name)
		output, err := runner.Run(ctx, bpftoolPath, "-j", "map", "show", "pinned", pinPath)
		if err != nil {
			return nil, nil, fmt.Errorf("inspect pinned BPF map %s: %w", expected.Name, err)
		}
		var info struct {
			ID         uint32 `json:"id"`
			Type       string `json:"type"`
			Name       string `json:"name"`
			BytesKey   uint32 `json:"bytes_key"`
			BytesValue uint32 `json:"bytes_value"`
			MaxEntries uint32 `json:"max_entries"`
		}
		if err := decodeBPFToolSingle(output, &info); err != nil {
			return nil, nil, fmt.Errorf("decode pinned BPF map %s: %w", expected.Name, err)
		}
		if info.ID == 0 || info.Name != expected.Name || info.Type != expected.Type {
			return nil, nil, fmt.Errorf(
				"%w: map %s loaded as id=%d name=%q type=%q",
				ErrBootstrapPostloadMismatch,
				expected.Name,
				info.ID,
				info.Name,
				info.Type,
			)
		}
		maps = append(maps, PinnedMapAttestation{
			Name:       info.Name,
			ID:         info.ID,
			Type:       info.Type,
			KeySize:    info.BytesKey,
			ValueSize:  info.BytesValue,
			MaxEntries: info.MaxEntries,
		})
	}
	return programs, maps, nil
}

func (l BootstrapLoader) runner() BPFToolRunner {
	if l.Runner != nil {
		return l.Runner
	}
	return execBPFToolRunner{}
}

func decodeBPFToolSingle(payload []byte, dst any) error {
	var raw json.RawMessage
	if err := json.Unmarshal(payload, &raw); err != nil {
		return err
	}
	trimmed := strings.TrimSpace(string(raw))
	if strings.HasPrefix(trimmed, "[") {
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return err
		}
		if len(items) != 1 {
			return fmt.Errorf("expected exactly one bpftool object, got %d", len(items))
		}
		return json.Unmarshal(items[0], dst)
	}
	return json.Unmarshal(raw, dst)
}

func ensureBootstrapPinsVacant(
	programDir string,
	mapDir string,
	manifest BootstrapManifest,
) error {
	for _, program := range manifest.Programs {
		path := filepath.Join(programDir, program.PinName)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("bootstrap program pin already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, m := range manifest.Maps {
		path := filepath.Join(mapDir, m.Name)
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("bootstrap map pin already exists: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func cleanupBootstrapPins(
	programDir string,
	mapDir string,
	manifest BootstrapManifest,
) error {
	var errs []error
	for _, program := range manifest.Programs {
		if err := os.Remove(filepath.Join(programDir, program.PinName)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	for _, m := range manifest.Maps {
		if err := os.Remove(filepath.Join(mapDir, m.Name)); err != nil &&
			!errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
