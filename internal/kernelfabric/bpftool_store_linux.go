//go:build linux

package kernelfabric

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

type BPFToolRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type execBPFToolRunner struct{}

func (execBPFToolRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type BPFToolStore struct {
	BPFToolPath    string
	CapsuleMapPath string
	FenceMapPath   string
	Runner         BPFToolRunner
}

func NewBPFToolStore(
	bpftoolPath string,
	capsuleMapPath string,
	fenceMapPath string,
) (*BPFToolStore, error) {
	bpftoolPath = strings.TrimSpace(bpftoolPath)
	if bpftoolPath == "" {
		var err error
		bpftoolPath, err = exec.LookPath("bpftool")
		if err != nil {
			return nil, fmt.Errorf("locate bpftool: %w", err)
		}
	}
	if strings.TrimSpace(capsuleMapPath) == "" || strings.TrimSpace(fenceMapPath) == "" {
		return nil, errors.New("pinned capsule and fence map paths are required")
	}
	return &BPFToolStore{
		BPFToolPath:    bpftoolPath,
		CapsuleMapPath: filepath.Clean(capsuleMapPath),
		FenceMapPath:   filepath.Clean(fenceMapPath),
		Runner:         execBPFToolRunner{},
	}, nil
}

func (s *BPFToolStore) PutFence(
	ctx context.Context,
	key ScopeFenceKey,
	value ScopeFenceState,
) error {
	keyBytes, err := MarshalScopeFenceKey(key)
	if err != nil {
		return err
	}
	valueBytes, err := MarshalScopeFenceState(value)
	if err != nil {
		return err
	}
	return s.updateMap(ctx, s.FenceMapPath, keyBytes, valueBytes)
}

func (s *BPFToolStore) PutCapsule(
	ctx context.Context,
	key ScopeKey,
	value DecisionCapsule,
) error {
	keyBytes, err := MarshalScopeKey(key)
	if err != nil {
		return err
	}
	valueBytes, err := MarshalDecisionCapsule(value)
	if err != nil {
		return err
	}
	return s.updateMap(ctx, s.CapsuleMapPath, keyBytes, valueBytes)
}

func (s *BPFToolStore) DeleteCapsule(
	ctx context.Context,
	key ScopeKey,
) error {
	keyBytes, err := MarshalScopeKey(key)
	if err != nil {
		return err
	}
	args := []string{"map", "delete", "pinned", s.CapsuleMapPath, "key", "hex"}
	args = append(args, hexByteArgs(keyBytes)...)
	output, err := s.runner().Run(ctx, s.BPFToolPath, args...)
	if err != nil {
		return fmt.Errorf("bpftool delete capsule: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *BPFToolStore) updateMap(
	ctx context.Context,
	path string,
	key []byte,
	value []byte,
) error {
	args := []string{"map", "update", "pinned", path, "key", "hex"}
	args = append(args, hexByteArgs(key)...)
	args = append(args, "value", "hex")
	args = append(args, hexByteArgs(value)...)
	output, err := s.runner().Run(ctx, s.BPFToolPath, args...)
	if err != nil {
		return fmt.Errorf("bpftool update %s: %w: %s", path, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *BPFToolStore) runner() BPFToolRunner {
	if s.Runner != nil {
		return s.Runner
	}
	return execBPFToolRunner{}
}

func hexByteArgs(payload []byte) []string {
	out := make([]string, 0, len(payload))
	for _, b := range payload {
		var encoded [2]byte
		hex.Encode(encoded[:], []byte{b})
		out = append(out, string(encoded[:]))
	}
	return out
}
