package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/achirothmane/state-latch/internal/decision"
)

var ErrExecutionReplay = errors.New("authorization was already claimed for execution")

type ReplayGuard interface {
	Claim(context.Context, decision.Authorization) error
}

type FileReplayGuard struct {
	dir string
}

func NewFileReplayGuard(dir string) (*FileReplayGuard, error) {
	if dir == "" {
		return nil, fmt.Errorf("replay guard directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create replay guard directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secure replay guard directory: %w", err)
	}
	return &FileReplayGuard{dir: dir}, nil
}

func (g *FileReplayGuard) Claim(ctx context.Context, auth decision.Authorization) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := authorizationReplayKey(auth)
	if err != nil {
		return err
	}
	path := filepath.Join(g.dir, key+".claimed")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrExecutionReplay
	}
	if err != nil {
		return fmt.Errorf("claim execution authorization: %w", err)
	}
	payload := []byte(auth.ActionID + "\n")
	if _, err := file.Write(payload); err != nil {
		_ = file.Close()
		return fmt.Errorf("write replay claim: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync replay claim: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close replay claim: %w", err)
	}
	return nil
}

func authorizationReplayKey(auth decision.Authorization) (string, error) {
	payload, err := json.Marshal(struct {
		ActionID        string
		Action          string
		Target          string
		ResourceVersion string
		EvidenceDigest  string
		PlanDigest      string
		ValidUntil      string
	}{
		ActionID:        auth.ActionID,
		Action:          auth.Action,
		Target:          auth.Target,
		ResourceVersion: auth.ResourceVersion,
		EvidenceDigest:  auth.EvidenceDigest,
		PlanDigest:      auth.PlanDigest,
		ValidUntil:      auth.ValidUntil.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
	})
	if err != nil {
		return "", fmt.Errorf("encode authorization replay key: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
