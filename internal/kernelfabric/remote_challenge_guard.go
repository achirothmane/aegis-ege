package kernelfabric

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var ErrRemoteChallengeReplay = errors.New("remote attestation challenge was already consumed")

type RemoteChallengeConsumptionRecord struct {
	Version         string    `json:"version"`
	ChallengeID     string    `json:"challenge_id"`
	DeviceID        string    `json:"device_id"`
	ChallengeDigest string    `json:"challenge_digest"`
	ConsumedAt      time.Time `json:"consumed_at"`
}

const RemoteChallengeConsumptionVersion = "aegis.ege/remote-attestation-consumption/v1"

func ConsumeRemoteAttestationChallenge(
	dir string,
	challenge RemoteAttestationChallenge,
	now time.Time,
) error {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := validateRemoteChallenge(challenge, now); err != nil {
		return err
	}
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || dir == "" {
		return errors.New("remote attestation challenge consumption directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create remote challenge consumption directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("secure remote challenge consumption directory: %w", err)
	}

	payload, err := canonicalRemoteChallengePayload(challenge)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(payload)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := sha256.Sum256([]byte(challenge.DeviceID + "\x00" + challenge.ChallengeID))
	path := filepath.Join(dir, hex.EncodeToString(key[:])+".consumed.json")

	record := RemoteChallengeConsumptionRecord{
		Version:         RemoteChallengeConsumptionVersion,
		ChallengeID:     challenge.ChallengeID,
		DeviceID:        challenge.DeviceID,
		ChallengeDigest: digest,
		ConsumedAt:      now.UTC(),
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode remote challenge consumption: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return ErrRemoteChallengeReplay
	}
	if err != nil {
		return fmt.Errorf("claim remote attestation challenge: %w", err)
	}
	if _, err := file.Write(append(encoded, '\n')); err != nil {
		_ = file.Close()
		return fmt.Errorf("write remote challenge consumption: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("sync remote challenge consumption: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close remote challenge consumption: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("open remote challenge consumption directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return fmt.Errorf("sync remote challenge consumption directory: %w", err)
	}
	return nil
}
