package kernelfabric

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type WorkloadGrantConsumptionRecord struct {
	Version     string    `json:"version"`
	GrantID     string    `json:"grant_id"`
	GrantDigest string    `json:"grant_digest"`
	DeviceID    string    `json:"device_id"`
	WorkloadID  string    `json:"workload_id"`
	ConsumedAt  time.Time `json:"consumed_at"`
}

const WorkloadGrantConsumptionVersion = "aegis.ege/workload-admission-consumption/v1"

func ConsumeWorkloadAdmissionGrant(
	dir string,
	signed SignedWorkloadAdmissionGrant,
	issuerPublicKey ed25519.PublicKey,
	expectedSpec WorkloadLaunchSpec,
	expectedTargetCgroup string,
	expectedDeviceID string,
	now time.Time,
) (WorkloadGrantConsumptionRecord, error) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if err := VerifySignedWorkloadAdmissionGrant(signed, issuerPublicKey, now); err != nil {
		return WorkloadGrantConsumptionRecord{}, err
	}
	expectedDigest, err := WorkloadLaunchSpecDigest(expectedSpec)
	if err != nil {
		return WorkloadGrantConsumptionRecord{}, err
	}
	if signed.Grant.WorkloadSpecDigest != expectedDigest ||
		filepath.Clean(signed.Grant.TargetCgroup) != filepath.Clean(expectedTargetCgroup) ||
		signed.Grant.DeviceID != strings.TrimSpace(expectedDeviceID) {
		return WorkloadGrantConsumptionRecord{}, ErrAdmissionBindingMismatch
	}
	grantDigest, err := SignedWorkloadAdmissionGrantDigest(signed)
	if err != nil {
		return WorkloadGrantConsumptionRecord{}, err
	}

	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || dir == "" {
		return WorkloadGrantConsumptionRecord{}, errors.New("workload grant consumption directory is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("create workload grant consumption directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("secure workload grant consumption directory: %w", err)
	}

	path := filepath.Join(dir, signed.Grant.GrantID+".consumed.json")
	record := WorkloadGrantConsumptionRecord{
		Version:     WorkloadGrantConsumptionVersion,
		GrantID:     signed.Grant.GrantID,
		GrantDigest: grantDigest,
		DeviceID:    signed.Grant.DeviceID,
		WorkloadID:  signed.Grant.WorkloadID,
		ConsumedAt:  now.UTC(),
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return WorkloadGrantConsumptionRecord{}, err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return WorkloadGrantConsumptionRecord{}, ErrAdmissionGrantReplay
	}
	if err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("claim workload admission grant: %w", err)
	}
	if _, err := file.Write(append(payload, '\n')); err != nil {
		_ = file.Close()
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("write workload grant consumption: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("sync workload grant consumption: %w", err)
	}
	if err := file.Close(); err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("close workload grant consumption: %w", err)
	}
	parent, err := os.Open(dir)
	if err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("open workload grant consumption directory: %w", err)
	}
	defer parent.Close()
	if err := parent.Sync(); err != nil {
		return WorkloadGrantConsumptionRecord{}, fmt.Errorf("sync workload grant consumption directory: %w", err)
	}
	return record, nil
}
