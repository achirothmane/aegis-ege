package recoverywitnessprofile

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

const StaticPolicyVersion = "aegis.ege/taint-recovery-witness-policy/v1"

type StaticPolicy struct {
	Version       string `json:"version"`
	PolicyEpoch   uint64 `json:"policy_epoch"`
	PlanDigest    string `json:"plan_digest"`
	CgroupID      uint64 `json:"cgroup_id"`
	BPFFSRoot     string `json:"bpffs_root"`
	BootIDHash    string `json:"boot_id_hash"`
	FromEpoch     uint64 `json:"from_epoch"`
	ToEpoch       uint64 `json:"to_epoch"`
	ExpectedDirty uint64 `json:"expected_dirty"`
}

func (p StaticPolicy) Validate() error {
	if p.Version != StaticPolicyVersion {
		return fmt.Errorf("unsupported witness policy version %q", p.Version)
	}
	if p.PolicyEpoch == 0 {
		return fmt.Errorf("witness policy epoch must be non-zero")
	}
	auth := kernelfabric.TaintRecoveryAuthorization{
		Version:         kernelfabric.TaintRecoveryAuthorizationVersion,
		AuthorizationID: "static-policy-validation",
		PlanDigest:      p.PlanDigest,
		CgroupID:        p.CgroupID,
		BPFFSRoot:       p.BPFFSRoot,
		BootIDHash:      p.BootIDHash,
		FromEpoch:       p.FromEpoch,
		ToEpoch:         p.ToEpoch,
		ExpectedDirty:   p.ExpectedDirty,
		NotBefore:       testPolicyTime(),
		ExpiresAt:       testPolicyTime().AddDate(0, 0, 1),
	}
	return kernelfabric.ValidateTaintRecoveryAuthorization(auth)
}

func (p StaticPolicy) AdmitTaintRecoveryWitness(
	_ context.Context,
	auth kernelfabric.TaintRecoveryAuthorization,
) error {
	if err := p.Validate(); err != nil {
		return fmt.Errorf("invalid witness policy: %w", err)
	}
	if auth.PlanDigest != p.PlanDigest ||
		auth.CgroupID != p.CgroupID ||
		auth.BPFFSRoot != p.BPFFSRoot ||
		auth.BootIDHash != p.BootIDHash ||
		auth.FromEpoch != p.FromEpoch ||
		auth.ToEpoch != p.ToEpoch ||
		auth.ExpectedDirty != p.ExpectedDirty {
		return fmt.Errorf("authorization does not match pinned witness policy")
	}
	return nil
}

func testPolicyTime() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}


func (p StaticPolicy) RecoveryWitnessPolicyEpoch() uint64 {
	return p.PolicyEpoch
}

func (p StaticPolicy) RecoveryWitnessPolicyHash() (string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return kernelfabric.CanonicalJSONSHA256(raw)
}
