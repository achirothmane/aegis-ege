package governedaction_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

//go:embed testdata/muse-class/corpus-v0.json
var museClassCorpusBytes []byte

type museClassCorpus struct {
	Schema                string          `json:"schema"`
	Status                string          `json:"status"`
	FrozenKernelV1Changed bool            `json:"frozen_kernel_v1_changed"`
	Cases                 []museClassCase `json:"cases"`
}

type museClassCase struct {
	ID                 string                 `json:"id"`
	Name               string                 `json:"name"`
	Class              string                 `json:"class"`
	Coverage           string                 `json:"coverage"`
	Gate               string                 `json:"gate"`
	Expect             string                 `json:"expect"`
	AdmittedOrigin     *museOriginFixture     `json:"admitted_origin,omitempty"`
	CurrentOrigin      *museOriginFixture     `json:"current_origin,omitempty"`
	AdmittedApproval   *museApprovalFixture   `json:"admitted_approval,omitempty"`
	CurrentApproval    *museApprovalFixture   `json:"current_approval,omitempty"`
	AdmittedCredential *museCredentialFixture `json:"admitted_credential,omitempty"`
	CurrentCredential  *museCredentialFixture `json:"current_credential,omitempty"`
	EffectsUsed        uint32                 `json:"effects_used,omitempty"`
	At                 string                 `json:"at,omitempty"`
}

type museOriginFixture struct {
	OriginID     string   `json:"origin_id"`
	OriginType   string   `json:"origin_type"`
	SourceDigest string   `json:"source_digest"`
	TrustDomain  string   `json:"trust_domain"`
	TrustEpoch   string   `json:"trust_epoch"`
	Capabilities []string `json:"capabilities"`
}

type museApprovalFixture struct {
	ApprovalRef    string `json:"approval_ref"`
	ActionRevision string `json:"action_revision"`
	EffectID       string `json:"effect_id"`
	Target         string `json:"target"`
	Scope          string `json:"scope"`
	Nonce          string `json:"nonce"`
	MaxEffects     uint32 `json:"max_effects"`
	ValidUntil     string `json:"valid_until"`
}

type museCredentialFixture struct {
	HandleID       string `json:"handle_id"`
	ActionRevision string `json:"action_revision"`
	EffectID       string `json:"effect_id"`
	Audience       string `json:"audience"`
	Destination    string `json:"destination"`
	Scope          string `json:"scope"`
	TrustEpoch     string `json:"trust_epoch"`
	ValidUntil     string `json:"valid_until"`
}

func TestMuseClassCorpusRegistrationAndExecutableCases(t *testing.T) {
	var corpus museClassCorpus
	if err := json.Unmarshal(museClassCorpusBytes, &corpus); err != nil {
		t.Fatalf("parse corpus: %v", err)
	}
	if corpus.Schema != "muse-class-adversarial-corpus/v0" {
		t.Fatalf("unexpected schema %q", corpus.Schema)
	}
	if corpus.Status != "EXPERIMENTAL_NON_NORMATIVE" {
		t.Fatalf("unexpected status %q", corpus.Status)
	}
	if corpus.FrozenKernelV1Changed {
		t.Fatal("experimental corpus must not relabel or change frozen kernel v1")
	}
	if len(corpus.Cases) != 16 {
		t.Fatalf("cases=%d; want 16 (M00-M15)", len(corpus.Cases))
	}

	seen := map[string]bool{}
	coverage := map[string]int{}
	executedOrigin := 0
	executedApproval := 0
	executedCredential := 0

	for _, tc := range corpus.Cases {
		if tc.ID == "" || tc.Name == "" || tc.Class == "" || tc.Coverage == "" || tc.Gate == "" || tc.Expect == "" {
			t.Fatalf("incomplete corpus case: %+v", tc)
		}
		if seen[tc.ID] {
			t.Fatalf("duplicate case id %s", tc.ID)
		}
		seen[tc.ID] = true
		coverage[tc.Coverage]++

		switch tc.Gate {
		case "origin":
			if tc.Coverage != "EXECUTABLE_NOW" {
				t.Fatalf("%s origin case is not executable: %s", tc.ID, tc.Coverage)
			}
			if tc.AdmittedOrigin == nil || tc.CurrentOrigin == nil {
				t.Fatalf("%s missing origin fixture", tc.ID)
			}
			admitted, err := fixtureOrigin(*tc.AdmittedOrigin)
			if err != nil {
				t.Fatalf("%s admitted fixture: %v", tc.ID, err)
			}
			current, err := fixtureOrigin(*tc.CurrentOrigin)
			if err != nil {
				t.Fatalf("%s current fixture: %v", tc.ID, err)
			}
			err = ga.CheckOrigin(admitted, current)
			assertMuseExpectation(t, tc, err)
			executedOrigin++

		case "approval":
			if tc.Coverage != "EXECUTABLE_NOW" {
				t.Fatalf("%s approval case is not executable: %s", tc.ID, tc.Coverage)
			}
			if tc.AdmittedApproval == nil || tc.CurrentApproval == nil {
				t.Fatalf("%s missing approval fixture", tc.ID)
			}
			admitted, err := fixtureApproval(*tc.AdmittedApproval)
			if err != nil {
				t.Fatalf("%s admitted approval fixture: %v", tc.ID, err)
			}
			current, err := fixtureApproval(*tc.CurrentApproval)
			if err != nil {
				t.Fatalf("%s current approval fixture: %v", tc.ID, err)
			}
			at, err := time.Parse(time.RFC3339, tc.At)
			if err != nil {
				t.Fatalf("%s boundary time: %v", tc.ID, err)
			}
			err = ga.CheckApprovalUse(admitted, current, at, tc.EffectsUsed)
			assertMuseExpectation(t, tc, err)
			executedApproval++

		case "credential":
			if tc.Coverage != "EXECUTABLE_NOW" {
				t.Fatalf("%s credential case is not executable: %s", tc.ID, tc.Coverage)
			}
			if tc.AdmittedCredential == nil || tc.CurrentCredential == nil {
				t.Fatalf("%s missing credential fixture", tc.ID)
			}
			admitted, err := fixtureCredential(*tc.AdmittedCredential)
			if err != nil {
				t.Fatalf("%s admitted credential fixture: %v", tc.ID, err)
			}
			current, err := fixtureCredential(*tc.CurrentCredential)
			if err != nil {
				t.Fatalf("%s current credential fixture: %v", tc.ID, err)
			}
			at, err := time.Parse(time.RFC3339, tc.At)
			if err != nil {
				t.Fatalf("%s boundary time: %v", tc.ID, err)
			}
			err = ga.CheckCredentialUse(admitted, current, at)
			assertMuseExpectation(t, tc, err)
			executedCredential++
		}
	}

	for i := 0; i <= 15; i++ {
		id := fmt.Sprintf("M%02d", i)
		if !seen[id] {
			t.Fatalf("missing registered case %s", id)
		}
	}
	if executedOrigin != 3 {
		t.Fatalf("executed origin cases=%d; want 3", executedOrigin)
	}
	if executedApproval != 2 {
		t.Fatalf("executed approval cases=%d; want 2", executedApproval)
	}
	if executedCredential != 2 {
		t.Fatalf("executed credential cases=%d; want 2", executedCredential)
	}
	if coverage["EXECUTABLE_NOW"] != 7 ||
		coverage["PLANNED"] != 3 ||
		coverage["EXISTING_COVERAGE"] != 4 ||
		coverage["PARTIAL_EXISTING"] != 2 {
		t.Fatalf("unexpected coverage accounting: %+v", coverage)
	}
}

func assertMuseExpectation(t *testing.T, tc museClassCase, err error) {
	t.Helper()
	switch tc.Expect {
	case "ALLOW_BOUNDARY_CHECK":
		if err != nil {
			t.Fatalf("%s rejected: %v", tc.ID, err)
		}
	case "REJECT":
		if err == nil {
			t.Fatalf("%s unexpectedly accepted", tc.ID)
		}
	default:
		t.Fatalf("%s unsupported executable expectation %q", tc.ID, tc.Expect)
	}
}

func fixtureOrigin(in museOriginFixture) (ga.OriginBinding, error) {
	caps := ga.OriginCapability(0)
	for _, capability := range in.Capabilities {
		switch capability {
		case "supply_instructions":
			caps |= ga.OriginSupplyInstructions
		case "register_tools":
			caps |= ga.OriginRegisterTools
		case "register_connectors":
			caps |= ga.OriginRegisterConnectors
		case "use_credential_handles":
			caps |= ga.OriginUseCredentialHandles
		case "network_egress":
			caps |= ga.OriginNetworkEgress
		default:
			return ga.OriginBinding{}, fmt.Errorf("unknown fixture capability %q", capability)
		}
	}
	return ga.OriginBinding{
		OriginID:     in.OriginID,
		OriginType:   in.OriginType,
		SourceDigest: in.SourceDigest,
		TrustDomain:  in.TrustDomain,
		TrustEpoch:   in.TrustEpoch,
		Capabilities: caps,
	}, nil
}

func fixtureApproval(in museApprovalFixture) (ga.ApprovalUseBinding, error) {
	until, err := time.Parse(time.RFC3339, in.ValidUntil)
	if err != nil {
		return ga.ApprovalUseBinding{}, fmt.Errorf("valid_until: %w", err)
	}
	return ga.ApprovalUseBinding{
		ApprovalRef:    in.ApprovalRef,
		ActionRevision: in.ActionRevision,
		EffectID:       in.EffectID,
		Target:         in.Target,
		Scope:          in.Scope,
		Nonce:          in.Nonce,
		MaxEffects:     in.MaxEffects,
		ValidUntil:     until,
	}, nil
}

func fixtureCredential(in museCredentialFixture) (ga.CredentialUseBinding, error) {
	until, err := time.Parse(time.RFC3339, in.ValidUntil)
	if err != nil {
		return ga.CredentialUseBinding{}, fmt.Errorf("valid_until: %w", err)
	}
	return ga.CredentialUseBinding{
		HandleID:       in.HandleID,
		ActionRevision: in.ActionRevision,
		EffectID:       in.EffectID,
		Audience:       in.Audience,
		Destination:    in.Destination,
		Scope:          in.Scope,
		TrustEpoch:     in.TrustEpoch,
		ValidUntil:     until,
	}, nil
}
