package governedaction_test

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"testing"

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
	ID             string             `json:"id"`
	Name           string             `json:"name"`
	Class          string             `json:"class"`
	Coverage       string             `json:"coverage"`
	Gate           string             `json:"gate"`
	Expect         string             `json:"expect"`
	AdmittedOrigin *museOriginFixture `json:"admitted_origin,omitempty"`
	CurrentOrigin  *museOriginFixture `json:"current_origin,omitempty"`
}

type museOriginFixture struct {
	OriginID     string   `json:"origin_id"`
	OriginType   string   `json:"origin_type"`
	SourceDigest string   `json:"source_digest"`
	TrustDomain  string   `json:"trust_domain"`
	TrustEpoch   string   `json:"trust_epoch"`
	Capabilities []string `json:"capabilities"`
}

func TestMuseClassCorpusRegistrationAndExecutableOriginCases(t *testing.T) {
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
	for _, tc := range corpus.Cases {
		if tc.ID == "" || tc.Name == "" || tc.Class == "" || tc.Coverage == "" || tc.Gate == "" || tc.Expect == "" {
			t.Fatalf("incomplete corpus case: %+v", tc)
		}
		if seen[tc.ID] {
			t.Fatalf("duplicate case id %s", tc.ID)
		}
		seen[tc.ID] = true
		coverage[tc.Coverage]++

		if tc.Gate != "origin" {
			continue
		}
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
		executedOrigin++
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
	if coverage["EXECUTABLE_NOW"] != 3 ||
		coverage["PLANNED"] != 7 ||
		coverage["EXISTING_COVERAGE"] != 4 ||
		coverage["PARTIAL_EXISTING"] != 2 {
		t.Fatalf("unexpected coverage accounting: %+v", coverage)
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
