package main

import (
	"os"
	"path/filepath"
	"testing"

	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

func TestLoadEvidenceIndependenceProfile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	body := []byte(`{
  "required_independence": "ASSERTED",
  "min_independent_sources": 2,
  "required_dependency_kinds": ["upstream", "credential"],
  "source_declarations": {
    "primary": {
      "producer_id": "producer:primary",
      "observation_path": "path:primary",
      "dependency_coverage": ["credential", "upstream"],
      "dependencies": [
        {"kind": "upstream", "id": "upstream:a", "material": true},
        {"kind": "credential", "id": "credential:a", "material": true}
      ],
      "assurance": "ASSERTED"
    }
  }
}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	profile, err := loadEvidenceIndependenceProfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if profile == nil {
		t.Fatal("expected profile")
	}
	if profile.RequiredIndependence != egeproto.EvidenceIndependenceAsserted {
		t.Fatalf("required independence = %s", profile.RequiredIndependence)
	}
	if profile.MinIndependentSources != 2 {
		t.Fatalf("min independent sources = %d", profile.MinIndependentSources)
	}
	if profile.SourceDeclarations["primary"].ProducerID != "producer:primary" {
		t.Fatalf("unexpected declaration: %+v", profile.SourceDeclarations["primary"])
	}
}

func TestLoadEvidenceIndependenceProfileRejectsUnknownFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadEvidenceIndependenceProfile(path); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}
