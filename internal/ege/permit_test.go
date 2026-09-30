package ege

import (
	"context"
	"testing"
	"time"
)

func TestSignedPermitRejectsTampering(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	claims := PermitClaims{
		IntentID:               "intent-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		ValidUntil:             time.Now().UTC().Add(time.Minute),
	}
	permit, err := SignPermit(context.Background(), authority, claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPermit(context.Background(), authority, permit); err != nil {
		t.Fatalf("valid permit rejected: %v", err)
	}

	permit.Claims.PlanDigest = "sha256:tampered"
	if err := VerifyPermit(context.Background(), authority, permit); err == nil {
		t.Fatal("tampered permit unexpectedly verified")
	}
}

func TestEvidenceManifestDigestIsStableAcrossEvidenceClassOrder(t *testing.T) {
	observedAt := time.Date(2026, 9, 25, 15, 0, 0, 0, time.UTC)
	left := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        "intent-1",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-7"},
		ResourceVersion: "100",
		EvidenceDigest:  "sha256:evidence",
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"server-dry-run", "state", "pdb"},
	}
	right := left
	right.EvidenceClasses = []string{"pdb", "server-dry-run", "state"}

	leftDigest, err := DigestEvidenceManifest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := DigestEvidenceManifest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("manifest digest changed with evidence class order: %s != %s", leftDigest, rightDigest)
	}
}


func TestEvidenceManifestDigestIsStableAcrossSourceOrder(t *testing.T) {
	observedAt := time.Date(2026, 9, 26, 20, 0, 0, 0, time.UTC)
	left := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        "intent-2",
		Kind:            "kubernetes.node_drain",
		Target:          Target{Type: "kubernetes.node", Name: "node-9"},
		ResourceVersion: "200",
		EvidenceDigest:  "sha256:primary",
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"state", "telemetry"},
		Sources: []EvidenceSource{
			{
				Name:        "primary",
				TrustDomain: "control-plane",
				Digest:      "sha256:primary",
				ObservedAt:  observedAt,
				Classes:     []string{"state", "dry-run"},
			},
			{
				Name:        "telemetry",
				TrustDomain: "telemetry-plane",
				Digest:      "sha256:telemetry",
				ObservedAt:  observedAt.Add(-time.Second),
				Classes:     []string{"latency", "health"},
			},
		},
	}

	right := left
	right.Sources = []EvidenceSource{
		{
			Name:        "telemetry",
			TrustDomain: "telemetry-plane",
			Digest:      "sha256:telemetry",
			ObservedAt:  observedAt.Add(-time.Second),
			Classes:     []string{"health", "latency"},
		},
		{
			Name:        "primary",
			TrustDomain: "control-plane",
			Digest:      "sha256:primary",
			ObservedAt:  observedAt,
			Classes:     []string{"dry-run", "state"},
		},
	}

	leftDigest, err := DigestEvidenceManifest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := DigestEvidenceManifest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("manifest digest changed with source order: %s != %s", leftDigest, rightDigest)
	}
}


func TestEvidenceManifestDigestCanonicalizesIndependenceDeclarations(t *testing.T) {
	observedAt := time.Date(2026, 9, 29, 21, 0, 0, 0, time.UTC)
	left := EvidenceManifest{
		APIVersion:      EvidenceManifestVersion,
		IntentID:        "intent-c09-digest",
		Kind:            "test.mutate",
		Target:          Target{Type: "test.resource", Name: "r-1"},
		ResourceVersion: "7",
		EvidenceDigest:  "sha256:primary",
		PlanDigest:      "sha256:plan",
		ObservedAt:      observedAt,
		EvidenceClasses: []string{"telemetry", "state"},
		Sources: []EvidenceSource{
			{
				Name:        "primary",
				TrustDomain: "control",
				Digest:      "sha256:primary",
				ObservedAt:  observedAt,
				Classes:     []string{"state"},
				Declaration: &EvidenceSourceDeclaration{
					ProducerID:         "producer:primary",
					Subject:            "test.resource/r-1",
					ObservationPath:    "path:primary",
					DependencyCoverage: []string{"upstream", "credential"},
					Dependencies: []EvidenceDependency{
						{Kind: "upstream", ID: "u-primary", Material: true},
						{Kind: "credential", ID: "c-primary", Material: true},
					},
					Assurance:         EvidenceDeclarationAsserted,
					CorroborationRefs: []string{"ref:b", "ref:a"},
				},
			},
			{
				Name:        "telemetry",
				TrustDomain: "telemetry",
				Digest:      "sha256:telemetry",
				ObservedAt:  observedAt.Add(-time.Second),
				Classes:     []string{"telemetry"},
				Declaration: &EvidenceSourceDeclaration{
					ProducerID:         "producer:telemetry",
					Subject:            "test.resource/r-1",
					ObservationPath:    "path:telemetry",
					DependencyCoverage: []string{"credential", "upstream"},
					Dependencies: []EvidenceDependency{
						{Kind: "credential", ID: "c-telemetry", Material: true},
						{Kind: "upstream", ID: "u-telemetry", Material: true},
					},
					Assurance: EvidenceDeclarationAsserted,
				},
			},
		},
		Composition: &EvidenceCompositionAssessment{
			ProfileVersion:         EvidenceCompositionProfileVersion,
			RequiredIndependence:   EvidenceIndependenceAsserted,
			IndependentSourceCount: 2,
			OverallIndependence:    EvidenceIndependenceAsserted,
			PairAssessments: []EvidencePairAssessment{
				{
					LeftSource:  "primary",
					RightSource: "telemetry",
					Status:      EvidenceIndependenceAsserted,
					ReasonCodes: []string{"z", "a"},
				},
			},
		},
	}
	right := left
	right.Sources = []EvidenceSource{left.Sources[1], left.Sources[0]}
	right.Sources[1].Declaration = &EvidenceSourceDeclaration{
		ProducerID:         "producer:primary",
		Subject:            "test.resource/r-1",
		ObservationPath:    "path:primary",
		DependencyCoverage: []string{"credential", "upstream"},
		Dependencies: []EvidenceDependency{
			{Kind: "credential", ID: "c-primary", Material: true},
			{Kind: "upstream", ID: "u-primary", Material: true},
		},
		Assurance:         EvidenceDeclarationAsserted,
		CorroborationRefs: []string{"ref:a", "ref:b"},
	}
	right.EvidenceClasses = []string{"state", "telemetry"}
	right.Composition = &EvidenceCompositionAssessment{
		ProfileVersion:         EvidenceCompositionProfileVersion,
		RequiredIndependence:   EvidenceIndependenceAsserted,
		IndependentSourceCount: 2,
		OverallIndependence:    EvidenceIndependenceAsserted,
		PairAssessments: []EvidencePairAssessment{
			{
				LeftSource:  "primary",
				RightSource: "telemetry",
				Status:      EvidenceIndependenceAsserted,
				ReasonCodes: []string{"a", "z"},
			},
		},
	}

	leftDigest, err := DigestEvidenceManifest(left)
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := DigestEvidenceManifest(right)
	if err != nil {
		t.Fatal(err)
	}
	if leftDigest != rightDigest {
		t.Fatalf("manifest digest changed with declaration ordering: %s != %s", leftDigest, rightDigest)
	}
}

func TestSignedPermitRejectsCapabilityFenceTampering(t *testing.T) {
	authority, err := NewEphemeralEd25519Authority()
	if err != nil {
		t.Fatal(err)
	}
	state := testCapabilityStateBinding()
	stateDigest, err := DigestCapabilityStateBinding(state)
	if err != nil {
		t.Fatal(err)
	}
	claims := PermitClaims{
		IntentID:               "intent-cap-1",
		Kind:                   "kubernetes.node_drain",
		Target:                 Target{Type: "kubernetes.node", Name: "node-7"},
		Action:                 "drain",
		ResourceVersion:        "100",
		EvidenceDigest:         "sha256:evidence",
		EvidenceManifestDigest: "sha256:manifest",
		PlanDigest:             "sha256:plan",
		CapabilityFence: &CapabilityFenceClaims{
			Version:            CapabilityFenceVersion,
			AuthorityDomain:    "cluster-a/control-plane",
			AuthorityTerm:      5,
			DecisionEpoch:      9,
			RevocationEpoch:    2,
			TargetIdentity:     "uid-7",
			StateBindingDigest: stateDigest,
		},
		ValidUntil: time.Now().UTC().Add(time.Minute),
	}
	permit, err := SignPermit(context.Background(), authority, claims)
	if err != nil {
		t.Fatal(err)
	}
	permit.Claims.CapabilityFence.DecisionEpoch++
	if err := VerifyPermit(context.Background(), authority, permit); err == nil {
		t.Fatal("tampered capability fence unexpectedly verified")
	}
}
