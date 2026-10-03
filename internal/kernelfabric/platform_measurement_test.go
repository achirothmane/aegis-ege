package kernelfabric

import "testing"

func TestPlatformMeasurementCommitmentStableAcrossGeneration(t *testing.T) {
	platform := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	measurement := "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	a, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		platform,
		measurement,
		7,
	)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		platform,
		measurement,
		8,
	)
	if err != nil {
		t.Fatal(err)
	}
	if a.CommitmentDigest != b.CommitmentDigest {
		t.Fatalf("unchanged platform measurement should remain stable across unrelated monotonic generation: %s != %s", a.CommitmentDigest, b.CommitmentDigest)
	}
	if a.VerifiedGeneration == b.VerifiedGeneration {
		t.Fatal("expected audit generation to preserve observed monotonic state")
	}
}

func TestPlatformMeasurementCommitmentChangesWithMeasurement(t *testing.T) {
	platform := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	a, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		platform,
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		7,
	)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		platform,
		"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		7,
	)
	if err != nil {
		t.Fatal(err)
	}
	if a.CommitmentDigest == b.CommitmentDigest {
		t.Fatal("different platform measurements must produce different commitments")
	}
}

func TestPlatformMeasurementCommitmentRejectsInvalidInput(t *testing.T) {
	if _, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		"not-a-digest",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		1,
	); err == nil {
		t.Fatal("invalid platform identity digest must be rejected")
	}
	if _, err := NewPlatformMeasurementCommitment(
		PlatformMeasurementClassMeasuredBoot,
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		0,
	); err == nil {
		t.Fatal("zero verified generation must be rejected")
	}
}
