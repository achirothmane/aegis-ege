//go:build linux && cgo

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/decision"
	"github.com/achirothmane/aegis-ege/internal/kubeadapter"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func migrationRemoteDecisionDigest(label string) string {
	sum := sha256.Sum256([]byte(label))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func signMigrationDestinationAttestationForTest(
	t *testing.T,
	migrationID string,
	state tpmNVRootState,
	now time.Time,
	privateKey ed25519.PrivateKey,
) SignedTPMRootMigrationDestinationAttestation {
	t.Helper()
	signed, err := SignTPMRootMigrationDestinationAttestation(
		TPMRootMigrationDestinationAttestation{
			Version:                         TPMRootMigrationDestinationAttestationVersion,
			AttestationID:                   "attestation-" + migrationID,
			MigrationID:                     migrationID,
			EnrolledDeviceID:                "node-b",
			DestinationDeviceIdentity:       state.DeviceIdentity,
			DestinationMeasuredBootIdentity: state.MeasuredBootIdentity,
			DestinationGeneration:           state.Generation,
			RemoteDecisionID:                "remote-decision-" + migrationID,
			RemoteChallengeID:               "remote-challenge-" + migrationID,
			RemoteDecisionDigest:            migrationRemoteDecisionDigest("remote-allow-" + migrationID),
			RemoteDecisionVerifiedAt:        now.Add(-30 * time.Second),
			Decision:                        "ALLOW",
			VerifiedAt:                      now.Add(-20 * time.Second),
			ExpiresAt:                       now.Add(30 * time.Second),
			VerifierID:                      "remote-attestation-authority",
		},
		privateKey,
	)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestTPMRootAuthorizedMigrationPreservesExactAuthorityAndRejectsReplay(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	simA, err := simulator.GetWithFixedSeedInsecure(301)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A151),
		StatePath: filepath.Join(dir, "root-a.json"),
		IndexAuth: []byte("aegis-root-migration-test"),
	}
	if err := ProvisionTPMNVMonotonicRoot(ctx, deviceA, cfgA); err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	rootA, err := NewTPMNVMonotonicRoot(deviceA, cfgA)
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}

	now := time.Date(2026, 10, 3, 2, 0, 0, 0, time.UTC)
	controller := &fakeController{
		preparation: capabilityTestPreparation(now),
		report: kubeadapter.GuardedDrainExecutionReport{
			Decision:   decision.Allow,
			PlanDigest: "sha256:plan",
		},
	}
	t1Issue := CapabilityFenceIssue{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   7,
		DecisionEpoch:   31,
		RevocationEpoch: 4,
	}
	t1 := capabilityAuthoritySnapshotFromIssue(t1Issue)
	mutable := &dualMutableCapabilityFenceAuthority{
		issue:        t1Issue,
		coordination: t1,
		witness:      t1,
	}
	authority, err := NewIndependentRootCapabilityAuthority(mutable, rootA)
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	replay, err := NewFileReplayGuard(filepath.Join(dir, "replay"))
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	srv, err := New(
		controller,
		kubeadapter.NewMemoryDrainCheckpointStore(),
		Config{
			MutationsEnabled:         true,
			RequireAuthentication:    true,
			Authorizer:               allowAuthorizer{},
			ReplayGuard:              replay,
			RequireCapabilityFencing: true,
			CapabilityFenceAuthority: authority,
		},
	)
	if err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}

	permitT1 := prepareRootedCapabilityPermit(t, srv)
	source, ok, err := readTPMNVRootState(cfgA.StatePath)
	if err != nil || !ok {
		_ = simA.Close()
		t.Fatalf("read source root state: ok=%t err=%v", ok, err)
	}
	if len(source.Scopes) == 0 {
		_ = simA.Close()
		t.Fatal("source migration state has no authority scopes")
	}
	if err := simA.Close(); err != nil {
		t.Fatalf("close TPM-A simulator: %v", err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(302)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	deviceB := transport.FromReadWriter(simB)
	cfgB := cfgA
	cfgB.StatePath = filepath.Join(dir, "root-b.json")
	if err := ProvisionTPMNVMonotonicRoot(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	rootB, err := NewTPMNVMonotonicRoot(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	destinationBefore, ok, err := readTPMNVRootState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read destination root state: ok=%t err=%v", ok, err)
	}
	if source.DeviceIdentity == destinationBefore.DeviceIdentity {
		t.Fatalf("source and destination unexpectedly share device identity: %s", source.DeviceIdentity)
	}
	counterBefore, err := rootB.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}

	migrationPub, migrationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPub, attestationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	migrationID := "migration-a-to-b-1"
	goodAttestation := signMigrationDestinationAttestationForTest(
		t, migrationID, destinationBefore, now, attestationPriv,
	)
	goodAttestationDigest, err := TPMRootMigrationDestinationAttestationDigest(goodAttestation)
	if err != nil {
		t.Fatal(err)
	}

	baseAuth := TPMRootMigrationAuthorization{
		Version:                      TPMRootMigrationAuthorizationVersion,
		MigrationID:                  migrationID,
		SourceDeviceIdentity:         source.DeviceIdentity,
		SourceStateDigest:            source.Digest,
		SourceGeneration:             source.Generation,
		DestinationDeviceIdentity:    destinationBefore.DeviceIdentity,
		DestinationGeneration:        destinationBefore.Generation,
		DestinationNVIndex:           uint32(cfgB.NVIndex),
		DestinationAttestationDigest: goodAttestationDigest,
		NotBefore:                    now.Add(-time.Minute),
		ExpiresAt:                    now.Add(5 * time.Minute),
	}

	assertCounterUnchanged := func(t *testing.T) {
		t.Helper()
		got, err := rootB.readCounter(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if got != counterBefore {
			t.Fatalf("rejected migration changed destination counter: before=%d after=%d", counterBefore, got)
		}
	}

	t.Run("same_authority_rejected", func(t *testing.T) {
		sameKeyAttestation := signMigrationDestinationAttestationForTest(
			t, migrationID, destinationBefore, now, migrationPriv,
		)
		digest, err := TPMRootMigrationDestinationAttestationDigest(sameKeyAttestation)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			sameKeyAttestation, migrationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
			t.Fatalf("same migration/attestation authority should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("measured_boot_mismatch_rejected", func(t *testing.T) {
		mismatchedState := destinationBefore
		mismatchedState.MeasuredBootIdentity = "sha256:" + strings.Repeat("22", 32)
		att := signMigrationDestinationAttestationForTest(
			t, migrationID, mismatchedState, now, attestationPriv,
		)
		digest, err := TPMRootMigrationDestinationAttestationDigest(att)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			att, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationDestinationAttestation) {
			t.Fatalf("mismatched live measured boot should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("stale_remote_decision_rejected", func(t *testing.T) {
		attestation := goodAttestation.Attestation
		attestation.AttestationID = "attestation-stale-remote-decision"
		attestation.RemoteDecisionID = "remote-decision-stale"
		attestation.RemoteChallengeID = "remote-challenge-stale"
		attestation.RemoteDecisionVerifiedAt = now.Add(-3 * time.Minute)
		attestation.VerifiedAt = now.Add(-30 * time.Second)
		attestation.ExpiresAt = now.Add(30 * time.Second)
		att, err := SignTPMRootMigrationDestinationAttestation(attestation, attestationPriv)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TPMRootMigrationDestinationAttestationDigest(att)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			att, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationDestinationAttestationStale) {
			t.Fatalf("stale remote decision should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("freshness_extension_rejected", func(t *testing.T) {
		attestation := goodAttestation.Attestation
		attestation.AttestationID = "attestation-freshness-extension"
		attestation.RemoteDecisionID = "remote-decision-extension"
		attestation.RemoteChallengeID = "remote-challenge-extension"
		attestation.RemoteDecisionVerifiedAt = now.Add(-90 * time.Second)
		attestation.VerifiedAt = now.Add(-20 * time.Second)
		attestation.ExpiresAt = now.Add(60 * time.Second)
		att, err := SignTPMRootMigrationDestinationAttestation(attestation, attestationPriv)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TPMRootMigrationDestinationAttestationDigest(att)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			att, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationDestinationAttestationStale) {
			t.Fatalf("bridge that extends remote decision freshness should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("future_remote_decision_rejected", func(t *testing.T) {
		attestation := goodAttestation.Attestation
		attestation.AttestationID = "attestation-future-remote-decision"
		attestation.RemoteDecisionID = "remote-decision-future"
		attestation.RemoteChallengeID = "remote-challenge-future"
		attestation.RemoteDecisionVerifiedAt = now.Add(10 * time.Second)
		attestation.VerifiedAt = now
		attestation.ExpiresAt = now.Add(30 * time.Second)
		att, err := SignTPMRootMigrationDestinationAttestation(attestation, attestationPriv)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TPMRootMigrationDestinationAttestationDigest(att)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			att, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationDestinationAttestationStale) {
			t.Fatalf("future remote decision should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("destination_generation_mismatch_rejected", func(t *testing.T) {
		attestation := goodAttestation.Attestation
		attestation.AttestationID = "attestation-wrong-generation"
		attestation.DestinationGeneration = destinationBefore.Generation + 1
		att, err := SignTPMRootMigrationDestinationAttestation(attestation, attestationPriv)
		if err != nil {
			t.Fatal(err)
		}
		digest, err := TPMRootMigrationDestinationAttestationDigest(att)
		if err != nil {
			t.Fatal(err)
		}
		auth := baseAuth
		auth.DestinationAttestationDigest = digest
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			att, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
			t.Fatalf("wrong attested destination generation should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("expired_authorization_rejected", func(t *testing.T) {
		auth := baseAuth
		auth.NotBefore = now.Add(-10 * time.Minute)
		auth.ExpiresAt = now.Add(-time.Minute)
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			goodAttestation, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
			t.Fatalf("expired migration should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("forged_authorization_rejected", func(t *testing.T) {
		signed, err := SignTPMRootMigrationAuthorization(baseAuth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		signed.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			goodAttestation, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
			t.Fatalf("forged migration should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	t.Run("wrong_destination_rejected", func(t *testing.T) {
		auth := baseAuth
		auth.DestinationDeviceIdentity = "sha256:" + strings.Repeat("11", 32)
		signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			goodAttestation, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
			t.Fatalf("wrong destination authorization should fail closed, got %v", err)
		}
		assertCounterUnchanged(t)
	})

	var signed SignedTPMRootMigrationAuthorization
	t.Run("authorized_migration_succeeds", func(t *testing.T) {
		var err error
		signed, err = SignTPMRootMigrationAuthorization(baseAuth, migrationPriv)
		if err != nil {
			t.Fatal(err)
		}
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			goodAttestation, attestationPub, now,
		); err != nil {
			t.Fatalf("authorized migration failed: %v", err)
		}
	})

	migrated, ok, err := readTPMNVRootState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read migrated root state: ok=%t err=%v", ok, err)
	}
	if migrated.DeviceIdentity != destinationBefore.DeviceIdentity {
		t.Fatalf("migration changed destination identity: got=%s want=%s", migrated.DeviceIdentity, destinationBefore.DeviceIdentity)
	}
	if migrated.PredecessorDeviceIdentity != source.DeviceIdentity {
		t.Fatalf("missing predecessor device identity: got=%s want=%s", migrated.PredecessorDeviceIdentity, source.DeviceIdentity)
	}
	if migrated.MigrationSourceStateDigest != source.Digest {
		t.Fatalf("source state digest lineage mismatch: got=%s want=%s", migrated.MigrationSourceStateDigest, source.Digest)
	}
	commitment, err := TPMRootMigrationAuthorizationDigest(signed)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.MigrationAuthorizationDigest != commitment {
		t.Fatalf("migration authorization commitment mismatch: got=%s want=%s", migrated.MigrationAuthorizationDigest, commitment)
	}
	if migrated.MigrationDestinationAttestationDigest != goodAttestationDigest {
		t.Fatalf("destination attestation commitment mismatch: got=%s want=%s", migrated.MigrationDestinationAttestationDigest, goodAttestationDigest)
	}
	if migrated.Generation != destinationBefore.Generation+1 {
		t.Fatalf("destination generation did not advance exactly once: got=%d want=%d", migrated.Generation, destinationBefore.Generation+1)
	}
	if len(migrated.Scopes) != len(source.Scopes) {
		t.Fatalf("migrated scope count mismatch: got=%d want=%d", len(migrated.Scopes), len(source.Scopes))
	}
	for key, want := range source.Scopes {
		if got, ok := migrated.Scopes[key]; !ok || got != want {
			t.Fatalf("migrated authority scope %s mismatch: got=%+v want=%+v", key, got, want)
		}
	}

	t.Run("replay_rejected", func(t *testing.T) {
		if err := MigrateTPMNVMonotonicRoot(
			ctx, cfgA.StatePath, rootB, signed, migrationPub,
			goodAttestation, attestationPub, now,
		); !errors.Is(err, ErrTPMRootMigrationReplay) {
			t.Fatalf("replayed migration authorization should fail closed, got %v", err)
		}
	})

	t.Run("continuity_preserved", func(t *testing.T) {
		authority.Root = rootB
		recorder := executeRootedCapabilityPermit(t, srv, permitT1)
		if recorder.Code != http.StatusOK {
			t.Fatalf("exact authority continuity should survive authorized migration: got=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if controller.executeCalls != 1 {
			t.Fatalf("authorized migration expected exactly one mutation controller call, got %d", controller.executeCalls)
		}
	})
}
