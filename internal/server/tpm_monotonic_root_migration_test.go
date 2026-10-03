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
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
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
			RemoteDecisionDigest:            migrationRemoteDecisionDigest("remote-allow-" + migrationID),
			Decision:                        "ALLOW",
			VerifiedAt:                      now.Add(-time.Minute),
			ExpiresAt:                       now.Add(5 * time.Minute),
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
	if counterBefore != destinationBefore.Generation {
		t.Fatalf("fresh destination counter/state mismatch: counter=%d generation=%d", counterBefore, destinationBefore.Generation)
	}

	migrationPub, migrationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	attestationPub, attestationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	destinationAttestation := signMigrationDestinationAttestationForTest(
		t, "migration-a-to-b-1", destinationBefore, now, attestationPriv,
	)
	attestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		t.Fatal(err)
	}

	auth := TPMRootMigrationAuthorization{
		Version:                      TPMRootMigrationAuthorizationVersion,
		MigrationID:                  "migration-a-to-b-1",
		SourceDeviceIdentity:         source.DeviceIdentity,
		SourceStateDigest:            source.Digest,
		SourceGeneration:             source.Generation,
		DestinationDeviceIdentity:    destinationBefore.DeviceIdentity,
		DestinationGeneration:        destinationBefore.Generation,
		DestinationNVIndex:           uint32(cfgB.NVIndex),
		DestinationAttestationDigest: attestationDigest,
		NotBefore:                    now.Add(-time.Minute),
		ExpiresAt:                    now.Add(5 * time.Minute),
	}
	signed, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}

	wrong := auth
	wrong.MigrationID = "migration-wrong-destination"
	wrong.DestinationDeviceIdentity = "sha256:" + strings.Repeat("11", 32)
	wrongSigned, err := SignTPMRootMigrationAuthorization(wrong, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, wrongSigned, migrationPub,
		destinationAttestation, attestationPub, now,
	); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
		t.Fatalf("wrong destination authorization should fail closed, got %v", err)
	}
	counterAfterWrong, err := rootB.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counterAfterWrong != counterBefore {
		t.Fatalf("rejected migration changed destination counter: before=%d after=%d", counterBefore, counterAfterWrong)
	}

	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, signed, migrationPub,
		destinationAttestation, attestationPub, now,
	); err != nil {
		t.Fatalf("authorized migration failed: %v", err)
	}
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
	if migrated.MigrationDestinationAttestationDigest != attestationDigest {
		t.Fatalf("destination attestation commitment mismatch: got=%s want=%s", migrated.MigrationDestinationAttestationDigest, attestationDigest)
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

	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, signed, migrationPub,
		destinationAttestation, attestationPub, now,
	); !errors.Is(err, ErrTPMRootMigrationReplay) {
		t.Fatalf("replayed migration authorization should fail closed, got %v", err)
	}

	authority.Root = rootB
	recorder := executeRootedCapabilityPermit(t, srv, permitT1)
	if recorder.Code != http.StatusOK {
		t.Fatalf("exact authority continuity should survive authorized migration: got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if controller.executeCalls != 1 {
		t.Fatalf("authorized migration expected exactly one mutation controller call, got %d", controller.executeCalls)
	}
}

func TestTPMRootMigrationRejectsExpiredAndForgedAuthorization(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()

	simA, err := simulator.GetWithFixedSeedInsecure(401)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A152),
		StatePath: filepath.Join(dir, "root-a.json"),
		IndexAuth: []byte("aegis-root-migration-expiry-test"),
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
	scope := CapabilityFenceScope{
		IntentID: "intent-migration-expiry",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-9"},
	}
	snapshot := egeproto.CapabilityAuthoritySnapshot{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   9,
		DecisionEpoch:   41,
		RevocationEpoch: 2,
	}
	if _, err := rootA.Advance(ctx, scope, snapshot); err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	source, ok, err := readTPMNVRootState(cfgA.StatePath)
	if err != nil || !ok {
		_ = simA.Close()
		t.Fatalf("read source state: ok=%t err=%v", ok, err)
	}
	if err := simA.Close(); err != nil {
		t.Fatal(err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(402)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	cfgB := cfgA
	cfgB.StatePath = filepath.Join(dir, "root-b.json")
	deviceB := transport.FromReadWriter(simB)
	if err := ProvisionTPMNVMonotonicRoot(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	rootB, err := NewTPMNVMonotonicRoot(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	dest, ok, err := readTPMNVRootState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read destination state: ok=%t err=%v", ok, err)
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
	now := time.Date(2026, 10, 3, 2, 30, 0, 0, time.UTC)
	destinationAttestation := signMigrationDestinationAttestationForTest(
		t, "migration-expired", dest, now, attestationPriv,
	)
	attestationDigest, err := TPMRootMigrationDestinationAttestationDigest(destinationAttestation)
	if err != nil {
		t.Fatal(err)
	}
	auth := TPMRootMigrationAuthorization{
		Version:                      TPMRootMigrationAuthorizationVersion,
		MigrationID:                  "migration-expired",
		SourceDeviceIdentity:         source.DeviceIdentity,
		SourceStateDigest:            source.Digest,
		SourceGeneration:             source.Generation,
		DestinationDeviceIdentity:    dest.DeviceIdentity,
		DestinationGeneration:        dest.Generation,
		DestinationNVIndex:           uint32(cfgB.NVIndex),
		DestinationAttestationDigest: attestationDigest,
		NotBefore:                    now.Add(-10 * time.Minute),
		ExpiresAt:                    now.Add(-time.Minute),
	}
	expired, err := SignTPMRootMigrationAuthorization(auth, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, expired, migrationPub,
		destinationAttestation, attestationPub, now,
	); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
		t.Fatalf("expired migration should fail closed, got %v", err)
	}

	validAuth := auth
	validAuth.NotBefore = now.Add(-time.Minute)
	validAuth.ExpiresAt = now.Add(time.Minute)
	forged, err := SignTPMRootMigrationAuthorization(validAuth, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}
	forged.Signature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, forged, migrationPub,
		destinationAttestation, attestationPub, now,
	); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
		t.Fatalf("forged migration should fail closed, got %v", err)
	}
	counterAfter, err := rootB.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counterAfter != counterBefore {
		t.Fatalf("rejected authorizations changed destination counter: before=%d after=%d", counterBefore, counterAfter)
	}
}

func TestTPMRootMigrationRequiresIndependentLiveDestinationAttestation(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	now := time.Date(2026, 10, 3, 3, 0, 0, 0, time.UTC)

	simA, err := simulator.GetWithFixedSeedInsecure(501)
	if err != nil {
		t.Fatalf("start TPM-A simulator: %v", err)
	}
	deviceA := transport.FromReadWriter(simA)
	cfgA := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A153),
		StatePath: filepath.Join(dir, "root-a.json"),
		IndexAuth: []byte("aegis-root-migration-attestation-test"),
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
	scope := CapabilityFenceScope{
		IntentID: "intent-migration-attested",
		Kind:     egeNodeDrainKind,
		Target:   egeproto.Target{Type: egeNodeTarget, Name: "node-attested"},
	}
	snapshot := egeproto.CapabilityAuthoritySnapshot{
		AuthorityDomain: "cluster-a/control-plane",
		AuthorityTerm:   11,
		DecisionEpoch:   51,
		RevocationEpoch: 3,
	}
	if _, err := rootA.Advance(ctx, scope, snapshot); err != nil {
		_ = simA.Close()
		t.Fatal(err)
	}
	source, ok, err := readTPMNVRootState(cfgA.StatePath)
	if err != nil || !ok {
		_ = simA.Close()
		t.Fatalf("read source root state: ok=%t err=%v", ok, err)
	}
	if err := simA.Close(); err != nil {
		t.Fatal(err)
	}

	simB, err := simulator.GetWithFixedSeedInsecure(502)
	if err != nil {
		t.Fatalf("start TPM-B simulator: %v", err)
	}
	defer simB.Close()
	cfgB := cfgA
	cfgB.StatePath = filepath.Join(dir, "root-b.json")
	deviceB := transport.FromReadWriter(simB)
	if err := ProvisionTPMNVMonotonicRoot(ctx, deviceB, cfgB); err != nil {
		t.Fatal(err)
	}
	rootB, err := NewTPMNVMonotonicRoot(deviceB, cfgB)
	if err != nil {
		t.Fatal(err)
	}
	dest, ok, err := readTPMNVRootState(cfgB.StatePath)
	if err != nil || !ok {
		t.Fatalf("read destination state: ok=%t err=%v", ok, err)
	}
	counterBefore, err := rootB.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}

	migrationPub, migrationPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	independentPub, independentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	sameKeyAttestation := signMigrationDestinationAttestationForTest(
		t, "migration-independent-check", dest, now, migrationPriv,
	)
	sameKeyDigest, err := TPMRootMigrationDestinationAttestationDigest(sameKeyAttestation)
	if err != nil {
		t.Fatal(err)
	}
	sameKeyAuth := TPMRootMigrationAuthorization{
		Version:                      TPMRootMigrationAuthorizationVersion,
		MigrationID:                  "migration-independent-check",
		SourceDeviceIdentity:         source.DeviceIdentity,
		SourceStateDigest:            source.Digest,
		SourceGeneration:             source.Generation,
		DestinationDeviceIdentity:    dest.DeviceIdentity,
		DestinationGeneration:        dest.Generation,
		DestinationNVIndex:           uint32(cfgB.NVIndex),
		DestinationAttestationDigest: sameKeyDigest,
		NotBefore:                    now.Add(-time.Minute),
		ExpiresAt:                    now.Add(5 * time.Minute),
	}
	sameKeySigned, err := SignTPMRootMigrationAuthorization(sameKeyAuth, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, sameKeySigned, migrationPub,
		sameKeyAttestation, migrationPub, now,
	); !errors.Is(err, ErrTPMRootMigrationAuthorization) {
		t.Fatalf("same authority for migration and attestation should fail closed, got %v", err)
	}

	mismatchedState := dest
	mismatchedState.MeasuredBootIdentity = "sha256:" + strings.Repeat("22", 32)
	mismatchedAttestation := signMigrationDestinationAttestationForTest(
		t, "migration-live-binding-check", mismatchedState, now, independentPriv,
	)
	mismatchedDigest, err := TPMRootMigrationDestinationAttestationDigest(mismatchedAttestation)
	if err != nil {
		t.Fatal(err)
	}
	mismatchedAuth := sameKeyAuth
	mismatchedAuth.MigrationID = "migration-live-binding-check"
	mismatchedAuth.DestinationAttestationDigest = mismatchedDigest
	mismatchedSigned, err := SignTPMRootMigrationAuthorization(mismatchedAuth, migrationPriv)
	if err != nil {
		t.Fatal(err)
	}
	if err := MigrateTPMNVMonotonicRoot(
		ctx, cfgA.StatePath, rootB, mismatchedSigned, migrationPub,
		mismatchedAttestation, independentPub, now,
	); !errors.Is(err, ErrTPMRootMigrationDestinationAttestation) {
		t.Fatalf("attestation that does not match live measured boot should fail closed, got %v", err)
	}

	counterAfter, err := rootB.readCounter(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if counterAfter != counterBefore {
		t.Fatalf("rejected destination evidence changed TPM-B counter: before=%d after=%d", counterBefore, counterAfter)
	}
}
