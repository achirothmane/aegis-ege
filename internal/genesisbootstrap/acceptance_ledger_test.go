package genesisbootstrap

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/achirothmane/easl/genesis"
)

func TestAcceptanceLedgerPersistsAcrossRestartAndIsIdempotent(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	now := time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC)
	manifest := acceptanceTestManifest(7, 0, "", 3, digestString("d"), 7)
	revocations := acceptanceTestRevocations(4)
	candidate := mustAcceptanceCandidate(t, manifest, revocations, now)

	ledger := mustAcceptanceLedger(t, path)
	session, floor, err := ledger.Begin(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if floor.GenesisEpoch != 0 {
		t.Fatalf("unexpected initial floor: %+v", floor)
	}
	if err := session.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	restarted := mustAcceptanceLedger(t, path)
	session, floor, err = restarted.Begin(context.Background(), candidate)
	if err != nil {
		t.Fatalf("restart Begin() error = %v", err)
	}
	if floor.GenesisEpoch != 7 || floor.Sequence != 0 || floor.ManifestHash != candidate.ManifestHash {
		t.Fatalf("unexpected persisted floor: %+v", floor)
	}
	if err := session.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(strings.Split(strings.TrimSpace(string(payload)), "\n")); got != 1 {
		t.Fatalf("idempotent restart appended %d records, want 1", got)
	}
}

func TestAcceptanceLedgerRequiresExactManifestLineage(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	now := time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC)
	revocations := acceptanceTestRevocations(4)

	firstManifest := acceptanceTestManifest(7, 0, "", 3, digestString("d"), 7)
	first := mustAcceptanceCandidate(t, firstManifest, revocations, now)
	acceptCandidate(t, path, first)

	successorManifest := acceptanceTestManifest(7, 1, first.ManifestHash, 3, digestString("d"), 7)
	successorManifest.Authenticity.Signature = "successor-signature"
	successor := mustAcceptanceCandidate(t, successorManifest, acceptanceTestRevocations(5), now.Add(time.Minute))
	acceptCandidate(t, path, successor)

	rollback := first
	if _, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), rollback); !errors.Is(err, ErrAcceptanceRollback) {
		t.Fatalf("rollback error = %v, want %v", err, ErrAcceptanceRollback)
	}

	wrongParentManifest := acceptanceTestManifest(7, 2, digestString("wrong"), 3, digestString("d"), 7)
	wrongParent := mustAcceptanceCandidate(t, wrongParentManifest, acceptanceTestRevocations(6), now.Add(2*time.Minute))
	if _, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), wrongParent); !errors.Is(err, ErrAcceptanceContinuity) {
		t.Fatalf("wrong parent error = %v, want %v", err, ErrAcceptanceContinuity)
	}

	equivocationManifest := successorManifest
	equivocationManifest.Authenticity.Signature = "different-manifest-at-same-sequence"
	equivocation := mustAcceptanceCandidate(t, equivocationManifest, acceptanceTestRevocations(5), now.Add(3*time.Minute))
	if _, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), equivocation); !errors.Is(err, ErrAcceptanceContinuity) {
		t.Fatalf("equivocation error = %v, want %v", err, ErrAcceptanceContinuity)
	}
}

func TestAcceptanceLedgerRejectsDoctrineRevocationAndTrustRootRollback(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	now := time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC)
	firstManifest := acceptanceTestManifest(8, 0, "", 5, digestString("d"), 9)
	first := mustAcceptanceCandidate(t, firstManifest, acceptanceTestRevocations(10), now)
	acceptCandidate(t, path, first)

	cases := []struct {
		name string
		candidate AcceptanceCandidate
	}{
		{
			name: "doctrine",
			candidate: mustAcceptanceCandidate(t,
				acceptanceTestManifest(9, 0, first.ManifestHash, 4, digestString("d"), 9),
				acceptanceTestRevocations(11), now.Add(time.Minute)),
		},
		{
			name: "revocation",
			candidate: mustAcceptanceCandidate(t,
				acceptanceTestManifest(9, 0, first.ManifestHash, 5, digestString("d"), 9),
				acceptanceTestRevocations(9), now.Add(time.Minute)),
		},
		{
			name: "trust-root",
			candidate: mustAcceptanceCandidate(t,
				acceptanceTestManifest(9, 0, first.ManifestHash, 5, digestString("d"), 8),
				acceptanceTestRevocations(11), now.Add(time.Minute)),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), tc.candidate); !errors.Is(err, ErrAcceptanceRollback) {
				t.Fatalf("Begin() error = %v, want %v", err, ErrAcceptanceRollback)
			}
		})
	}
}

func TestAcceptanceLedgerFailsClosedOnCorruption(t *testing.T) {
	path := t.TempDir() + "/genesis-acceptance.log"
	now := time.Date(2026, 9, 28, 15, 0, 0, 0, time.UTC)
	manifest := acceptanceTestManifest(7, 0, "", 3, digestString("d"), 7)
	candidate := mustAcceptanceCandidate(t, manifest, acceptanceTestRevocations(4), now)
	acceptCandidate(t, path, candidate)

	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	payload = []byte(strings.Replace(string(payload), candidate.ManifestHash, digestString("tampered"), 1))
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), candidate); !errors.Is(err, ErrAcceptanceCorrupt) {
		t.Fatalf("corruption error = %v, want %v", err, ErrAcceptanceCorrupt)
	}
}

func acceptCandidate(t *testing.T, path string, candidate AcceptanceCandidate) {
	t.Helper()
	session, _, err := mustAcceptanceLedger(t, path).Begin(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func mustAcceptanceCandidate(t *testing.T, manifest genesis.Manifest, revocations SignedRevocationList, now time.Time) AcceptanceCandidate {
	t.Helper()
	candidate, err := NewAcceptanceCandidate(manifest, revocations, now)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func acceptanceTestManifest(genesisEpoch, sequence uint64, previous string, doctrineEpoch uint64, doctrineHash string, trustRootEpoch uint64) genesis.Manifest {
	return genesis.Manifest{
		ManifestVersion:      "1.1",
		GenesisEpoch:         genesisEpoch,
		Sequence:             sequence,
		PreviousManifestHash: previous,
		ArchitectureVersion:  "level-minus-1/v1.1",
		Doctrine: genesis.DoctrineBinding{
			DoctrineID:           "aegis-ege-doctrine",
			DoctrineEpoch:        doctrineEpoch,
			DoctrineManifestHash: doctrineHash,
		},
		Trust: genesis.Trust{
			TrustRootRef:   "ed25519:test",
			TrustRootEpoch: trustRootEpoch,
		},
		Authenticity: genesis.Authenticity{
			Canonicalization:   "RFC8785",
			SignatureScope:     "MANIFEST_EXCLUDING_AUTHENTICITY",
			SignedPayloadHash:  digestString("payload"),
			SignatureAlgorithm: "ed25519",
			SignerKeyID:        "ed25519:test",
			Signature:          "signature",
		},
	}
}

func acceptanceTestRevocations(epoch uint64) SignedRevocationList {
	return SignedRevocationList{
		List: RevocationList{
			Version:                     RevocationListVersion,
			Epoch:                       epoch,
			MinimumAcceptedGenesisEpoch: 1,
			MinimumAcceptedDoctrineEpoch: 1,
			MinimumTrustRootEpoch:       1,
			IssuedAt:                    time.Date(2026, 9, 28, 14, 0, 0, 0, time.UTC),
			ExpiresAt:                   time.Date(2026, 9, 29, 14, 0, 0, 0, time.UTC),
		},
		KeyID:     "ed25519:revocation",
		Signature: "signature",
	}
}

func digestString(seed string) string {
	sum := sha256.Sum256([]byte(seed))
	return "sha256:" + hex.EncodeToString(sum[:])
}
