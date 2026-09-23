package journal

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
		"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const formatVersion = 2

type EventType string

const (
	EventAuthorization EventType = "AUTHORIZATION"
	EventExecution     EventType = "EXECUTION"
	EventOutcome       EventType = "OUTCOME"
	EventDecision      EventType = "DECISION"
)

type Event struct {
	Type           EventType `json:"type"`
	ActionID       string    `json:"action_id,omitempty"`
	Target         string    `json:"target,omitempty"`
	Decision       string    `json:"decision,omitempty"`
	ReasonCodes    []string  `json:"reason_codes,omitempty"`
	EvidenceDigest string    `json:"evidence_digest,omitempty"`
	PlanDigest     string    `json:"plan_digest,omitempty"`
	OutcomeVerdict string    `json:"outcome_verdict,omitempty"`
	PayloadDigest  string    `json:"payload_digest,omitempty"`
	OccurredAt     time.Time `json:"occurred_at"`
}

type Entry struct {
	Version   int    `json:"version"`
	JournalID string `json:"journal_id"`
	Sequence  uint64 `json:"sequence"`
	PrevHash  string `json:"prev_hash"`
	Event     Event  `json:"event"`
	EntryHash string `json:"entry_hash"`
}

type Anchor struct {
	Version   int       `json:"version"`
	JournalID string    `json:"journal_id"`
	Sequence  uint64    `json:"sequence"`
	HeadHash  string    `json:"head_hash"`
	KeyID     string    `json:"key_id"`
	UpdatedAt time.Time `json:"updated_at"`
	Signature string    `json:"signature"`
}

type Verification struct {
	Valid      bool
	EntryCount uint64
	HeadHash   string
	Error      string
}

type FileJournal struct {
	mu           sync.Mutex
	path         string
	anchorPath   string
	signer       AnchorSigner
	verifier     AnchorVerifier
	externalHead ExternalHeadStore
	publicKey    ed25519.PublicKey
	now          func() time.Time
}

func NewFileJournal(path, anchorPath string, privateKey ed25519.PrivateKey) (*FileJournal, error) {
	signer, err := NewEd25519Signer("", privateKey)
	if err != nil {
		return nil, err
	}
	keyring := NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		return nil, err
	}
	j, err := NewFileJournalWithSecurity(path, anchorPath, signer, keyring, nil)
	if err != nil {
		return nil, err
	}
	j.publicKey = signer.PublicKey()
	return j, nil
}

func NewFileJournalWithSecurity(
	path string,
	anchorPath string,
	signer AnchorSigner,
	verifier AnchorVerifier,
	externalHead ExternalHeadStore,
) (*FileJournal, error) {
	if signer == nil {
		return nil, fmt.Errorf("journal signer is required")
	}
	if signer.KeyID() == "" {
		return nil, fmt.Errorf("journal signer key id is required")
	}
	if verifier == nil {
		return nil, fmt.Errorf("journal anchor verifier is required")
	}
	j := &FileJournal{
		path:         path,
		anchorPath:   anchorPath,
		signer:       signer,
		verifier:     verifier,
		externalHead: externalHead,
		now:          time.Now,
	}
	if err := j.initialize(context.Background()); err != nil {
		return nil, err
	}
	verification := j.verifyUnlocked(context.Background())
	if !verification.Valid {
		return nil, fmt.Errorf("journal verification failed during open: %s", verification.Error)
	}
	return j, nil
}

func VerifyFiles(path, anchorPath string, publicKey ed25519.PublicKey) Verification {
	if len(publicKey) != ed25519.PublicKeySize {
		return Verification{Error: "invalid Ed25519 public key"}
	}
	keyring := NewEd25519Keyring()
	keyID := Ed25519KeyID(publicKey)
	if err := keyring.Add(keyID, publicKey); err != nil {
		return Verification{Error: err.Error()}
	}
	j := &FileJournal{
		path:       path,
		anchorPath: anchorPath,
		verifier:   keyring,
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
	}
	return j.verifyUnlocked(context.Background())
}

func (j *FileJournal) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), j.publicKey...)
}

func (j *FileJournal) Append(ctx context.Context, event Event) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}

	j.mu.Lock()
	defer j.mu.Unlock()

	verification := j.verifyUnlocked(ctx)
	if !verification.Valid {
		return Entry{}, fmt.Errorf("refusing append to unverifiable journal: %s", verification.Error)
	}

	anchor, err := readAnchor(j.anchorPath)
	if err != nil {
		return Entry{}, err
	}

	if event.OccurredAt.IsZero() {
		event.OccurredAt = j.now().UTC()
	} else {
		event.OccurredAt = event.OccurredAt.UTC()
	}
	event.ReasonCodes = append([]string(nil), event.ReasonCodes...)

	entry := Entry{
		Version:   formatVersion,
		JournalID: anchor.JournalID,
		Sequence:  anchor.Sequence + 1,
		PrevHash:  anchor.HeadHash,
		Event:     event,
	}
	hash, err := hashEntry(entry)
	if err != nil {
		return Entry{}, err
	}
	entry.EntryHash = hash

	line, err := json.Marshal(entry)
	if err != nil {
		return Entry{}, fmt.Errorf("marshal journal entry: %w", err)
	}

	file, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Entry{}, fmt.Errorf("open journal for append: %w", err)
	}
	if _, err := file.Write(append(line, '\n')); err != nil {
		_ = file.Close()
		return Entry{}, fmt.Errorf("append journal entry: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return Entry{}, fmt.Errorf("fsync journal entry: %w", err)
	}
	if err := file.Close(); err != nil {
		return Entry{}, fmt.Errorf("close journal file: %w", err)
	}

	newAnchor := Anchor{
		Version:   formatVersion,
		JournalID: anchor.JournalID,
		Sequence:  entry.Sequence,
		HeadHash:  entry.EntryHash,
		KeyID:     j.signer.KeyID(),
		UpdatedAt: j.now().UTC(),
	}
	if err := signAnchor(ctx, &newAnchor, j.signer); err != nil {
		return Entry{}, err
	}
	if err := writeAnchorAtomic(j.anchorPath, newAnchor); err != nil {
		return Entry{}, err
	}
	if j.externalHead != nil {
		previous := externalHeadFromAnchor(anchor)
		next := externalHeadFromAnchor(newAnchor)
		if _, err := j.externalHead.CompareAndAdvance(ctx, previous, next); err != nil {
			return Entry{}, fmt.Errorf("advance external journal head: %w", err)
		}
	}

	return entry, nil
}

func (j *FileJournal) Verify(ctx context.Context) Verification {
	if err := ctx.Err(); err != nil {
		return Verification{Error: err.Error()}
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.verifyUnlocked(ctx)
}

func DigestPayload(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (j *FileJournal) initialize(ctx context.Context) error {
	journalExists, err := pathExists(j.path)
	if err != nil {
		return err
	}
	anchorExists, err := pathExists(j.anchorPath)
	if err != nil {
		return err
	}

	switch {
	case journalExists && anchorExists:
		return nil
	case journalExists != anchorExists:
		return errors.New("journal and signed anchor must either both exist or both be absent")
	}

	if err := os.MkdirAll(filepath.Dir(j.path), 0o700); err != nil {
		return fmt.Errorf("create journal directory: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(j.anchorPath), 0o700); err != nil {
		return fmt.Errorf("create anchor directory: %w", err)
	}

	journalID, err := randomID()
	if err != nil {
		return err
	}
	file, err := os.OpenFile(j.path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("create journal file: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("fsync empty journal: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close empty journal: %w", err)
	}

	anchor := Anchor{
		Version:   formatVersion,
		JournalID: journalID,
		Sequence:  0,
		HeadHash:  "",
		KeyID:     j.signer.KeyID(),
		UpdatedAt: j.now().UTC(),
	}
	if err := signAnchor(ctx, &anchor, j.signer); err != nil {
		return err
	}
	if err := writeAnchorAtomic(j.anchorPath, anchor); err != nil {
		return err
	}
	if j.externalHead != nil {
		if _, err := j.externalHead.CompareAndAdvance(
			ctx,
			ExternalHead{JournalID: journalID},
			externalHeadFromAnchor(anchor),
		); err != nil {
			return fmt.Errorf("initialize external journal head: %w", err)
		}
	}
	return nil
}

func (j *FileJournal) verifyUnlocked(ctx context.Context) Verification {
	anchor, err := readAnchor(j.anchorPath)
	if err != nil {
		return Verification{Error: err.Error()}
	}
	if anchor.Version != formatVersion {
		return Verification{Error: fmt.Sprintf("unsupported anchor version %d", anchor.Version)}
	}
	if j.verifier == nil {
		return Verification{Error: "journal anchor verifier is not configured"}
	}
	if err := verifyAnchor(ctx, anchor, j.verifier); err != nil {
		return Verification{Error: "signed anchor verification failed: " + err.Error()}
	}

	file, err := os.Open(j.path)
	if err != nil {
		return Verification{Error: fmt.Sprintf("open journal: %v", err)}
	}
	defer file.Close()

	var expectedSequence uint64 = 1
	var previousHash string
	var entryCount uint64

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		var entry Entry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return Verification{Error: fmt.Sprintf("decode entry %d: %v", expectedSequence, err)}
		}
		if entry.Version != formatVersion {
			return Verification{Error: fmt.Sprintf("entry %d has unsupported version %d", expectedSequence, entry.Version)}
		}
		if entry.JournalID != anchor.JournalID {
			return Verification{Error: fmt.Sprintf("entry %d journal id mismatch", expectedSequence)}
		}
		if entry.Sequence != expectedSequence {
			return Verification{Error: fmt.Sprintf("sequence mismatch: expected %d got %d", expectedSequence, entry.Sequence)}
		}
		if entry.PrevHash != previousHash {
			return Verification{Error: fmt.Sprintf("entry %d previous hash mismatch", entry.Sequence)}
		}

		wantHash, err := hashEntry(entry)
		if err != nil {
			return Verification{Error: fmt.Sprintf("hash entry %d: %v", entry.Sequence, err)}
		}
		if entry.EntryHash != wantHash {
			return Verification{Error: fmt.Sprintf("entry %d hash mismatch", entry.Sequence)}
		}

		previousHash = entry.EntryHash
		entryCount++
		expectedSequence++
	}
	if err := scanner.Err(); err != nil {
		return Verification{Error: fmt.Sprintf("scan journal: %v", err)}
	}

	if anchor.Sequence != entryCount {
		return Verification{
			EntryCount: entryCount,
			HeadHash:   previousHash,
			Error:      fmt.Sprintf("signed anchor sequence=%d journal entries=%d", anchor.Sequence, entryCount),
		}
	}
	if anchor.HeadHash != previousHash {
		return Verification{
			EntryCount: entryCount,
			HeadHash:   previousHash,
			Error:      "signed anchor head hash does not match journal",
		}
	}

	if j.externalHead != nil {
		external, err := j.externalHead.Load(ctx, anchor.JournalID)
		if err != nil {
			return Verification{
				EntryCount: entryCount,
				HeadHash:   previousHash,
				Error:      "external journal head unavailable: " + err.Error(),
			}
		}
		local := externalHeadFromAnchor(anchor)
		if external.Sequence != local.Sequence ||
			external.HeadHash != local.HeadHash ||
			external.KeyID != local.KeyID {
			return Verification{
				EntryCount: entryCount,
				HeadHash:   previousHash,
				Error: fmt.Sprintf(
					"external journal head mismatch: external sequence=%d hash=%q key=%q local sequence=%d hash=%q key=%q",
					external.Sequence, external.HeadHash, external.KeyID,
					local.Sequence, local.HeadHash, local.KeyID,
				),
			}
		}
	}

	return Verification{
		Valid:      true,
		EntryCount: entryCount,
		HeadHash:   previousHash,
	}
}

func hashEntry(entry Entry) (string, error) {
	copyEntry := entry
	copyEntry.EntryHash = ""
	payload, err := json.Marshal(copyEntry)
	if err != nil {
		return "", fmt.Errorf("marshal entry for hash: %w", err)
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func signAnchor(ctx context.Context, anchor *Anchor, signer AnchorSigner) error {
	if signer == nil {
		return errors.New("journal signer is not configured")
	}
	if anchor.KeyID == "" {
		anchor.KeyID = signer.KeyID()
	}
	if anchor.KeyID != signer.KeyID() {
		return fmt.Errorf("anchor key id %q does not match signer %q", anchor.KeyID, signer.KeyID())
	}
	payload, err := anchorSigningPayload(*anchor)
	if err != nil {
		return err
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return fmt.Errorf("sign journal anchor: %w", err)
	}
	anchor.Signature = encodeSignature(signature)
	return nil
}

func verifyAnchor(ctx context.Context, anchor Anchor, verifier AnchorVerifier) error {
	if verifier == nil {
		return errors.New("journal verifier is not configured")
	}
	if anchor.KeyID == "" {
		return errors.New("journal anchor key id is missing")
	}
	signature, err := decodeSignature(anchor.Signature)
	if err != nil {
		return err
	}
	payload, err := anchorSigningPayload(anchor)
	if err != nil {
		return err
	}
	return verifier.Verify(ctx, anchor.KeyID, payload, signature)
}

func externalHeadFromAnchor(anchor Anchor) ExternalHead {
	return ExternalHead{
		JournalID: anchor.JournalID,
		Sequence:  anchor.Sequence,
		HeadHash:  anchor.HeadHash,
		KeyID:     anchor.KeyID,
	}
}

func anchorSigningPayload(anchor Anchor) ([]byte, error) {
	copyAnchor := anchor
	copyAnchor.Signature = ""
	payload, err := json.Marshal(copyAnchor)
	if err != nil {
		return nil, fmt.Errorf("marshal anchor payload: %w", err)
	}
	return payload, nil
}

func readAnchor(path string) (Anchor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Anchor{}, fmt.Errorf("read signed anchor: %w", err)
	}
	var anchor Anchor
	if err := json.Unmarshal(data, &anchor); err != nil {
		return Anchor{}, fmt.Errorf("decode signed anchor: %w", err)
	}
	return anchor, nil
}

func writeAnchorAtomic(path string, anchor Anchor) error {
	data, err := json.Marshal(anchor)
	if err != nil {
		return fmt.Errorf("marshal signed anchor: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create anchor directory: %w", err)
	}

	temp, err := os.CreateTemp(dir, ".anchor-*")
	if err != nil {
		return fmt.Errorf("create temporary anchor: %w", err)
	}
	tempName := temp.Name()
	defer os.Remove(tempName)

	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return fmt.Errorf("chmod temporary anchor: %w", err)
	}
	if _, err := temp.Write(append(data, '\n')); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary anchor: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("fsync temporary anchor: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary anchor: %w", err)
	}
	if err := os.Rename(tempName, path); err != nil {
		return fmt.Errorf("replace signed anchor: %w", err)
	}
	return nil
}

func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func randomID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate journal id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
