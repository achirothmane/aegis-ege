package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
)

var (
	ErrExternalHeadNotFound = errors.New("external journal head not found")
	ErrExternalHeadConflict = errors.New("external journal head conflict")
)

type AnchorSigner interface {
	KeyID() string
	Sign(context.Context, []byte) ([]byte, error)
}

type AnchorVerifier interface {
	Verify(context.Context, string, []byte, []byte) error
}

type ExternalHead struct {
	JournalID    string `json:"journal_id"`
	Sequence     uint64 `json:"sequence"`
	HeadHash     string `json:"head_hash"`
	KeyID        string `json:"key_id"`
	StoreVersion string `json:"-"`
}

type ExternalHeadStore interface {
	Load(context.Context, string) (ExternalHead, error)
	CompareAndAdvance(context.Context, ExternalHead, ExternalHead) (ExternalHead, error)
}

type Ed25519Signer struct {
	keyID      string
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

func NewEd25519Signer(keyID string, privateKey ed25519.PrivateKey) (*Ed25519Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length: %d", len(privateKey))
	}
	publicKey := privateKey.Public().(ed25519.PublicKey)
	if keyID == "" {
		keyID = Ed25519KeyID(publicKey)
	}
	return &Ed25519Signer{
		keyID:      keyID,
		privateKey: append(ed25519.PrivateKey(nil), privateKey...),
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}

func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

func (s *Ed25519Signer) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ed25519.Sign(s.privateKey, payload), nil
}

func (s *Ed25519Signer) PublicKey() ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), s.publicKey...)
}

func Ed25519KeyID(publicKey ed25519.PublicKey) string {
	sum := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(sum[:12])
}

type Ed25519Keyring struct {
	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey
}

func NewEd25519Keyring() *Ed25519Keyring {
	return &Ed25519Keyring{keys: make(map[string]ed25519.PublicKey)}
}

func (k *Ed25519Keyring) Add(keyID string, publicKey ed25519.PublicKey) error {
	if keyID == "" {
		return errors.New("key id is required")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key length: %d", len(publicKey))
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[keyID] = append(ed25519.PublicKey(nil), publicKey...)
	return nil
}

func (k *Ed25519Keyring) Verify(
	ctx context.Context,
	keyID string,
	payload []byte,
	signature []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	k.mu.RLock()
	publicKey, ok := k.keys[keyID]
	k.mu.RUnlock()
	if !ok {
		return fmt.Errorf("unknown journal signing key %q", keyID)
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return errors.New("journal anchor signature verification failed")
	}
	return nil
}

func decodeSignature(encoded string) ([]byte, error) {
	signature, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode anchor signature: %w", err)
	}
	return signature, nil
}

func encodeSignature(signature []byte) string {
	return base64.StdEncoding.EncodeToString(signature)
}

type MemoryHeadStore struct {
	mu    sync.Mutex
	heads map[string]ExternalHead
}

func NewMemoryHeadStore() *MemoryHeadStore {
	return &MemoryHeadStore{heads: make(map[string]ExternalHead)}
}

func (s *MemoryHeadStore) Load(_ context.Context, journalID string) (ExternalHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	head, ok := s.heads[journalID]
	if !ok {
		return ExternalHead{}, ErrExternalHeadNotFound
	}
	return head, nil
}

func (s *MemoryHeadStore) CompareAndAdvance(
	_ context.Context,
	previous ExternalHead,
	next ExternalHead,
) (ExternalHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	current, exists := s.heads[next.JournalID]
	if !exists {
		if previous.Sequence != 0 || previous.HeadHash != "" {
			return ExternalHead{}, ErrExternalHeadConflict
		}
		if next.Sequence != 0 {
			return ExternalHead{}, ErrExternalHeadConflict
		}
		s.heads[next.JournalID] = next
		return next, nil
	}

	if current.Sequence != previous.Sequence ||
		current.HeadHash != previous.HeadHash ||
		current.KeyID != previous.KeyID {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if next.Sequence < current.Sequence {
		return ExternalHead{}, ErrExternalHeadConflict
	}
	if next.Sequence == current.Sequence &&
		(next.HeadHash != current.HeadHash || next.KeyID != current.KeyID) {
		return ExternalHead{}, ErrExternalHeadConflict
	}

	s.heads[next.JournalID] = next
	return next, nil
}
