package ege

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
)

type Ed25519PublicKeyVerifier struct {
	keyID     string
	publicKey ed25519.PublicKey
}

func NewEd25519PublicKeyVerifier(publicKey ed25519.PublicKey) (*Ed25519PublicKeyVerifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length %d", len(publicKey))
	}
	keyCopy := append(ed25519.PublicKey(nil), publicKey...)
	sum := sha256.Sum256(keyCopy)
	return &Ed25519PublicKeyVerifier{
		keyID:     "ed25519:" + hex.EncodeToString(sum[:12]),
		publicKey: keyCopy,
	}, nil
}

func NewEd25519PublicKeyVerifierPEM(data []byte) (*Ed25519PublicKeyVerifier, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("approval public key is not valid PEM")
	}
	if len(rest) != 0 {
		for _, b := range rest {
			switch b {
			case ' ', '\t', '\r', '\n':
			default:
				return nil, errors.New("approval public key PEM contains trailing data")
			}
		}
	}
	if block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("approval public key PEM block must be PUBLIC KEY, got %q", block.Type)
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse approval public key: %w", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("approval public key must be Ed25519, got %T", parsed)
	}
	return NewEd25519PublicKeyVerifier(publicKey)
}

func (v *Ed25519PublicKeyVerifier) KeyID() string {
	if v == nil {
		return ""
	}
	return v.keyID
}

func (v *Ed25519PublicKeyVerifier) Verify(
	ctx context.Context,
	keyID string,
	payload []byte,
	signature []byte,
) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v == nil || len(v.publicKey) != ed25519.PublicKeySize {
		return errors.New("Ed25519 approval verifier is unavailable")
	}
	if keyID != v.keyID {
		return fmt.Errorf("unknown Ed25519 approval key %q", keyID)
	}
	if !ed25519.Verify(v.publicKey, payload, signature) {
		return errors.New("Ed25519 approval signature verification failed")
	}
	return nil
}
