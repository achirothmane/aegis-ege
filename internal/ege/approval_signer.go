package ege

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

func NewEd25519AuthorityPKCS8PEM(data []byte) (*Ed25519Authority, error) {
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, errors.New("Ed25519 private key is not valid PEM")
	}
	if len(rest) != 0 {
		for _, b := range rest {
			switch b {
			case ' ', '\t', '\r', '\n':
			default:
				return nil, errors.New("Ed25519 private key PEM contains trailing data")
			}
		}
	}
	if block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("Ed25519 private key PEM block must be PRIVATE KEY, got %q", block.Type)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse Ed25519 private key: %w", err)
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be Ed25519, got %T", parsed)
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key length %d", len(privateKey))
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicKey, ok := privateCopy.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("derive Ed25519 public key from private key")
	}
	verifier, err := NewEd25519PublicKeyVerifier(publicKey)
	if err != nil {
		return nil, err
	}
	return &Ed25519Authority{
		keyID:      verifier.KeyID(),
		privateKey: privateCopy,
		publicKey:  append(ed25519.PublicKey(nil), publicKey...),
	}, nil
}
