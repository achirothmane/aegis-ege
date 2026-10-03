package kernelfabric

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

const (
	RecoveryWitnessSignatureEd25519         = "ed25519"
	RecoveryWitnessSignatureECDSAP256SHA256 = "ecdsa-p256-sha256"
)

type RecoveryWitnessVerifier struct {
	algorithm string
	keyID     string
	ed25519   ed25519.PublicKey
	ecdsa     *ecdsa.PublicKey
}

type ecdsaSignatureASN1 struct {
	R *big.Int
	S *big.Int
}

func NewRecoveryWitnessVerifier(
	algorithm string,
	encodedPublicKey string,
) (RecoveryWitnessVerifier, error) {
	algorithm = strings.TrimSpace(algorithm)
	if algorithm == "" {
		algorithm = RecoveryWitnessSignatureEd25519
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedPublicKey))
	if err != nil {
		return RecoveryWitnessVerifier{}, fmt.Errorf("decode recovery witness public key: %w", err)
	}
	switch algorithm {
	case RecoveryWitnessSignatureEd25519:
		if len(raw) != ed25519.PublicKeySize {
			return RecoveryWitnessVerifier{}, errors.New("invalid Ed25519 recovery witness public key")
		}
		key := ed25519.PublicKey(append([]byte(nil), raw...))
		keyID, err := BootstrapKeyID(key)
		if err != nil {
			return RecoveryWitnessVerifier{}, err
		}
		return RecoveryWitnessVerifier{
			algorithm: algorithm,
			keyID:     keyID,
			ed25519:   key,
		}, nil
	case RecoveryWitnessSignatureECDSAP256SHA256:
		publicAny, err := x509.ParsePKIXPublicKey(raw)
		if err != nil {
			return RecoveryWitnessVerifier{}, fmt.Errorf("parse ECDSA recovery witness public key: %w", err)
		}
		publicKey, ok := publicAny.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return RecoveryWitnessVerifier{}, errors.New("recovery witness public key must be ECDSA P-256")
		}
		keyID, err := recoveryWitnessECDSAKeyID(publicKey)
		if err != nil {
			return RecoveryWitnessVerifier{}, err
		}
		return RecoveryWitnessVerifier{
			algorithm: algorithm,
			keyID:     keyID,
			ecdsa:     publicKey,
		}, nil
	default:
		return RecoveryWitnessVerifier{}, fmt.Errorf("unsupported recovery witness signature algorithm %q", algorithm)
	}
}

func NewECDSAP256RecoveryWitnessVerifier(
	publicKey *ecdsa.PublicKey,
) (RecoveryWitnessVerifier, error) {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return RecoveryWitnessVerifier{}, errors.New("recovery witness public key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return RecoveryWitnessVerifier{}, err
	}
	return NewRecoveryWitnessVerifier(
		RecoveryWitnessSignatureECDSAP256SHA256,
		base64.StdEncoding.EncodeToString(der),
	)
}

func (v RecoveryWitnessVerifier) Algorithm() string {
	return v.algorithm
}

func (v RecoveryWitnessVerifier) KeyID() string {
	return v.keyID
}

func (v RecoveryWitnessVerifier) EncodedPublicKey() (string, error) {
	switch v.algorithm {
	case RecoveryWitnessSignatureEd25519:
		return base64.StdEncoding.EncodeToString(v.ed25519), nil
	case RecoveryWitnessSignatureECDSAP256SHA256:
		der, err := x509.MarshalPKIXPublicKey(v.ecdsa)
		if err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(der), nil
	default:
		return "", errors.New("recovery witness verifier is unavailable")
	}
}

func (v RecoveryWitnessVerifier) Verify(payload, signature []byte) bool {
	switch v.algorithm {
	case RecoveryWitnessSignatureEd25519:
		return len(v.ed25519) == ed25519.PublicKeySize &&
			len(signature) == ed25519.SignatureSize &&
			ed25519.Verify(v.ed25519, payload, signature)
	case RecoveryWitnessSignatureECDSAP256SHA256:
		if v.ecdsa == nil {
			return false
		}
		var parsed ecdsaSignatureASN1
		if rest, err := asn1.Unmarshal(signature, &parsed); err != nil ||
			len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return false
		}
		digest := sha256.Sum256(payload)
		return ecdsa.Verify(v.ecdsa, digest[:], parsed.R, parsed.S)
	default:
		return false
	}
}

func recoveryWitnessECDSAKeyID(publicKey *ecdsa.PublicKey) (string, error) {
	if publicKey == nil || publicKey.Curve != elliptic.P256() {
		return "", errors.New("recovery witness public key must be ECDSA P-256")
	}
	der, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "ecdsa-p256:" + hex.EncodeToString(sum[:12]), nil
}

func EncodeECDSARecoveryWitnessSignature(r, s *big.Int) ([]byte, error) {
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 {
		return nil, errors.New("invalid ECDSA recovery witness signature")
	}
	return asn1.Marshal(ecdsaSignatureASN1{R: r, S: s})
}
