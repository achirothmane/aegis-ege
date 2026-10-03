package kernelfabric

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

type TPMRecoveryWitnessSigner struct {
	mu       sync.Mutex
	rw       io.ReadWriteCloser
	handle   tpmutil.Handle
	password string
	verifier RecoveryWitnessVerifier
	closed   bool
}

const tpmHardwareWitnessEvidenceDomain = "aegis-ege/tpm-hardware-witness-evidence/v1\x00"

func legacyTPMRequiredHardwareSignerAttributes() legacytpm2.KeyProp {
	return legacytpm2.FlagSign |
		legacytpm2.FlagFixedTPM |
		legacytpm2.FlagFixedParent |
		legacytpm2.FlagSensitiveDataOrigin |
		legacytpm2.FlagUserWithAuth
}

func legacyTPMForbiddenHardwareSignerAttributes() legacytpm2.KeyProp {
	return legacytpm2.FlagDecrypt
}

type TPMRecoveryWitnessPublicEvidence struct {
	PublicAreaSHA256   string `json:"public_area_sha256"`
	NameHex            string `json:"name_hex"`
	Type               uint16 `json:"type"`
	NameAlgorithm      uint16 `json:"name_algorithm"`
	Attributes         uint32 `json:"attributes"`
	Curve              uint16 `json:"curve"`
	SignatureAlgorithm uint16 `json:"signature_algorithm"`
	SignatureHash      uint16 `json:"signature_hash"`
}

func NewTPMRecoveryWitnessSigner(
	rw io.ReadWriteCloser,
	keyAuth string,
) (*TPMRecoveryWitnessSigner, error) {
	return NewTPMRecoveryWitnessSignerWithAuth(rw, "", keyAuth)
}

func NewTPMRecoveryWitnessSignerWithAuth(
	rw io.ReadWriteCloser,
	ownerAuth string,
	keyAuth string,
) (*TPMRecoveryWitnessSigner, error) {
	if rw == nil {
		return nil, errors.New("TPM transport is required")
	}
	template := legacytpm2.Public{
		Type:    legacytpm2.AlgECC,
		NameAlg: legacytpm2.AlgSHA256,
		Attributes: legacytpm2.FlagSign |
			legacytpm2.FlagFixedTPM |
			legacytpm2.FlagFixedParent |
			legacytpm2.FlagSensitiveDataOrigin |
			legacytpm2.FlagUserWithAuth,
		ECCParameters: &legacytpm2.ECCParams{
			Sign: &legacytpm2.SigScheme{
				Alg:  legacytpm2.AlgECDSA,
				Hash: legacytpm2.AlgSHA256,
			},
			CurveID: legacytpm2.CurveNISTP256,
		},
	}
	handle, publicAny, err := legacytpm2.CreatePrimary(
		rw,
		legacytpm2.HandleOwner,
		legacytpm2.PCRSelection{},
		ownerAuth,
		keyAuth,
		template,
	)
	if err != nil {
		return nil, fmt.Errorf("create TPM recovery witness signing primary: %w", err)
	}
	publicKey, ok := publicAny.(*ecdsa.PublicKey)
	if !ok {
		_ = legacytpm2.FlushContext(rw, handle)
		return nil, errors.New("TPM recovery witness public key is not ECDSA")
	}
	verifier, err := NewECDSAP256RecoveryWitnessVerifier(publicKey)
	if err != nil {
		_ = legacytpm2.FlushContext(rw, handle)
		return nil, err
	}
	return &TPMRecoveryWitnessSigner{
		rw:       rw,
		handle:   handle,
		password: keyAuth,
		verifier: verifier,
	}, nil
}

func (s *TPMRecoveryWitnessSigner) KeyID() string {
	if s == nil {
		return ""
	}
	return s.verifier.KeyID()
}

func (s *TPMRecoveryWitnessSigner) Verifier() RecoveryWitnessVerifier {
	if s == nil {
		return RecoveryWitnessVerifier{}
	}
	return s.verifier
}

func (s *TPMRecoveryWitnessSigner) Sign(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	if !isAllowedRecoveryWitnessSigningPayload(payload) {
		return nil, errors.New("recovery witness signer payload domain is not allowed")
	}
	return s.signTPMPayload(ctx, payload)
}

func (s *TPMRecoveryWitnessSigner) SignHardwareEvidence(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	if len(payload) < len(tpmHardwareWitnessEvidenceDomain) ||
		string(payload[:len(tpmHardwareWitnessEvidenceDomain)]) != tpmHardwareWitnessEvidenceDomain {
		return nil, errors.New("TPM hardware evidence payload domain is not allowed")
	}
	return s.signTPMPayload(ctx, payload)
}

func (s *TPMRecoveryWitnessSigner) signTPMPayload(
	ctx context.Context,
	payload []byte,
) ([]byte, error) {
	if s == nil {
		return nil, errors.New("TPM recovery witness signer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.rw == nil {
		return nil, errors.New("TPM recovery witness signer is closed")
	}
	signature, err := legacytpm2.Sign(
		s.rw,
		s.handle,
		s.password,
		digest[:],
		nil,
		&legacytpm2.SigScheme{
			Alg:  legacytpm2.AlgECDSA,
			Hash: legacytpm2.AlgSHA256,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("TPM recovery witness sign: %w", err)
	}
	if signature == nil || signature.ECC == nil {
		return nil, errors.New("TPM recovery witness returned non-ECDSA signature")
	}
	encoded, err := EncodeECDSARecoveryWitnessSignature(
		signature.ECC.R,
		signature.ECC.S,
	)
	if err != nil {
		return nil, err
	}
	if !s.verifier.Verify(payload, encoded) {
		return nil, errors.New("TPM recovery witness signature failed local verification")
	}
	return encoded, nil
}

func (s *TPMRecoveryWitnessSigner) PublicEvidence() (TPMRecoveryWitnessPublicEvidence, error) {
	if s == nil {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("TPM recovery witness signer is unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.rw == nil {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("TPM recovery witness signer is closed")
	}
	public, name, _, err := legacytpm2.ReadPublic(s.rw, s.handle)
	if err != nil {
		return TPMRecoveryWitnessPublicEvidence{}, fmt.Errorf("read TPM recovery witness public area: %w", err)
	}
	if public.Type != legacytpm2.AlgECC || public.ECCParameters == nil ||
		public.ECCParameters.Sign == nil {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("TPM recovery witness public area is not ECC signing")
	}
	required := legacyTPMRequiredHardwareSignerAttributes()
	forbidden := legacyTPMForbiddenHardwareSignerAttributes()
	if public.Attributes&required != required || public.Attributes&forbidden != 0 {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("TPM recovery witness public attributes violate non-exportable signer contract")
	}
	encodedPublic, err := public.Encode()
	if err != nil {
		return TPMRecoveryWitnessPublicEvidence{}, fmt.Errorf("encode TPM recovery witness public area: %w", err)
	}
	sum := sha256.Sum256(encodedPublic)
	observed := TPMRecoveryWitnessPublicEvidence{
		PublicAreaSHA256:   "sha256:" + hex.EncodeToString(sum[:]),
		NameHex:            hex.EncodeToString(name),
		Type:               uint16(public.Type),
		NameAlgorithm:      uint16(public.NameAlg),
		Attributes:         uint32(public.Attributes),
		Curve:              uint16(public.ECCParameters.CurveID),
		SignatureAlgorithm: uint16(public.ECCParameters.Sign.Alg),
		SignatureHash:      uint16(public.ECCParameters.Sign.Hash),
	}
	expected, err := expectedTPMRecoveryWitnessPublicEvidence(s.verifier)
	if err != nil {
		return TPMRecoveryWitnessPublicEvidence{}, err
	}
	if observed != expected {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("live TPM recovery witness public area differs from pinned signer template")
	}
	return observed, nil
}

func expectedTPMRecoveryWitnessPublicEvidence(
	verifier RecoveryWitnessVerifier,
) (TPMRecoveryWitnessPublicEvidence, error) {
	if verifier.Algorithm() != RecoveryWitnessSignatureECDSAP256SHA256 ||
		verifier.ecdsa == nil {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("TPM recovery witness requires ECDSA P-256 verifier")
	}
	x := verifier.ecdsa.X.Bytes()
	y := verifier.ecdsa.Y.Bytes()
	if len(x) > 32 || len(y) > 32 {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("invalid P-256 recovery witness coordinates")
	}
	xRaw := make([]byte, 32)
	yRaw := make([]byte, 32)
	copy(xRaw[32-len(x):], x)
	copy(yRaw[32-len(y):], y)
	public := legacytpm2.Public{
		Type:       legacytpm2.AlgECC,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacyTPMRequiredHardwareSignerAttributes(),
		ECCParameters: &legacytpm2.ECCParams{
			Sign: &legacytpm2.SigScheme{
				Alg:  legacytpm2.AlgECDSA,
				Hash: legacytpm2.AlgSHA256,
			},
			CurveID: legacytpm2.CurveNISTP256,
			Point: legacytpm2.ECPoint{
				XRaw: tpmutil.U16Bytes(xRaw),
				YRaw: tpmutil.U16Bytes(yRaw),
			},
		},
	}
	encoded, err := public.Encode()
	if err != nil {
		return TPMRecoveryWitnessPublicEvidence{}, err
	}
	sum := sha256.Sum256(encoded)
	name, err := public.Name()
	if err != nil || name.Digest == nil {
		return TPMRecoveryWitnessPublicEvidence{}, errors.New("compute TPM recovery witness public name")
	}
	nameRaw, err := name.Digest.Encode()
	if err != nil {
		return TPMRecoveryWitnessPublicEvidence{}, err
	}
	return TPMRecoveryWitnessPublicEvidence{
		PublicAreaSHA256:   "sha256:" + hex.EncodeToString(sum[:]),
		NameHex:            hex.EncodeToString(nameRaw),
		Type:               uint16(public.Type),
		NameAlgorithm:      uint16(public.NameAlg),
		Attributes:         uint32(public.Attributes),
		Curve:              uint16(public.ECCParameters.CurveID),
		SignatureAlgorithm: uint16(public.ECCParameters.Sign.Alg),
		SignatureHash:      uint16(public.ECCParameters.Sign.Hash),
	}, nil
}

func (s *TPMRecoveryWitnessSigner) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	var flushErr error
	if s.rw != nil && s.handle != 0 {
		flushErr = legacytpm2.FlushContext(s.rw, s.handle)
	}
	var closeErr error
	if s.rw != nil {
		closeErr = s.rw.Close()
	}
	if flushErr != nil {
		return flushErr
	}
	return closeErr
}
