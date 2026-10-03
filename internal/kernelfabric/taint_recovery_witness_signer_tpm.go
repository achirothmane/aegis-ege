package kernelfabric

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
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

func NewTPMRecoveryWitnessSigner(
	rw io.ReadWriteCloser,
	password string,
) (*TPMRecoveryWitnessSigner, error) {
	if rw == nil {
		return nil, errors.New("TPM transport is required")
	}
	template := legacytpm2.Public{
		Type:       legacytpm2.AlgECC,
		NameAlg:    legacytpm2.AlgSHA256,
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
		"",
		password,
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
		password: password,
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
	if s == nil {
		return nil, errors.New("TPM recovery witness signer is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !isAllowedRecoveryWitnessSigningPayload(payload) {
		return nil, errors.New("recovery witness signer payload domain is not allowed")
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
