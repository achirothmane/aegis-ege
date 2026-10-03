//go:build linux && cgo

package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"path/filepath"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm-tools/simulator"
)

func TestTPMPlatformIdentityMatchesEnrollmentEKSPKI(t *testing.T) {
	sim, err := simulator.GetWithFixedSeedInsecure(1010)
	if err != nil {
		t.Fatalf("start TPM simulator: %v", err)
	}
	defer sim.Close()
	device := transport.FromReadWriter(sim)

	cfg := TPMNVMonotonicRootConfig{
		NVIndex:   tpm2.TPMHandle(0x0180A17B),
		StatePath: filepath.Join(t.TempDir(), "root.json"),
		IndexAuth: []byte("aegis-vcs10-ek-identity"),
	}
	if err := ProvisionTPMNVMonotonicRoot(context.Background(), device, cfg); err != nil {
		t.Fatal(err)
	}
	root, err := NewTPMNVMonotonicRoot(device, cfg)
	if err != nil {
		t.Fatal(err)
	}

	commitment, err := root.CurrentPlatformMeasurement(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	response, err := (tpm2.CreatePrimary{
		PrimaryHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHEndorsement,
			Name:   tpm2.HandleName(tpm2.TPMRHEndorsement),
			Auth:   tpm2.PasswordAuth(cfg.EndorsementAuth),
		},
		InPublic: tpm2.New2B(tpm2.ECCEKTemplate),
	}).Execute(device)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = (tpm2.FlushContext{FlushHandle: response.ObjectHandle}).Execute(device)
	}()

	public, err := response.OutPublic.Contents()
	if err != nil {
		t.Fatal(err)
	}
	detail, err := public.Parameters.ECCDetail()
	if err != nil {
		t.Fatal(err)
	}
	curve, err := detail.CurveID.Curve()
	if err != nil {
		t.Fatal(err)
	}
	unique, err := public.Unique.ECC()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(unique.X.Buffer),
		Y:     new(big.Int).SetBytes(unique.Y.Buffer),
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	expected := "sha256:" + hex.EncodeToString(sum[:])

	if commitment.PlatformIdentityDigest != expected {
		t.Fatalf("platform identity=%s want enrollment EK SPKI=%s", commitment.PlatformIdentityDigest, expected)
	}
}
