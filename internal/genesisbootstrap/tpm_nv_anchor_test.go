package genesisbootstrap

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestTPMNVAnchorIdentityRequiresDedicatedCounterProfile(t *testing.T) {
	index := tpmutil.Handle(0x0180A001)
	pub := legacytpm2.NVPublic{
		NVIndex:    index,
		NameAlg:    legacytpm2.AlgSHA256,
		Attributes: legacytpm2.NVAttr(1<<4) | legacytpm2.AttrAuthRead | legacytpm2.AttrAuthWrite | legacytpm2.AttrNoDA,
		DataSize:   8,
	}

	got, err := tpmNVAnchorIdentity(pub, index)
	if err != nil {
		t.Fatal(err)
	}
	stable := pub
	stable.Attributes &^= legacytpm2.AttrWritten | legacytpm2.AttrReadLocked | legacytpm2.AttrWriteLocked
	wire, err := tpmutil.Pack(stable)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wire)
	want := "tpm2-nv:0x0180a001:definition-sha256:" + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("identity = %q, want %q", got, want)
	}

	written := pub
	written.Attributes |= legacytpm2.AttrWritten
	afterWrite, err := tpmNVAnchorIdentity(written, index)
	if err != nil {
		t.Fatal(err)
	}
	if afterWrite != got {
		t.Fatalf("identity changed after TPMA_NV_WRITTEN: before=%q after=%q", got, afterWrite)
	}

	cases := []struct {
		name string
		edit func(*legacytpm2.NVPublic)
	}{
		{
			name: "ordinary-index",
			edit: func(p *legacytpm2.NVPublic) {
				p.Attributes &^= legacytpm2.NVAttr(0xF0)
			},
		},
		{
			name: "wrong-size",
			edit: func(p *legacytpm2.NVPublic) {
				p.DataSize = 16
			},
		},
		{
			name: "wrong-name-algorithm",
			edit: func(p *legacytpm2.NVPublic) {
				p.NameAlg = legacytpm2.AlgSHA384
			},
		},
		{
			name: "no-auth-read",
			edit: func(p *legacytpm2.NVPublic) {
				p.Attributes &^= legacytpm2.AttrAuthRead
			},
		},
		{
			name: "no-auth-write",
			edit: func(p *legacytpm2.NVPublic) {
				p.Attributes &^= legacytpm2.AttrAuthWrite
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			candidate := pub
			tc.edit(&candidate)
			if _, err := tpmNVAnchorIdentity(candidate, index); err == nil {
				t.Fatal("expected invalid TPM NV public profile to fail")
			}
		})
	}
}

func TestLoadTPMNVAuthFileRequiresOwnerOnlyBase64Secret(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nv-auth")
	secret := []byte("0123456789abcdef0123456789abcdef")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(secret)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := LoadTPMNVAuthFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(secret) {
		t.Fatalf("decoded auth mismatch")
	}

	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadTPMNVAuthFile(path); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("expected permissive auth-file mode rejection, got %v", err)
	}
}

func TestNewTPMNVCounterAnchorRejectsWeakConfiguration(t *testing.T) {
	if _, err := NewTPMNVCounterAnchor("", 0x0180A001, []byte("secret")); err == nil {
		t.Fatal("expected empty device path to fail")
	}
	if _, err := NewTPMNVCounterAnchor("/dev/tpmrm0", 0, []byte("secret")); err == nil {
		t.Fatal("expected zero NV index to fail")
	}
	if _, err := NewTPMNVCounterAnchor("/dev/tpmrm0", 0x0180A001, nil); err == nil {
		t.Fatal("expected empty auth to fail")
	}
	if _, err := NewTPMNVCounterAnchor("/dev/tpmrm0", 0x0180A001, make([]byte, tpmNVAuthMax+1)); err == nil {
		t.Fatal("expected oversized auth to fail")
	}
}
