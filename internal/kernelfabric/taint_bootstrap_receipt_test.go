package kernelfabric

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"
)

func TestTaintBootstrapReceiptSignVerifyAndTamper(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	digest := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return "sha256:" + hex.EncodeToString(sum[:])
	}

	programs := make([]PinnedProgramAttestation, 0, len(taintBootstrapPrograms))
	links := make([]TaintPinnedLinkAttestation, 0, len(taintBootstrapPrograms))
	for i, expected := range taintBootstrapPrograms {
		programs = append(programs, PinnedProgramAttestation{
			PinName:    expected.PinName,
			ID:         uint32(i + 1),
			Name:       expected.Name,
			Type:       expected.Type,
			Tag:        "tag-" + expected.Name,
			AttachType: expected.AttachType,
		})
		links = append(links, TaintPinnedLinkAttestation{
			Name:       expected.PinName,
			Path:       "/sys/fs/bpf/aegis-ege/taint/links/" + expected.PinName,
			ProgramPin: "/sys/fs/bpf/aegis-ege/taint/programs/" + expected.PinName,
			AttachType: expected.AttachType,
		})
	}

	maps := make([]PinnedMapAttestation, 0, len(taintBootstrapMaps))
	for i, expected := range taintBootstrapMaps {
		maps = append(maps, PinnedMapAttestation{
			Name:       expected.Name,
			ID:         uint32(100 + i),
			Type:       expected.Type,
			KeySize:    8,
			ValueSize:  8,
			MaxEntries: 4096,
		})
	}

	receipt := TaintBootstrapReceipt{
		Version:             TaintBootstrapReceiptVersion,
		ManifestDigest:      digest("manifest"),
		ManifestSignerKeyID: "ed25519:release",
		ArtifactSHA256:      digest("artifact"),
		ArtifactSize:        123,
		Host: BootstrapHostSnapshot{
			BootIDHash:    digest("boot"),
			KernelRelease: "6.x-test",
			BPFFSRoot:     "/sys/fs/bpf/aegis-ege/taint",
		},
		CgroupPath: "/sys/fs/cgroup/aegis-test",
		Programs:   programs,
		Maps:       maps,
		Links:      links,
		CompletedAt: time.Date(
			2026, 10, 2, 2, 0, 0, 0, time.UTC,
		),
	}

	signed, err := SignTaintBootstrapReceipt(receipt, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifySignedTaintBootstrapReceipt(signed, publicKey); err != nil {
		t.Fatal(err)
	}

	tampered := signed
	tampered.Receipt.CgroupPath = "/sys/fs/cgroup/other"
	if err := VerifySignedTaintBootstrapReceipt(tampered, publicKey); err == nil {
		t.Fatal("tampered taint bootstrap receipt verified")
	}
}
