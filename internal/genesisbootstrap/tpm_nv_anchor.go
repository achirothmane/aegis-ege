package genesisbootstrap

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	legacytpm2 "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/sys/unix"
)

const (
	tpmNVCounterType = uint32(1)
	tpmNVTypeMask    = uint32(0xF0)
	tpmNVTypeShift   = uint32(4)
	tpmNVAuthMax     = 64
)

type TPMNVCounterAnchor struct {
	devicePath string
	index      tpmutil.Handle
	auth       []byte
}

func NewTPMNVCounterAnchor(devicePath string, index uint32, auth []byte) (*TPMNVCounterAnchor, error) {
	if strings.TrimSpace(devicePath) == "" {
		return nil, errors.New("TPM device path is required")
	}
	if index == 0 {
		return nil, errors.New("TPM NV counter index is required")
	}
	if len(auth) == 0 {
		return nil, errors.New("TPM NV counter auth must not be empty")
	}
	if len(auth) > tpmNVAuthMax {
		return nil, fmt.Errorf("TPM NV counter auth is %d bytes; maximum supported is %d", len(auth), tpmNVAuthMax)
	}
	return &TPMNVCounterAnchor{
		devicePath: devicePath,
		index:      tpmutil.Handle(index),
		auth:       append([]byte(nil), auth...),
	}, nil
}

func LoadTPMNVAuthFile(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("TPM NV auth file is required")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open TPM NV auth file: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = unix.Close(fd)
		return nil, errors.New("wrap TPM NV auth file descriptor")
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat TPM NV auth file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("TPM NV auth file is not a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("TPM NV auth file permissions %o expose the secret; require owner-only access", info.Mode().Perm())
	}
	payload, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil {
		return nil, fmt.Errorf("read TPM NV auth file: %w", err)
	}
	if len(payload) > 4096 {
		return nil, errors.New("TPM NV auth file is unexpectedly large")
	}
	decoded, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("decode TPM NV auth file as base64: %w", err)
	}
	if len(decoded) == 0 {
		return nil, errors.New("TPM NV auth decodes to an empty value")
	}
	if len(decoded) > tpmNVAuthMax {
		return nil, fmt.Errorf("TPM NV auth is %d bytes; maximum supported is %d", len(decoded), tpmNVAuthMax)
	}
	return decoded, nil
}

func (a *TPMNVCounterAnchor) Identity(ctx context.Context) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	rwc, err := legacytpm2.OpenTPM(a.devicePath)
	if err != nil {
		return "", fmt.Errorf("open TPM device %q: %w", a.devicePath, err)
	}
	defer rwc.Close()

	pub, err := legacytpm2.NVReadPublic(rwc, a.index)
	if err != nil {
		return "", fmt.Errorf("read TPM NV public area 0x%08x: %w", uint32(a.index), err)
	}
	return tpmNVAnchorIdentity(pub, a.index)
}

func (a *TPMNVCounterAnchor) Read(ctx context.Context) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	rwc, err := legacytpm2.OpenTPM(a.devicePath)
	if err != nil {
		return 0, fmt.Errorf("open TPM device %q: %w", a.devicePath, err)
	}
	defer rwc.Close()

	pub, err := legacytpm2.NVReadPublic(rwc, a.index)
	if err != nil {
		return 0, fmt.Errorf("read TPM NV public area 0x%08x: %w", uint32(a.index), err)
	}
	if _, err := tpmNVAnchorIdentity(pub, a.index); err != nil {
		return 0, err
	}
	return readTPMNVCounter(rwc, a.index, a.auth)
}

func (a *TPMNVCounterAnchor) Advance(ctx context.Context, expectedCurrent uint64) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if expectedCurrent == ^uint64(0) {
		return 0, errors.New("TPM NV counter is exhausted")
	}

	rwc, err := legacytpm2.OpenTPM(a.devicePath)
	if err != nil {
		return 0, fmt.Errorf("open TPM device %q: %w", a.devicePath, err)
	}
	defer rwc.Close()

	pub, err := legacytpm2.NVReadPublic(rwc, a.index)
	if err != nil {
		return 0, fmt.Errorf("read TPM NV public area 0x%08x: %w", uint32(a.index), err)
	}
	if _, err := tpmNVAnchorIdentity(pub, a.index); err != nil {
		return 0, err
	}

	current, err := readTPMNVCounter(rwc, a.index, a.auth)
	if err != nil {
		return 0, err
	}
	if current != expectedCurrent {
		return 0, fmt.Errorf("TPM NV counter changed concurrently: got %d want %d", current, expectedCurrent)
	}
	if err := legacytpm2.NVIncrement(rwc, a.index, string(a.auth)); err != nil {
		return 0, fmt.Errorf("increment TPM NV counter 0x%08x: %w", uint32(a.index), err)
	}
	next, err := readTPMNVCounter(rwc, a.index, a.auth)
	if err != nil {
		return 0, fmt.Errorf("read TPM NV counter after increment: %w", err)
	}
	if next != expectedCurrent+1 {
		return 0, fmt.Errorf("TPM NV counter increment result %d; expected %d", next, expectedCurrent+1)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return next, nil
}

func tpmNVAnchorIdentity(pub legacytpm2.NVPublic, expectedIndex tpmutil.Handle) (string, error) {
	if pub.NVIndex != expectedIndex {
		return "", fmt.Errorf("TPM NV public index 0x%08x does not match configured index 0x%08x", uint32(pub.NVIndex), uint32(expectedIndex))
	}
	nvType := (uint32(pub.Attributes) & tpmNVTypeMask) >> tpmNVTypeShift
	if nvType != tpmNVCounterType {
		return "", fmt.Errorf("TPM NV index 0x%08x has type %d; require TPM_NT_COUNTER", uint32(expectedIndex), nvType)
	}
	if pub.DataSize != 8 {
		return "", fmt.Errorf("TPM NV counter 0x%08x has size %d; require 8", uint32(expectedIndex), pub.DataSize)
	}
	if pub.NameAlg != legacytpm2.AlgSHA256 {
		return "", fmt.Errorf("TPM NV counter 0x%08x uses name algorithm %s; require SHA256", uint32(expectedIndex), pub.NameAlg)
	}
	if pub.Attributes&legacytpm2.AttrAuthRead == 0 {
		return "", fmt.Errorf("TPM NV counter 0x%08x does not permit index-authenticated reads", uint32(expectedIndex))
	}
	if pub.Attributes&legacytpm2.AttrAuthWrite == 0 {
		return "", fmt.Errorf("TPM NV counter 0x%08x does not permit index-authenticated increments", uint32(expectedIndex))
	}

	wire, err := tpmutil.Pack(pub)
	if err != nil {
		return "", fmt.Errorf("marshal TPM NV public area: %w", err)
	}
	sum := sha256.Sum256(wire)
	name := make([]byte, 2+len(sum))
	binary.BigEndian.PutUint16(name[:2], uint16(legacytpm2.AlgSHA256))
	copy(name[2:], sum[:])
	return fmt.Sprintf("tpm2-nv:0x%08x:name:%s", uint32(expectedIndex), hex.EncodeToString(name)), nil
}

func readTPMNVCounter(rwc io.ReadWriter, index tpmutil.Handle, auth []byte) (uint64, error) {
	payload, err := legacytpm2.NVReadEx(rwc, index, index, string(auth), 0)
	if err != nil {
		return 0, fmt.Errorf("read TPM NV counter 0x%08x: %w", uint32(index), err)
	}
	if len(payload) != 8 {
		return 0, fmt.Errorf("TPM NV counter 0x%08x returned %d bytes; require 8", uint32(index), len(payload))
	}
	return binary.BigEndian.Uint64(payload), nil
}
