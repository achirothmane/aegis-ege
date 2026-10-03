//go:build linux

package computesettlement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/achirothmane/aegis-ege/internal/kernelfabric"
)

type vcs11HeadAnchor struct {
	mu    sync.Mutex
	state kernelfabric.DurableHeadAnchorState
}

func (a *vcs11HeadAnchor) Current(context.Context) (kernelfabric.DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.state, nil
}

func (a *vcs11HeadAnchor) CompareAndAdvance(
	_ context.Context,
	expected,
	next kernelfabric.DurableHeadAnchorState,
) (kernelfabric.DurableHeadAnchorState, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != expected {
		return a.state, errors.New("compare failed")
	}
	if next.Sequence != expected.Sequence+1 {
		return a.state, errors.New("non-successor")
	}
	a.state = next
	return a.state, nil
}

func TestVCS11DurableEnrollmentReceiptDrivesSettlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ek := "sha256:" + strings.Repeat("a", 64)
	enrolled := vcs11Identity(live.state.DeviceID, ek, live.now.Add(-time.Minute))
	commitment := vcs09Commitment(
		t,
		ek,
		"sha256:"+strings.Repeat("b", 64),
		61,
	)
	store := vcs11Store(t)
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "r1", 1, "", enrolled)
	d1, err := store.Append(context.Background(), r1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}

	root, err := CaptureDurableEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		enrolled,
		store,
		enrollmentPub,
		live.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if root.EnrollmentReceiptDigest != d1 {
		t.Fatalf("durable enrollment receipt digest=%s want=%s", root.EnrollmentReceiptDigest, d1)
	}
	if root.EnrollmentReceipt.Receipt.ReceiptID != "r1" {
		t.Fatalf("unexpected durable enrollment receipt: %+v", root.EnrollmentReceipt.Receipt)
	}

	f := vcs04Fixture(t)
	providerAuthority := vcs06Authority(t)
	tenantAuthority := vcs06Authority(t)
	provenanceAuthority := vcs06Authority(t)
	streams := vcs05FullPerformanceStreams(f.receipt, 1200, 1200)
	measurements := vcs06Measurements(t, f, live.profile, streams, providerAuthority, tenantAuthority)
	provenance := vcs07Provenance(t, f, live.profile, root.Root, provenanceAuthority)
	bindings := vcs07Bindings(t, f, measurements, provenance, provenanceAuthority)
	result := vcs07Reconcile(
		t,
		f,
		live.profile,
		streams,
		measurements,
		vcs06Verifiers(providerAuthority, tenantAuthority),
		root.Root,
		provenance,
		bindings,
		provenanceAuthority,
	)
	if result.Disposition != Settled {
		t.Fatalf("durably enrolled hardware root should settle: got %s (%s)", result.Disposition, result.Detail)
	}
}

func TestVCS11RolledBackValidReceiptCannotDriveSettlement(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := vcs11Store(t)
	ek1 := "sha256:" + strings.Repeat("a", 64)
	id1 := vcs11Identity(live.state.DeviceID, ek1, live.now.Add(-2*time.Minute))
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "r1", 1, "", id1)
	d1, err := store.Append(context.Background(), r1, enrollmentPub)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := os.ReadFile(store.Store.Path)
	if err != nil {
		t.Fatal(err)
	}

	ek2 := "sha256:" + strings.Repeat("c", 64)
	id2 := vcs11Identity(live.state.DeviceID, ek2, live.now.Add(-time.Minute))
	r2 := vcs11SignedReceipt(t, enrollmentPriv, "r2", 2, d1, id2)
	if _, err := store.Append(context.Background(), r2, enrollmentPub); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(store.Store.Path, snapshot, 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(store.Store.Path + ".pending")

	commitment := vcs09Commitment(
		t,
		ek2,
		"sha256:"+strings.Repeat("d", 64),
		62,
	)
	_, err = CaptureDurableEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		id2,
		store,
		enrollmentPub,
		live.now,
	)
	if !errors.Is(err, kernelfabric.ErrEnrollmentIdentityRollback) {
		t.Fatalf("expected durable enrollment rollback rejection, got %v", err)
	}
}

func TestVCS11ReceiptForDifferentIdentityCannotDriveCurrentRoot(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	store := vcs11Store(t)
	receiptIdentity := vcs11Identity(
		live.state.DeviceID,
		"sha256:"+strings.Repeat("a", 64),
		live.now.Add(-time.Minute),
	)
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "r1", 1, "", receiptIdentity)
	if _, err := store.Append(context.Background(), r1, enrollmentPub); err != nil {
		t.Fatal(err)
	}

	currentIdentity := receiptIdentity
	currentIdentity.EKSPKISHA256 = "sha256:" + strings.Repeat("b", 64)
	commitment := vcs09Commitment(
		t,
		currentIdentity.EKSPKISHA256,
		"sha256:"+strings.Repeat("c", 64),
		63,
	)
	_, err = CaptureDurableEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		currentIdentity,
		store,
		enrollmentPub,
		live.now,
	)
	if err == nil {
		t.Fatal("receipt for different enrolled identity must not drive current root")
	}
}

func TestVCS11WrongEnrollmentAuthorityCannotDriveRoot(t *testing.T) {
	live := newVCS08LiveFixture(t)
	enrollmentPub, enrollmentPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ek := "sha256:" + strings.Repeat("a", 64)
	enrolled := vcs11Identity(live.state.DeviceID, ek, live.now.Add(-time.Minute))
	store := vcs11Store(t)
	r1 := vcs11SignedReceipt(t, enrollmentPriv, "r1", 1, "", enrolled)
	if _, err := store.Append(context.Background(), r1, enrollmentPub); err != nil {
		t.Fatal(err)
	}
	commitment := vcs09Commitment(
		t,
		ek,
		"sha256:"+strings.Repeat("b", 64),
		64,
	)
	_, err = CaptureDurableEnrollmentBoundAegisExecutionRoot(
		context.Background(),
		os.Getpid(),
		live.state,
		live.activation,
		live.runtimeLease,
		live.profile,
		live.trust,
		vcs09PlatformMeasurementSource{commitment: commitment},
		enrolled,
		store,
		wrongPub,
		live.now,
	)
	if err == nil {
		t.Fatal("wrong enrollment authority must not validate durable receipt")
	}
}

func vcs11Store(t *testing.T) kernelfabric.AnchoredEnrollmentIdentityStore {
	t.Helper()
	return kernelfabric.AnchoredEnrollmentIdentityStore{
		Store: kernelfabric.EnrollmentIdentityReceiptStore{
			Path: filepath.Join(t.TempDir(), "enrollment-current.json"),
		},
		Anchor: &vcs11HeadAnchor{},
	}
}

func vcs11Identity(
	deviceID,
	ekDigest string,
	enrolledAt time.Time,
) kernelfabric.EnrolledTPMIdentity {
	return kernelfabric.EnrolledTPMIdentity{
		DeviceID:                   deviceID,
		AK:                         kernelfabric.TPMAttestationParameters{Public: []byte("ak-public-vcs11-compute")},
		EKSPKISHA256:               ekDigest,
		BootstrapAttestorPublicKey: make([]byte, ed25519.PublicKeySize),
		TPMManufacturer:            "SIM",
		TPMVendorInfo:              "VCS11",
		TPMFirmwareMajor:           1,
		TPMFirmwareMinor:           2,
		EnrolledAt:                 enrolledAt.UTC(),
	}
}

func vcs11SignedReceipt(
	t *testing.T,
	priv ed25519.PrivateKey,
	id string,
	sequence uint64,
	previous string,
	identity kernelfabric.EnrolledTPMIdentity,
) kernelfabric.SignedEnrollmentIdentityReceipt {
	t.Helper()
	receipt, err := kernelfabric.NewEnrollmentIdentityReceipt(
		id,
		sequence,
		previous,
		identity,
		identity.EnrolledAt.Add(time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := kernelfabric.SignEnrollmentIdentityReceipt(receipt, priv)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
