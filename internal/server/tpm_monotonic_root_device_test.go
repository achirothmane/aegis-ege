//go:build linux && cgo

package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

func TestTPMRootEndorsementIdentityRotationBlocksExistingPermit(t *testing.T) {
	f := newTPMRootCrashFixture(t, tpm2.TPMHandle(0x0180A141))

	before, err := f.root.deviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	counterBefore, err := f.root.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := (tpm2.ChangeEPS{
		AuthHandle: tpm2.AuthHandle{
			Handle: tpm2.TPMRHPlatform,
			Name:   tpm2.HandleName(tpm2.TPMRHPlatform),
			Auth:   tpm2.PasswordAuth(nil),
		},
	}).Execute(f.root.tpm); err != nil {
		t.Fatalf("rotate endorsement primary seed: %v", err)
	}

	after, err := f.root.deviceIdentity(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatalf("endorsement identity did not change after ChangeEPS: %s", before)
	}

	counterAfter, err := f.root.readCounter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if counterAfter != counterBefore {
		t.Fatalf("device-identity rotation unexpectedly changed monotonic counter: before=%d after=%d", counterBefore, counterAfter)
	}

	recorder := executeRootedCapabilityPermit(t, f.srv, f.permitT1)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("existing permit expected 409 after TPM identity change, got=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "CAPABILITY_ROOT_DEVICE_CHANGED") {
		t.Fatalf("unexpected device-change denial: %s", recorder.Body.String())
	}
	if f.controller.executeCalls != 0 {
		t.Fatalf("TPM identity change reached mutation controller %d times", f.controller.executeCalls)
	}
	if _, err := f.root.Current(context.Background(), f.scope); !errors.Is(err, ErrTPMMonotonicRootDeviceChanged) {
		t.Fatalf("expected device identity change evidence, got %v", err)
	}
}
