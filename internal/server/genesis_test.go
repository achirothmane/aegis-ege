package server

import (
	"testing"

	"github.com/achirothmane/easl"
	"github.com/achirothmane/aegis-ege/internal/testsupport"
)

func readyEASLRuntime(t *testing.T) *easl.Runtime {
	t.Helper()
	runtime, err := testsupport.NewSyntheticEASLRuntime()
	if err != nil {
		t.Fatalf("create synthetic EASL runtime: %v", err)
	}
	return runtime
}
