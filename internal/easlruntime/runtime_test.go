package easlruntime

import (
	"errors"
	"testing"
	"time"

	"github.com/achirothmane/easl"

	"github.com/achirothmane/aegis-ege/internal/testsupport"
)

func TestRegistryFailsClosedBeforeBindingThenUsesVerifiedRuntime(t *testing.T) {
	_, err := Evaluate(easl.Snapshot{At: time.Now().UTC()})
	if !errors.Is(err, ErrRuntimeUnavailable) {
		t.Fatalf("Evaluate before Bind error = %v, want %v", err, ErrRuntimeUnavailable)
	}

	runtime, err := testsupport.NewSyntheticEASLRuntime()
	if err != nil {
		t.Fatal(err)
	}
	if err := Bind(runtime); err != nil {
		t.Fatal(err)
	}

	got, err := Evaluate(easl.Snapshot{
		At: time.Date(2026, 9, 28, 4, 45, 0, 0, time.UTC),
		Assumptions: []easl.Assumption{{ID: "registry-ready"}},
	})
	if err != nil {
		t.Fatalf("Evaluate after Bind error = %v", err)
	}
	if got.State != easl.StateValid {
		t.Fatalf("expected VALID after verified runtime bind, got %+v", got)
	}
}
