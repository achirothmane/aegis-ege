package evidenceverify

import (
	"encoding/json"
	"testing"

	"github.com/ucarion/jcs"
)

// The production verifier has no JCS dependency. Compare its deliberately
// bounded encoding with the producer's actual canonicalizer in tests.
func TestSuccessionCanonicalMatchesProducerWithinProfile(t *testing.T) {
	values := []any{map[string]any{"z": "<&>\n\t\"\\", "a": uint64(8), "nested": []any{true, nil, map[string]any{"b": "head", "a": uint64(0)}}}, map[string]any{"epoch": uint64((1 << 53) - 1)}}
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var producerValue any
		if err := json.Unmarshal(raw, &producerValue); err != nil {
			t.Fatal(err)
		}
		want, err := jcs.Format(producerValue)
		if err != nil {
			t.Fatal(err)
		}
		got, err := successionCanonical(value)
		if err != nil || string(got) != want {
			t.Fatalf("canonical encoding disagrees with existing producer: got=%s want=%s err=%v", got, want, err)
		}
	}
}

func TestSuccessionCanonicalFailsClosedOutsideProfile(t *testing.T) {
	for _, value := range []any{map[string]any{"epoch": uint64(1 << 53)}, map[string]any{"epoch": -1}, map[string]any{"epoch": 1.5}, map[string]any{"nonascii": "é"}, map[string]any{"é": "key"}} {
		if _, err := successionCanonical(value); err == nil {
			t.Fatalf("unsupported value accepted: %v", value)
		}
	}
}
