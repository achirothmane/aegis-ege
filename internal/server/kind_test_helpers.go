//go:build integration

package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

func prepareUntilStable(
	t *testing.T,
	client *http.Client,
	baseURL string,
	payload []byte,
) prepareResponse {
	t.Helper()
	for attempt := 0; attempt < 12; attempt++ {
		resp, err := client.Post(
			baseURL+"/v1/node-drains/prepare",
			"application/json",
			bytes.NewReader(payload),
		)
		if err != nil {
			t.Fatal(err)
		}
		var preparation prepareResponse
		decodeErr := json.NewDecoder(resp.Body).Decode(&preparation)
		_ = resp.Body.Close()
		if decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("prepare status=%d response=%+v", resp.StatusCode, preparation)
		}
		if preparation.Decision == decision.Allow && preparation.Authorization != nil {
			return preparation
		}
		if preparation.Decision == decision.Escalate &&
			hasServerReason(preparation.ReasonCodes, decision.ResourceVersionChanged) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		t.Fatalf("prepare did not reach stable ALLOW: %+v", preparation)
	}
	t.Fatal("prepare remained unstable after retries")
	return prepareResponse{}
}

func hasServerReason(reasons []decision.ReasonCode, target decision.ReasonCode) bool {
	for _, reason := range reasons {
		if reason == target {
			return true
		}
	}
	return false
}
