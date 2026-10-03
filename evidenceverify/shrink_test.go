package evidenceverify_test

import (
	"encoding/json"
	"testing"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
)

// A signed, trusted history can accurately retain an unsupported claim. Each
// witness changes one semantic join while retaining every other mechanism.
func TestKernelShrinkSignedCommitRequiresBoundRelations(t *testing.T) {
	cases := map[string]func(*fixture){
		"effect":    func(f *fixture) { f.d.Commit.EffectID = "another-effect" },
		"attempt":   func(f *fixture) { f.d.Commit.AttemptID = "another-attempt" },
		"custody":   func(f *fixture) { f.d.Commit.CustodyGeneration++ },
		"owner":     func(f *fixture) { f.d.Commit.Owner.ID = "another-owner" },
		"authority": func(f *fixture) { f.d.Commit.AuthorityActive = false },
		"basis":     func(f *fixture) { f.a.PolicyHash = "producer-selected-policy" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(f)
			f.addHistory(t)
			r := f.verify(t)
			if r.ClaimsSupported || r.Closure != "UNKNOWN" || r.HistoricalTrust != "TRUSTED_HISTORY" || r.Signatures != "VALID" {
				t.Fatalf("removed %s relation accepted a false exact-effect claim: %+v", name, r)
			}
		})
	}
}

func TestKernelShrinkHistoryCannotBindForeignBundle(t *testing.T) {
	f := newFixture(t)
	f.addHistory(t)
	// Preserve the exact effect and all signatures. Re-sign only the producer's
	// evidence for another intent; the retained outcome belongs to the old bundle.
	f.e.IntentID = "another-intent"
	f.refresh(t)
	r := f.verify(t)
	if r.ClaimsSupported || r.HistoricalTrust != "UNTRUSTED_HISTORY" || r.Closure != "CLOSED" || r.Causality != "EXACT_COMMIT_RECORD" || r.Signatures != "VALID" {
		t.Fatalf("foreign bundle inherited governing history, or history failure erased effect truth: %+v", r)
	}
}

func TestKernelShrinkPolicyMigrationCannotChooseClaimFromBundle(t *testing.T) {
	for _, claim := range []string{"EXACT_EFFECT", "POSTCONDITION"} {
		t.Run(claim, func(t *testing.T) {
			f := newFixture(t)
			f.e.ClaimType = claim
			if claim == "POSTCONDITION" {
				f.d.Commit = nil
				f.e.ClaimedCausality = "STATE_ONLY"
			}
			f.addHistory(t)
			var legacy map[string]json.RawMessage
			if err := json.Unmarshal(marshal(t, f.p), &legacy); err != nil {
				t.Fatal(err)
			}
			delete(legacy, "required_claim_type")
			r := v.Verify(marshal(t, f.b), marshal(t, legacy))
			if r.ClaimsSupported || r.Structure != "INVALID" || r.RequiredClaimType != "" || r.Closure != "UNKNOWN" {
				t.Fatalf("legacy policy inherited the producer's %s standard: %+v", claim, r)
			}
		})
	}
}
