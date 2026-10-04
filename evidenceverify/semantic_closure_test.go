package evidenceverify_test

import (
	"bytes"
	"testing"
)

// Keep the exact admission, producer/custody tuple and independent obligation
// fixed. A trusted history retains every claim, including the false ones.
// Neither custody nor an authenticated historical commit supplies both missing
// closure relations: this attempt caused the effect; its state still holds.
func TestSemanticClosureCannotBeDerivedFromCustody(t *testing.T) {
	f := newFixture(t)
	admission := marshal(t, f.a)
	execution := marshal(t, f.e)
	policy := marshal(t, f.p)
	original := f.d
	for _, name := range []string{"owned", "foreign-attempt", "changed-postcondition"} {
		t.Run(name, func(t *testing.T) {
			f.d = original
			f.b.History = nil
			f.p.Checkpoint = nil
			f.e.ClaimedHistory = "UNTRUSTED_HISTORY"
			switch name {
			case "foreign-attempt":
				// An honest observer has matching state and a one-effect tally,
				// but no commit receipt for the requested attempt.
				f.d.Commit = nil
			case "changed-postcondition":
				f.d.Observed.Digest = "changed-after-commit"
			}
			if !bytes.Equal(admission, marshal(t, f.a)) || !bytes.Equal(execution, marshal(t, f.e)) || !bytes.Equal(policy, marshal(t, f.p)) {
				t.Fatal("trial changed the retained admission/custody/obligation projection")
			}
			f.addHistory(t)
			r := f.verify(t)
			wantClosure, wantCausality := "CLOSED", "EXACT_COMMIT_RECORD"
			if name == "foreign-attempt" {
				wantClosure, wantCausality = "UNKNOWN", "STATE_ONLY"
			} else if name == "changed-postcondition" {
				wantClosure = "UNKNOWN"
			}
			if r.Closure != wantClosure || r.Causality != wantCausality || r.ClaimsSupported != (name == "owned") {
				t.Fatalf("semantic closure merge changed the independently required answer: %+v", r)
			}
			if !r.Admitted || r.Signatures != "VALID" || r.TrustRoots != "VALID" || r.HistoricalTrust != "TRUSTED_HISTORY" || r.RequiredClaimType != "EXACT_EFFECT" || r.ExternallyCommittedEffects == nil || *r.ExternallyCommittedEffects != 1 {
				t.Fatalf("counterexample lost its valid retained mechanisms: %+v", r)
			}
			if name == "changed-postcondition" && r.AuthorityAtCommit != "VALID_AT_COMMIT" {
				t.Fatal("current state drift erased an independently proven historical cause")
			}
		})
	}
}
