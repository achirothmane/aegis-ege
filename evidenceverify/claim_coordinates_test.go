package evidenceverify_test

import "testing"

// A/C/P describe semantic truth. They cannot replace the independently pinned
// claim, trust roots, signatures, or replay cardinality in a portable proof.
func TestACPConjunctionDoesNotReplaceEvidenceContract(t *testing.T) {
	for _, name := range []string{"wrong-claim", "untrusted-root", "duplicate-effect", "wrong-build"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			switch name {
			case "wrong-claim":
				f.p.RequiredClaimType = "POSTCONDITION"
			case "untrusted-root":
				f.p.RoleKeys["destination"] = "unprovisioned"
			case "duplicate-effect":
				f.d.EffectCount = 2
				f.refresh(t)
			case "wrong-build":
				f.p.BuildSHA = "1111111111111111111111111111111111111111"
			}
			if report := f.verify(t); report.ClaimsSupported {
				t.Fatalf("A/C/P silently replaced the evidence/identity/policy contract: %+v", report)
			}
		})
	}
}

func TestPostconditionProfileDoesNotRequireCommitAuthorityOrExactCause(t *testing.T) {
	f := newFixture(t)
	f.p.RequiredClaimType, f.e.ClaimType = "POSTCONDITION", "POSTCONDITION"
	f.e.ClaimedCausality = "STATE_ONLY"
	f.d.Commit = nil
	f.e.Admitted = false
	f.a.AuthorityActive = false
	f.e.ClaimedHistory = "UNTRUSTED_HISTORY"
	f.b.History, f.p.Checkpoint = nil, nil
	f.refresh(t)
	report := f.verify(t)
	if !report.ClaimsSupported || report.Closure != "CLOSED" || report.Admitted || report.AuthorityAtCommit != "UNPROVEN" || report.Causality != "STATE_ONLY" {
		t.Fatalf("postcondition-only claim incorrectly inherited exact-effect obligations: %+v", report)
	}
}

// A trusted signed snapshot is not a live destination query. This pins the
// boundary of the current offline profile, rather than inventing freshness
// from a signature, exact commit, build SHA or trusted history. The independent
// observer must supply the current view outside this offline evaluator.
func TestAuthenticRetainedSnapshotDoesNotProvePresentTruth(t *testing.T) {
	f := newFixture(t)
	if report := f.verify(t); !report.ClaimsSupported || report.Closure != "CLOSED" {
		t.Fatalf("initial current-view control failed: %+v", report)
	}
	// Current native-world truth changes. The old signed bundle is retained.
	f.d.Observed.Digest = "changed-in-the-world-after-the-signed-snapshot"
	if f.d.Observed == f.e.Request.After {
		t.Fatal("present postcondition did not change")
	}
	if report := f.verify(t); !report.ClaimsSupported || report.Closure != "CLOSED" {
		t.Fatalf("offline verifier unexpectedly acquired a live destination view: %+v", report)
	}
	// A new truthful view removes the false current closure, preserving A/C.
	f.refresh(t)
	if report := f.verify(t); report.ClaimsSupported || report.Closure != "UNKNOWN" || report.AuthorityAtCommit != "VALID_AT_COMMIT" || report.Causality != "EXACT_COMMIT_RECORD" {
		t.Fatalf("fresh observation did not distinguish current truth: %+v", report)
	}
}
