package evidenceverify_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	"github.com/achirothmane/aegis-ege/internal/journal"
)

type fixture struct {
	b    v.Bundle
	p    v.Policy
	e    v.Execution
	d    v.Destination
	a    v.Admission
	keys map[string]ed25519.PrivateKey
}

func marshal(t *testing.T, value any) []byte {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (f *fixture) seal(t *testing.T, role string, value any) v.Envelope {
	t.Helper()
	env, err := v.Seal(role, f.p.RoleKeys[role], f.keys[role], value)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (f *fixture) refresh(t *testing.T) {
	f.b.Admission = f.seal(t, "admission", f.a)
	f.b.Execution = f.seal(t, "execution", f.e)
	d := f.seal(t, "destination", f.d)
	f.b.Destination = &d
}

func (f *fixture) verify(t *testing.T) v.Report { return v.Verify(marshal(t, f.b), marshal(t, f.p)) }

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{b: v.Bundle{Schema: v.Schema}, p: v.Policy{Schema: v.Schema, BuildSHA: strings.Repeat("a", 40), CaseID: "unit-case", DestinationProfile: "postgresql/native-fence/v1", AdmissionPolicyHash: v.ContentDigest([]byte("exact active admission policy")), RequiredClaimType: "EXACT_EFFECT", MaximumGrade: "unit", HistoryID: "history:unit-case", PublicKeys: map[string]string{}, RoleKeys: map[string]string{}}, keys: map[string]ed25519.PrivateKey{}}
	for _, role := range []string{"admission", "execution", "destination", "history", "witness"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		id := role + ":fixture"
		f.keys[role] = key
		f.p.RoleKeys[role] = id
		f.p.PublicKeys[id] = base64.StdEncoding.EncodeToString(pub)
	}
	q := v.Request{Subject: v.Identity{ID: "service", Kind: "subject"}, Executor: v.Identity{ID: "worker-A", Kind: "worker"}, Before: v.State{Target: "account", Revision: "1", Digest: "before"}, After: v.State{Target: "account", Revision: "2", Digest: "after"}, Operation: "update", AttemptID: "attempt-1"}
	parts := []string{q.Subject.ID, q.Subject.Kind, q.Before.Target, q.Before.Revision, q.Before.Digest, q.Operation, q.After.Revision, q.After.Digest}
	q.AdmissionBinding = v.RelationDigest(append([]string{"admission-v0"}, parts...)...)
	f.e = v.Execution{BuildSHA: f.p.BuildSHA, CaseID: f.p.CaseID, Grade: "unit", ClaimType: "EXACT_EFFECT", IntentID: "intent-1", Request: q, EffectID: v.RelationDigest(append([]string{"effect-v0"}, parts...)...), CustodyGeneration: 1, AuthorityEpoch: 1, AuthorityGeneration: 1, Admitted: true, AcknowledgementLost: true, RecoveredBy: v.Identity{ID: "observer", Kind: "observer"}, ClaimedClosure: "CLOSED", ClaimedCausality: "EXACT_COMMIT_RECORD", ClaimedHistory: "UNTRUSTED_HISTORY"}
	f.a = v.Admission{BuildSHA: f.p.BuildSHA, CaseID: f.p.CaseID, PolicyHash: f.p.AdmissionPolicyHash, RequestBinding: q.AdmissionBinding, ObservedBefore: q.Before, AllowedOperation: q.Operation, AuthorityEpoch: 1, AuthorityGeneration: 1, AuthorityActive: true}
	f.d = v.Destination{BuildSHA: f.p.BuildSHA, CaseID: f.p.CaseID, Profile: f.p.DestinationProfile, Observed: q.After, EffectCount: 1, CurrentAuthorityGeneration: 2, Commit: &v.Commit{EffectID: f.e.EffectID, AttemptID: q.AttemptID, Owner: q.Executor, CustodyGeneration: 1, AdmissionBinding: q.AdmissionBinding, AuthorityEpoch: 1, AuthorityGeneration: 1, AuthorityActive: true, Operation: q.Operation, Before: q.Before, After: q.After, CommittedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
	f.refresh(t)
	return f
}

// Use the real journal producer, not a verifier-specific imitation of its
// encoding. Memory witness makes this a unit grade, not native evidence.
func (f *fixture) addHistory(t *testing.T) {
	t.Helper()
	f.e.ClaimedHistory = "TRUSTED_HISTORY"
	f.refresh(t)
	path := filepath.Join(t.TempDir(), "history.jsonl")
	anchorPath := path + ".anchor"
	signer, err := journal.NewEd25519Signer(f.p.RoleKeys["history"], f.keys["history"])
	if err != nil {
		t.Fatal(err)
	}
	keyring := journal.NewEd25519Keyring()
	if err := keyring.Add(signer.KeyID(), signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	witness := journal.NewMemoryHeadStore()
	j, err := journal.CreateAnchoredFileJournal(context.Background(), path, anchorPath, f.p.HistoryID, signer, keyring, witness)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.Append(context.Background(), journal.Event{Type: journal.EventOutcome, ActionID: f.e.EffectID, AttemptID: f.e.Request.AttemptID, PayloadDigest: v.BundleHistoryBinding(f.b), OutcomeVerdict: f.e.ClaimedClosure}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	anchor, err := os.ReadFile(anchorPath)
	if err != nil {
		t.Fatal(err)
	}
	head, err := witness.Load(context.Background(), f.p.HistoryID)
	if err != nil {
		t.Fatal(err)
	}
	f.p.Checkpoint = &v.Head{JournalID: head.JournalID, Sequence: head.Sequence, HeadHash: head.HeadHash, KeyID: head.KeyID}
	f.b.History = &v.History{Anchor: anchor, Witness: f.seal(t, "witness", v.Witness{BuildSHA: f.p.BuildSHA, CaseID: f.p.CaseID, Head: *f.p.Checkpoint})}
	for _, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		f.b.History.Entries = append(f.b.History.Entries, append(json.RawMessage(nil), line...))
	}
}

func TestExactCommittedEffectClosesAfterAuthorityRevocation(t *testing.T) {
	f := newFixture(t)
	f.addHistory(t)
	r := f.verify(t)
	if !r.ClaimsSupported || r.Closure != "CLOSED" || r.HistoricalTrust != "TRUSTED_HISTORY" || r.AuthorityAtCommit != "VALID_AT_COMMIT" || r.AuthorityCurrentlyActive == nil || *r.AuthorityCurrentlyActive || r.Causality != "EXACT_COMMIT_RECORD" {
		t.Fatalf("unexpected independent judgment: %+v", r)
	}
}

func TestIndentedTransportPreservesSignedValuesAndHistory(t *testing.T) {
	f := newFixture(t)
	f.addHistory(t)
	bundle, err := json.MarshalIndent(f.b, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := json.MarshalIndent(f.p, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	r := v.Verify(bundle, policy)
	if !r.ClaimsSupported || r.Signatures != "VALID" || r.HistoricalTrust != "TRUSTED_HISTORY" {
		t.Fatalf("transport formatting invalidated signed evidence: %+v", r)
	}
	// Formatting tolerance must never erase whitespace inside a signed value.
	tampered := bytes.Replace(bundle, []byte("intent-1"), []byte("intent- 1"), 1)
	r = v.Verify(tampered, policy)
	if r.ClaimsSupported || r.Signatures != "INVALID" {
		t.Fatalf("value mutation escaped signature checking: %+v", r)
	}
}

func TestSignedFalseClaimsAreNotAutomaticallyTrue(t *testing.T) {
	cases := map[string]func(*fixture){
		"foreign-attempt":                func(f *fixture) { f.d.Commit.AttemptID = "another-attempt" },
		"foreign-owner":                  func(f *fixture) { f.d.Commit.Owner.ID = "another-owner" },
		"foreign-owner-kind":             func(f *fixture) { f.d.Commit.Owner.Kind = "another-kind" },
		"changed-custody-generation":     func(f *fixture) { f.d.Commit.CustodyGeneration++ },
		"changed-authority-generation":   func(f *fixture) { f.d.Commit.AuthorityGeneration++ },
		"changed-authority-epoch":        func(f *fixture) { f.d.Commit.AuthorityEpoch++ },
		"revoked-at-commit":              func(f *fixture) { f.d.Commit.AuthorityActive = false },
		"inactive-admission":             func(f *fixture) { f.a.AuthorityActive = false },
		"admission-for-other-state":      func(f *fixture) { f.a.ObservedBefore.Digest = "other" },
		"admission-for-other-operation":  func(f *fixture) { f.a.AllowedOperation = "delete" },
		"admission-for-other-binding":    func(f *fixture) { f.a.RequestBinding = "other" },
		"other-policy":                   func(f *fixture) { f.a.PolicyHash = "bundle-selected-policy" },
		"different-commit-state":         func(f *fixture) { f.d.Commit.After.Digest = "other" },
		"multiple-effects":               func(f *fixture) { f.d.EffectCount = 2 },
		"matching-state-only":            func(f *fixture) { f.d.Commit = nil },
		"other-build":                    func(f *fixture) { f.e.BuildSHA = strings.Repeat("b", 40) },
		"hardware-harness-inflation":     func(f *fixture) { f.e.Grade = "hardware" },
		"internal-rerun-inflation":       func(f *fixture) { f.e.Grade = "independently_reproduced" },
		"native-without-native-evidence": func(f *fixture) { f.e.Grade = "native"; f.p.MaximumGrade = "native"; f.b.Destination = nil },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			change(f)
			if name != "native-without-native-evidence" {
				f.refresh(t)
			} else {
				f.b.Execution = f.seal(t, "execution", f.e)
			}
			r := f.verify(t)
			if r.ClaimsSupported || r.Signatures != "VALID" || len(r.Errors) == 0 {
				t.Fatalf("signed false claim accepted: %+v", r)
			}
		})
	}
}

func TestClosureAndHistoryRemainIndependentDimensions(t *testing.T) {
	for _, closed := range []bool{true, false} {
		for _, trusted := range []bool{true, false} {
			name := "UNKNOWN"
			if closed {
				name = "CLOSED"
			}
			if trusted {
				name += "+TRUSTED_HISTORY"
			} else {
				name += "+UNTRUSTED_HISTORY"
			}
			t.Run(name, func(t *testing.T) {
				f := newFixture(t)
				if !closed {
					f.d.Commit = nil
					f.e.ClaimedClosure = "UNKNOWN"
					f.e.ClaimedCausality = "STATE_ONLY"
					f.refresh(t)
				}
				if trusted {
					f.addHistory(t)
				}
				r := f.verify(t)
				if !r.ClaimsSupported || r.Closure != f.e.ClaimedClosure || r.HistoricalTrust != f.e.ClaimedHistory {
					t.Fatalf("dimensions collapsed: %+v", r)
				}
			})
		}
	}
}

func TestPostconditionDoesNotClaimAttemptCausality(t *testing.T) {
	f := newFixture(t)
	f.p.RequiredClaimType = "POSTCONDITION"
	f.e.ClaimType = "POSTCONDITION"
	f.e.ClaimedCausality = "STATE_ONLY"
	f.d.Commit = nil
	f.refresh(t)
	r := f.verify(t)
	if !r.ClaimsSupported || r.Closure != "CLOSED" || r.Causality != "STATE_ONLY" || r.AuthorityAtCommit != "UNPROVEN" {
		t.Fatalf("post-state became causal evidence: %+v", r)
	}
}

func TestIndependentPolicyRejectsBundleClaimDowngrade(t *testing.T) {
	f := newFixture(t)
	// The relying party asks about the exact effect, but the signed producer
	// substitutes a truthful, weaker statement about matching destination state.
	f.e.ClaimType = "POSTCONDITION"
	f.e.ClaimedCausality = "STATE_ONLY"
	f.d.Commit = nil
	f.addHistory(t)
	r := f.verify(t)
	if r.ClaimsSupported || r.Closure != "UNKNOWN" || r.Signatures != "VALID" || r.HistoricalTrust != "TRUSTED_HISTORY" {
		t.Fatalf("bundle-selected postcondition satisfied the independent exact-effect obligation: %+v", r)
	}
	if !strings.Contains(strings.Join(r.Errors, "\n"), "claim type does not match the independent policy requirement") {
		t.Fatalf("downgrade was not rejected by the independent obligation: %+v", r)
	}
}

func TestIndependentClaimRequirementMustBeExplicit(t *testing.T) {
	for _, requirement := range []string{"", "ANY", "exact_effect", "EXACT_EFFECT "} {
		t.Run(requirement, func(t *testing.T) {
			f := newFixture(t)
			f.p.RequiredClaimType = requirement
			r := f.verify(t)
			if r.ClaimsSupported || r.Structure != "INVALID" || r.Closure != "UNKNOWN" || r.Signatures != "NOT_CHECKED" {
				t.Fatalf("missing/invalid independent obligation accepted: %+v", r)
			}
		})
	}
	f := newFixture(t)
	var policy map[string]any
	if err := json.Unmarshal(marshal(t, f.p), &policy); err != nil {
		t.Fatal(err)
	}
	delete(policy, "required_claim_type")
	r := v.Verify(marshal(t, f.b), marshal(t, policy))
	if r.ClaimsSupported || r.Structure != "INVALID" {
		t.Fatalf("legacy policy silently delegated its obligation to the bundle: %+v", r)
	}
}

func TestIndependentPostconditionRequirementRejectsDifferentClaim(t *testing.T) {
	f := newFixture(t)
	f.p.RequiredClaimType = "POSTCONDITION"
	r := f.verify(t)
	if r.ClaimsSupported || !strings.Contains(strings.Join(r.Errors, "\n"), "claim type does not match the independent policy requirement") {
		t.Fatalf("signed exact-effect claim silently changed the relying party's question: %+v", r)
	}
}

func TestNativeTallyDoesNotResolveUnknown(t *testing.T) {
	f := newFixture(t)
	f.e.Grade = "native"
	f.p.MaximumGrade = "native"
	f.e.ClaimedClosure = "UNKNOWN"
	f.e.ClaimedCausality = "UNPROVEN"
	f.d.Commit = nil
	f.d.Observed = v.State{}
	f.d.ObservationError = "Exact observation unavailable"
	f.refresh(t)
	f.addHistory(t)
	r := f.verify(t)
	if !r.ClaimsSupported || r.Closure != "UNKNOWN" || r.Causality != "UNPROVEN" || r.ExternallyCommittedEffects == nil || *r.ExternallyCommittedEffects != 1 {
		t.Fatalf("tally invented closure: %+v", r)
	}
}

func TestIndependentRootsAndContinuityCannotBeSelectedByBundle(t *testing.T) {
	for _, name := range []string{"wrong-root", "wrong-role", "tampered-signature", "wrong-checkpoint", "missing-checkpoint", "corrupt-chain", "other-history"} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.addHistory(t)
			switch name {
			case "wrong-root":
				pub, _, _ := ed25519.GenerateKey(rand.Reader)
				f.p.PublicKeys[f.p.RoleKeys["destination"]] = base64.StdEncoding.EncodeToString(pub)
			case "wrong-role":
				f.b.Destination.KeyID = f.p.RoleKeys["execution"]
			case "tampered-signature":
				f.b.Execution.Signature = base64.StdEncoding.EncodeToString(make([]byte, 64))
			case "wrong-checkpoint":
				f.p.Checkpoint.HeadHash = "other"
			case "missing-checkpoint":
				f.p.Checkpoint = nil
			case "corrupt-chain":
				f.b.History.Entries[0] = bytes.Replace(f.b.History.Entries[0], []byte("OUTCOME"), []byte("DECISION"), 1)
			case "other-history":
				f.p.HistoryID = "replacement-history"
			}
			r := f.verify(t)
			if r.ClaimsSupported {
				t.Fatalf("untrusted claim accepted: %+v", r)
			}
			if name == "missing-checkpoint" && (r.Closure != "CLOSED" || r.HistoricalTrust != "UNTRUSTED_HISTORY") {
				t.Fatalf("history failure rewrote operational evidence: %+v", r)
			}
		})
	}
}

func TestAmbiguousAndOversizedJSONFailsClosed(t *testing.T) {
	for _, input := range []string{`{"schema":"first","schema":"second"}`, `{"unknown":true}`, `{} {}`, strings.Repeat("[", 130) + "0" + strings.Repeat("]", 130), strings.Repeat(" ", v.MaxInputBytes+1)} {
		var b v.Bundle
		if err := v.Decode([]byte(input), &b); err == nil {
			t.Fatal("ambiguous/excessive input accepted")
		}
	}
}
