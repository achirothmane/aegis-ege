package simulation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// One native effect, two retained CROSSING attempts. The admission, all custody
// rows, observed after-state and effect tally are identical in the owned and
// foreign worlds. Only the destination's exact commit identifies the cause.
// No effect row is forged or edited to construct the foreign-attempt witness.
func TestPostgresCompositeSemanticClosurePairs(t *testing.T) {
	build, binary := os.Getenv("COMPOSITE_BUILD_SHA"), os.Getenv("EVIDENCE_VERIFY_BINARY")
	if len(build) != 40 || binary == "" {
		if os.Getenv("COMPOSITE_REQUIRE") == "1" {
			t.Fatal("COMPOSITE_BUILD_SHA and EVIDENCE_VERIFY_BINARY are required")
		}
		t.Skip("native semantic closure inputs are not set")
	}
	p := v.Policy{Schema: v.Schema, BuildSHA: build, CaseID: "semantic-closure", DestinationProfile: "postgresql/native-fence/v1", AdmissionPolicyHash: v.ContentDigest([]byte("exact active admission and retained custody")), RequiredClaimType: "EXACT_EFFECT", MaximumGrade: "native", PublicKeys: map[string]string{}, RoleKeys: map[string]string{}}
	keys := map[string]ed25519.PrivateKey{}
	for _, role := range []string{"admission", "execution", "destination"} {
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		p.RoleKeys[role] = role + ":semantic-closure"
		p.PublicKeys[p.RoleKeys[role]] = base64.StdEncoding.EncodeToString(pub)
		keys[role] = key
	}
	seal := func(t *testing.T, role string, value any) v.Envelope {
		t.Helper()
		env, err := v.Seal(role, p.RoleKeys[role], keys[role], value)
		if err != nil {
			t.Fatal(err)
		}
		return env
	}
	state := func(s r.State) v.State { return v.State{Target: s.Target, Revision: s.Revision, Digest: s.Digest} }
	var projection []byte
	for _, name := range []string{"owned", "foreign-attempt", "changed-postcondition"} {
		t.Run(name, func(t *testing.T) {
			a, req := setupPostgresNativeFence(t)
			ctx := context.Background()
			first, err := r.ReserveFenced(ctx, req, a)
			if err != nil {
				t.Fatal(err)
			}
			other := req
			other.AttemptID = "attempt:other"
			crossings := []r.FencedCustody{first.Custody}
			if name != "changed-postcondition" {
				second, err := r.ReserveFenced(ctx, other, a)
				if err != nil {
					t.Fatal(err)
				}
				crossings = append(crossings, second.Custody)
			}
			for i := range crossings {
				crossings[i].Phase = r.CustodyCrossing
				before := crossings[i]
				before.Phase = r.CustodyReserved
				if err := a.TransitionFencedCustodyCAS(ctx, before, crossings[i]); err != nil {
					t.Fatal(err)
				}
			}
			selected := crossings[0]
			if name == "foreign-attempt" {
				selected = crossings[1]
			}
			if _, err := a.ExecuteFenced(ctx, req.Transition, selected); err != nil {
				t.Fatal(err)
			}
			if name == "changed-postcondition" {
				atCommit, err := a.CurrentState(ctx, req.Current.Target)
				if err != nil || !atCommit.Equal(req.Transition.To) {
					t.Fatal("native commit did not establish the required after-state")
				}
				var before, after string
				if err := a.db.QueryRow("SELECT row_to_json(e)::text FROM " + nativeFenceTable("effects") + " e").Scan(&before); err != nil {
					t.Fatal(err)
				}
				if _, err := a.db.Exec("UPDATE "+nativeFenceTable("target_state")+" SET digest=$1 WHERE target=$2", "changed-after-commit", req.Current.Target); err != nil {
					t.Fatal(err)
				}
				if err := a.db.QueryRow("SELECT row_to_json(e)::text FROM " + nativeFenceTable("effects") + " e").Scan(&after); err != nil || before != after {
					t.Fatal("postcondition drift changed the historical native receipt")
				}
			}
			for _, c := range crossings {
				retained, err := a.LoadFencedCustody(ctx, c.EffectID, c.AttemptID)
				if err != nil || !retained.Equal(c) {
					t.Fatal("native execution changed retained custody")
				}
			}
			var commit v.Commit
			var committedAt time.Time
			err = a.db.QueryRow("SELECT effect_id,attempt_id,owner_id,owner_kind,generation,admission_binding,authority_epoch,authority_generation,authority_active,operation,target,from_revision,from_digest,to_revision,to_digest,created_at FROM "+nativeFenceTable("effects")).Scan(&commit.EffectID, &commit.AttemptID, &commit.Owner.ID, &commit.Owner.Kind, &commit.CustodyGeneration, &commit.AdmissionBinding, &commit.AuthorityEpoch, &commit.AuthorityGeneration, &commit.AuthorityActive, &commit.Operation, &commit.Before.Target, &commit.Before.Revision, &commit.Before.Digest, &commit.After.Revision, &commit.After.Digest, &committedAt)
			if err != nil {
				t.Fatal(err)
			}
			commit.After.Target = commit.Before.Target
			commit.CommittedAt = committedAt.UTC().Format(time.RFC3339Nano)
			observed, err := a.CurrentState(ctx, req.Current.Target)
			if err != nil {
				t.Fatal(err)
			}
			q := v.Request{Subject: v.Identity{ID: req.Subject.ID, Kind: req.Subject.Kind}, Executor: v.Identity{ID: req.Executor.ID, Kind: req.Executor.Kind}, Before: state(req.Current), After: state(req.Transition.To), Operation: req.Transition.Operation, AttemptID: req.AttemptID, AdmissionBinding: req.Admission.BindingDigest}
			e := v.Execution{BuildSHA: build, CaseID: p.CaseID, Grade: "native", ClaimType: "EXACT_EFFECT", IntentID: "intent:semantic-closure", Request: q, EffectID: first.Custody.EffectID, CustodyGeneration: 1, AuthorityEpoch: 1, AuthorityGeneration: 1, Admitted: true, ClaimedClosure: "CLOSED", ClaimedCausality: "EXACT_COMMIT_RECORD", ClaimedHistory: "UNTRUSTED_HISTORY"}
			admission := v.Admission{BuildSHA: build, CaseID: p.CaseID, PolicyHash: p.AdmissionPolicyHash, RequestBinding: q.AdmissionBinding, ObservedBefore: q.Before, AllowedOperation: q.Operation, AuthorityEpoch: 1, AuthorityGeneration: 1, AuthorityActive: true}
			d := v.Destination{BuildSHA: build, CaseID: p.CaseID, Profile: p.DestinationProfile, Observed: state(observed), EffectCount: uint64(nativeEffectCount(t, a)), Commit: &commit, AuthorityCurrentlyActive: true, CurrentAuthorityGeneration: 1}
			fixed, err := json.Marshal(struct {
				Admission v.Admission
				Execution v.Execution
				Custody   []r.FencedCustody
				Observed  v.State
				Tally     uint64
			}{admission, e, crossings, d.Observed, d.EffectCount})
			if err != nil {
				t.Fatal(err)
			}
			if name == "owned" {
				projection = fixed
			} else if name == "foreign-attempt" && !bytes.Equal(projection, fixed) {
				t.Fatal("native worlds differ outside the erased causal evidence")
			}
			if name == "foreign-attempt" {
				if _, err := a.ObserveFenced(ctx, req.Transition, crossings[0]); !errors.Is(err, errNativeObservation) || commit.AttemptID != other.AttemptID {
					t.Fatal("native observer substituted foreign causality")
				}
				// Preserve the raw foreign receipt separately. The destination
				// cannot offer an exact receipt for the requested attempt.
				d.Commit = nil
			}
			dest := seal(t, "destination", d)
			b := v.Bundle{Schema: v.Schema, Admission: seal(t, "admission", admission), Execution: seal(t, "execution", e), Destination: &dest}
			dir := t.TempDir()
			if root := os.Getenv("COMPOSITE_ARTIFACT_DIR"); root != "" {
				dir = filepath.Join(root, "semantic-closure", name)
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			writeCompositeJSON(t, filepath.Join(dir, "native-commit.json"), commit)
			writeCompositeJSON(t, filepath.Join(dir, "native-custody.json"), crossings)
			writeCompositeJSON(t, filepath.Join(dir, "bundle.json"), b)
			writeCompositeJSON(t, filepath.Join(dir, "fixture-policy.json"), p)
			inspect := exec.Command(binary, "--bundle", filepath.Join(dir, "bundle.json"), "--policy", filepath.Join(dir, "fixture-policy.json"), "--format", "json")
			inspect.Env = []string{"PATH=/usr/bin:/bin"}
			raw, err := inspect.Output()
			wantSupported := name == "owned"
			var exit *exec.ExitError
			if (err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1)) || (err == nil) != wantSupported {
				t.Fatalf("semantic closure merge changed consumer acceptance: %v %s", err, raw)
			}
			var report v.Report
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatal(err)
			}
			wantClosure, wantCausality := "CLOSED", "EXACT_COMMIT_RECORD"
			if name == "foreign-attempt" {
				wantClosure, wantCausality = "UNKNOWN", "STATE_ONLY"
			} else if name == "changed-postcondition" {
				wantClosure = "UNKNOWN"
			}
			if report.Closure != wantClosure || report.Causality != wantCausality || report.ClaimsSupported != wantSupported || !report.Admitted || report.Signatures != "VALID" || report.TrustRoots != "VALID" || report.RequiredClaimType != "EXACT_EFFECT" || report.ExternallyCommittedEffects == nil || *report.ExternallyCommittedEffects != 1 {
				t.Fatalf("semantic closure merge changed the independently required answer: %+v", report)
			}
			if name == "changed-postcondition" && report.AuthorityAtCommit != "VALID_AT_COMMIT" {
				t.Fatal("state drift erased the destination's proven historical authority")
			}
			if name != "changed-postcondition" && !observed.Equal(req.Transition.To) {
				t.Fatal("attempt pair does not have identical observed after-state")
			}
			observer := &observeOnlyComposite{postgresNativeFenceAdapter: a}
			retained := r.Custody{EffectID: crossings[0].EffectID, AttemptID: crossings[0].AttemptID, Target: crossings[0].Target, Owner: crossings[0].Owner}
			auth := r.Attestation{ID: "recovery:semantic-closure", Issuer: nativeObserverIssuer, BindingDigest: r.RecoveryBindingDigest(retained, nativeObserverIssuer)}
			recovery := r.Recover(ctx, r.RecoveryRequest{Original: req, Recoverer: nativeObserverIssuer, RecoveryAuthorization: auth}, observer)
			if string(recovery.Disposition) != wantClosure || recovery.BoundaryEntered || observer.forbiddenCalls != 0 || nativeEffectCount(t, a) != 1 {
				t.Fatalf("read-only runtime recovery changed the native answer: %+v", recovery)
			}
			writeCompositeJSON(t, filepath.Join(dir, "report.json"), report)
		})
	}
}
