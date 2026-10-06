package simulation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

// All source names, policy predicates and new evidence records stay in research
// tests. Every native mutation below invokes the existing #241 implementation.
type normativeProducer struct {
	roots map[string]normativeRoot
	keys  map[string]ed25519.PrivateKey
}

func newNormativeProducer(t *testing.T) normativeProducer {
	t.Helper()
	producer := normativeProducer{roots: map[string]normativeRoot{}, keys: map[string]ed25519.PrivateKey{}}
	for _, item := range []struct{ id, role, principal string }{
		{"observer:1", "facts", "observer:one"},
		{"observer:2", "facts", "observer:two"},
		{"human:1", "approval", "human:one"},
		{"human:1-rotated", "approval", "human:one"},
		{"human:2", "approval", "human:two"},
		{"discloser:1", "disclosure", "discloser:one"},
		{"consenter:1", "consent", "consenter:one"},
	} {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		producer.roots[item.id] = normativeRoot{Role: item.role, Principal: item.principal, Key: public}
		producer.keys[item.id] = private
	}
	return producer
}

func (producer normativeProducer) sign(t *testing.T, keyID, role string, value any) v.Envelope {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(producer.keys[keyID], normativeSigningBytes(role, raw))
	return v.Envelope{KeyID: keyID, Payload: raw, Signature: base64.StdEncoding.EncodeToString(signature)}
}

func defaultNormativeFacts(req r.Request) normativeFacts {
	return normativeFacts{
		RecordID: "review:fixture:one", RequestBinding: req.Admission.BindingDigest,
		Before: noCustodyState(req.Current), AccountableOwner: "owner:fixture",
		ControlRecord: "audit:review:fixture", Uncertainty: 0.1,
		Flags: map[string]bool{
			"owner_recorded": true, "purpose_justified": true,
			"harm_review_passed": true, "privacy_review_passed": true,
			"truth_review_passed": true, "audit_recorded": true,
			"safety_impact": false, "documented_bias": false,
			"bias_reward": false, "family_biometric": false,
			"legal_basis": true, "religious_attribute_use": false,
			"identifiable_data": false,
		},
	}
}

func (producer normativeProducer) evidence(t *testing.T, facts normativeFacts, approvers []string, disclosure, consentFirst bool) normativeEvidence {
	t.Helper()
	raw, _ := json.Marshal(facts)
	digest := v.ContentDigest(raw)
	result := normativeEvidence{Facts: []v.Envelope{producer.sign(t, "observer:1", "facts", facts)}, Events: []v.Envelope{}}
	for i, approver := range approvers {
		event := normativeEvent{Kind: "approval", RequestBinding: facts.RequestBinding, Before: facts.Before, FactsDigest: digest, Sequence: uint64(1 + i), Statement: "VALIDATED"}
		result.Events = append(result.Events, producer.sign(t, approver, "approval", event))
	}
	if disclosure {
		disclosureAt, consentAt := uint64(10), uint64(20)
		if consentFirst {
			disclosureAt, consentAt = consentAt, disclosureAt
		}
		disclosed := normativeEvent{Kind: "disclosure", RequestBinding: facts.RequestBinding, Before: facts.Before, FactsDigest: digest, Sequence: disclosureAt, Uncertainty: facts.Uncertainty, Statement: "DISCLOSED"}
		consented := normativeEvent{Kind: "consent", RequestBinding: facts.RequestBinding, Before: facts.Before, FactsDigest: digest, Sequence: consentAt, Statement: "CONSENTED"}
		result.Events = append(result.Events, producer.sign(t, "discloser:1", "disclosure", disclosed), producer.sign(t, "consenter:1", "consent", consented))
	}
	return result
}

type normativeReplayInput struct {
	Policy       normativePolicy          `json:"policy"`
	ExpectedHash string                   `json:"expected_hash"`
	Request      r.Request                `json:"request"`
	Evidence     normativeEvidence        `json:"evidence"`
	Roots        map[string]normativeRoot `json:"independent_public_roots"`
}

// The relying-party replay process receives public evidence and policy only.
// It gets no private signer keys, SQL credentials, DB handle or execution code
// invocation. Process isolation is claimed; independent implementation is not.
func TestNormativeIndependentReplay(t *testing.T) {
	if os.Getenv("NORMATIVE_REPLAY_CHILD") != "1" {
		return
	}
	var input normativeReplayInput
	if err := json.NewDecoder(os.Stdin).Decode(&input); err != nil {
		t.Fatal(err)
	}
	result := evaluateNormativePolicy(input.Policy, input.ExpectedHash, input.Request, input.Evidence, input.Roots)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		t.Fatal(err)
	}
	os.Exit(0)
}

func independentlyReplayNormative(t *testing.T, input normativeReplayInput) normativeEvaluation {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNormativeIndependentReplay$")
	command.Env = []string{"PATH=/usr/bin:/bin", "NORMATIVE_REPLAY_CHILD=1", "GORACE=atexit_sleep_ms=0"}
	command.Stdin = bytes.NewReader(raw)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("independent normative replay failed: %v %s", err, output)
	}
	var result normativeEvaluation
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

type normativeTrial struct {
	Case                    string              `json:"case"`
	Constitution            string              `json:"constitution"`
	EffectID                string              `json:"effect_id"`
	RequestDigest           string              `json:"request_digest"`
	Destination             string              `json:"destination"`
	AvailableEvidenceDigest string              `json:"available_evidence_digest"`
	TechnicalCapability     bool                `json:"technical_capability"`
	Evaluation              normativeEvaluation `json:"evaluation"`
	DispatchEntered         bool                `json:"dispatch_entered"`
	PhysicalEffects         uint64              `json:"physical_effects"`
	ExecutionDisposition    string              `json:"execution_disposition"`
	CommitCoordinates       string              `json:"commit_coordinates"`
	VerifierReport          *v.Report           `json:"verifier_report,omitempty"`
}

func normativeArtifactDir(t *testing.T, name string) string {
	t.Helper()
	root := os.Getenv("COMPOSITE_ARTIFACT_DIR")
	if root == "" {
		root = t.TempDir()
	}
	directory := filepath.Join(root, "constitutional-substitution", name)
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func normativeSnapshot(t *testing.T, name, output string) {
	t.Helper()
	command := exec.Command("python3", "../../scripts/verify_constitution_substitution.py", "--stage", name, "--out", output)
	if data, err := command.CombinedOutput(); err != nil {
		t.Fatalf("invariance failure: %v %s", err, data)
	}
}

func resetNormativeWorld(t *testing.T, f *noCustodyFixture) {
	t.Helper()
	// Counterfactual trials restore the same physical destination and initial
	// state through a privileged fixture reset. This is not runtime recovery,
	// deletion permission, or a replay guarantee across destroyed histories.
	if _, err := f.a.db.Exec("DELETE FROM " + nativeFenceTable("ledger")); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.db.Exec("UPDATE "+nativeFenceTable("target_state")+" SET revision=$1,digest=$2 WHERE target=$3", f.req.Current.Revision, f.req.Current.Digest, f.req.Current.Target); err != nil {
		t.Fatal(err)
	}
	if _, err := f.a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET active=TRUE,epoch=1,generation=1 WHERE binding_digest=$1", f.req.Admission.BindingDigest); err != nil {
		t.Fatal(err)
	}
}

func runNormativeTrial(t *testing.T, f *noCustodyFixture, name string, policy normativePolicy, expectedHash string, evidence normativeEvidence, roots map[string]normativeRoot) normativeTrial {
	t.Helper()
	directory := normativeArtifactDir(t, name+"/"+policy.ID)
	normativeSnapshot(t, name+"/"+policy.ID+"/before", filepath.Join(directory, "fingerprint-before.json"))
	var capable bool
	if err := f.a.db.QueryRow("SELECT has_table_privilege(current_user,$1,'INSERT')", nativeFenceTable("ledger")).Scan(&capable); err != nil || !capable {
		t.Fatal("native INSERT capability missing", err)
	}
	effectID, err := r.EffectIdentity(f.req)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, _ := json.Marshal(f.req)
	evaluation := evaluateNormativePolicy(policy, expectedHash, f.req, evidence, roots)
	input := normativeReplayInput{Policy: policy, ExpectedHash: expectedHash, Request: f.req, Evidence: evidence, Roots: roots}
	independent := independentlyReplayNormative(t, input)
	primaryJSON, _ := json.Marshal(evaluation)
	independentJSON, _ := json.Marshal(independent)
	if !bytes.Equal(primaryJSON, independentJSON) {
		t.Fatal("independent policy replay disagreed", evaluation, independent)
	}
	writeCompositeJSON(t, filepath.Join(directory, "normative-input-public.json"), input)
	writeCompositeJSON(t, filepath.Join(directory, "evaluation.json"), evaluation)
	writeCompositeJSON(t, filepath.Join(directory, "independent-policy-replay.json"), independent)
	trial := normativeTrial{Case: name, Constitution: policy.ID, EffectID: effectID, RequestDigest: v.ContentDigest(rawRequest), Destination: "PostgreSQL/native_destination_fence_v1/ledger", AvailableEvidenceDigest: evaluation.EvidenceDigest, TechnicalCapability: capable, Evaluation: evaluation, ExecutionDisposition: "REJECTED", CommitCoordinates: "UNDEFINED_NO_COMMITTED_EFFECT"}
	f.policy.AdmissionPolicyHash = expectedHash
	if evaluation.Decision == "ALLOW" {
		// Issuance belongs to the independently provisioned admission authority,
		// after transparent evaluation. The translator cannot call f.seal.
		admission := f.seal(t, "admission", f.admission(f.req, 1))
		trial.DispatchEntered = true
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, admission, f.policy, nil); err != nil {
			t.Fatal(err)
		}
		destination, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
		if err != nil || destination.Commit == nil {
			t.Fatal("native effect lacks exact origin", err)
		}
		report := f.inspect(t, "constitutional-substitution/"+name+"/"+policy.ID, f.req, 1, destination, "CLOSED", "EXACT_COMMIT_RECORD", true)
		if report.AuthorityAtCommit != "VALID_AT_COMMIT" || report.Causality != "EXACT_COMMIT_RECORD" || report.Closure != "CLOSED" {
			t.Fatalf("A/C/P changed: %+v", report)
		}
		trial.VerifierReport, trial.ExecutionDisposition, trial.CommitCoordinates = &report, "CLOSED", "111"
		// A valid unchanged normative approval cannot authorize replay of a
		// completed non-idempotent native append in the same retained world.
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, admission, f.policy, nil); !errors.Is(err, errNativeCompleted) {
			t.Fatalf("replay exclusion changed: %v", err)
		}
	}
	trial.PhysicalEffects = f.tally(t)
	if (evaluation.Decision == "ALLOW" && trial.PhysicalEffects != 1) || (evaluation.Decision != "ALLOW" && (trial.PhysicalEffects != 0 || trial.DispatchEntered)) {
		t.Fatal("policy/physical dispatch mismatch", trial)
	}
	writeCompositeJSON(t, filepath.Join(directory, "trial.json"), trial)
	normativeSnapshot(t, name+"/"+policy.ID+"/after", filepath.Join(directory, "fingerprint-after.json"))
	fmt.Printf("NORMATIVE_TRIAL case=%s constitution=%s decision=%s effects=%d coordinates=%s\n", name, policy.ID, evaluation.Decision, trial.PhysicalEffects, trial.CommitCoordinates)
	return trial
}

func TestPostgresConstitutionSubstitution(t *testing.T) {
	policies, err := normativePolicies()
	if err != nil {
		t.Fatal(err)
	}
	type scenario struct {
		name                                                         string
		modify                                                       func(*normativeFacts)
		approvers                                                    []string
		disclosure, consentFirst, wrongState, conflict, missingFacts bool
		want                                                         [3]string
	}
	cases := []scenario{
		{name: "ordinary-validated", approvers: []string{"human:1"}, want: [3]string{"ALLOW", "ALLOW", "ALLOW"}},
		{name: "same-effect-safety-one-approval", modify: func(f *normativeFacts) { f.Flags["safety_impact"] = true }, approvers: []string{"human:1"}, want: [3]string{"ALLOW", "REQUIRE_HUMAN_APPROVAL", "ALLOW"}},
		{name: "safety-two-approvals", modify: func(f *normativeFacts) { f.Flags["safety_impact"] = true }, approvers: []string{"human:1", "human:2"}, want: [3]string{"ALLOW", "ALLOW", "ALLOW"}},
		{name: "capability-without-validation", want: [3]string{"REQUIRE_HUMAN_APPROVAL", "ALLOW", "ALLOW"}},
		{name: "valid-policy-hash-failed-underlying-review", modify: func(f *normativeFacts) { f.Flags["harm_review_passed"] = false }, approvers: []string{"human:1"}, want: [3]string{"DENY", "ALLOW", "ALLOW"}},
		{name: "missing-required-evidence", modify: func(f *normativeFacts) { delete(f.Flags, "purpose_justified") }, approvers: []string{"human:1"}, want: [3]string{"REQUIRE_EVIDENCE", "ALLOW", "ALLOW"}},
		{name: "valid-human-signature-wrong-state", approvers: []string{"human:1"}, wrongState: true, want: [3]string{"REQUIRE_EVIDENCE", "REQUIRE_EVIDENCE", "REQUIRE_EVIDENCE"}},
		{name: "high-uncertainty-without-disclosure", modify: func(f *normativeFacts) { f.Uncertainty = 0.8 }, approvers: []string{"human:1"}, want: [3]string{"ALLOW", "REQUIRE_DISCLOSURE", "ALLOW"}},
		{name: "uncertainty-disclosed-before-consent", modify: func(f *normativeFacts) { f.Uncertainty = 0.8 }, approvers: []string{"human:1"}, disclosure: true, want: [3]string{"ALLOW", "ALLOW", "ALLOW"}},
		{name: "consent-before-disclosure", modify: func(f *normativeFacts) { f.Uncertainty = 0.8 }, approvers: []string{"human:1"}, disclosure: true, consentFirst: true, want: [3]string{"ALLOW", "REQUIRE_DISCLOSURE", "ALLOW"}},
		{name: "same-effect-identifiable-with-consent", modify: func(f *normativeFacts) { f.Flags["identifiable_data"] = true }, approvers: []string{"human:1"}, disclosure: true, want: [3]string{"ALLOW", "ALLOW", "DENY"}},
		{name: "documented-bias-reward", modify: func(f *normativeFacts) {
			f.Flags["documented_bias"], f.Flags["bias_reward"], f.Flags["truth_review_passed"] = true, true, false
		}, approvers: []string{"human:1"}, want: [3]string{"DENY", "DENY", "ALLOW"}},
		{name: "biometric-family-without-legal-basis", modify: func(f *normativeFacts) {
			f.Flags["family_biometric"], f.Flags["legal_basis"], f.Flags["privacy_review_passed"] = true, false, false
		}, approvers: []string{"human:1"}, want: [3]string{"DENY", "DENY", "ALLOW"}},
		{name: "religious-attribute-use", modify: func(f *normativeFacts) {
			f.Flags["religious_attribute_use"], f.Flags["privacy_review_passed"] = true, false
		}, approvers: []string{"human:1"}, want: [3]string{"DENY", "DENY", "ALLOW"}},
		{name: "conflicting-trusted-assessments", approvers: []string{"human:1"}, conflict: true, want: [3]string{"REQUIRE_EXTERNAL_RESOLUTION", "REQUIRE_EXTERNAL_RESOLUTION", "REQUIRE_EXTERNAL_RESOLUTION"}},
		{name: "missing-fact-attestation", missingFacts: true, want: [3]string{"REQUIRE_EVIDENCE", "REQUIRE_EVIDENCE", "REQUIRE_EVIDENCE"}},
		{name: "two-keys-one-human-principal", modify: func(f *normativeFacts) { f.Flags["safety_impact"] = true }, approvers: []string{"human:1", "human:1-rotated"}, want: [3]string{"ALLOW", "REQUIRE_HUMAN_APPROVAL", "ALLOW"}},
	}
	var all []normativeTrial
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			f := setupUnifiedEffectRecord(t)
			f.policy.CaseID = "constitutional-substitution/" + item.name
			producer := newNormativeProducer(t)
			facts := defaultNormativeFacts(f.req)
			if item.modify != nil {
				item.modify(&facts)
			}
			evidence := producer.evidence(t, facts, item.approvers, item.disclosure, item.consentFirst)
			if item.wrongState {
				var event normativeEvent
				if err := json.Unmarshal(evidence.Events[0].Payload, &event); err != nil {
					t.Fatal(err)
				}
				event.Before.Digest = "different-current-state"
				evidence.Events[0] = producer.sign(t, "human:1", "approval", event)
			}
			if item.conflict {
				other := facts
				other.RecordID = "review:fixture:contradictory"
				other.Flags = map[string]bool{}
				for key, value := range facts.Flags {
					other.Flags[key] = value
				}
				other.Flags["harm_review_passed"] = false
				evidence.Facts = append(evidence.Facts, producer.sign(t, "observer:2", "facts", other))
			}
			if item.missingFacts {
				evidence.Facts = nil
			}
			var first *normativeTrial
			for index, policy := range policies {
				resetNormativeWorld(t, f)
				trial := runNormativeTrial(t, f, item.name, policy, normativePolicyHash(policy), evidence, producer.roots)
				if trial.Evaluation.Decision != item.want[index] {
					t.Fatalf("source-fragment decision changed: want=%s got=%+v", item.want[index], trial.Evaluation)
				}
				if first != nil && (trial.EffectID != first.EffectID || trial.RequestDigest != first.RequestDigest || trial.Destination != first.Destination || trial.AvailableEvidenceDigest != first.AvailableEvidenceDigest) {
					t.Fatal("normative disagreement changed effect/request/destination/evidence")
				}
				if first == nil {
					copy := trial
					first = &copy
				}
				all = append(all, trial)
			}
		})
	}
	writeCompositeJSON(t, filepath.Join(normativeArtifactDir(t, ""), "native-trials.json"), all)
}

func TestPostgresConstitutionCurrentTruthAndReplay(t *testing.T) {
	policies, err := normativePolicies()
	if err != nil {
		t.Fatal(err)
	}
	for _, policy := range policies {
		t.Run(policy.ID, func(t *testing.T) {
			f := setupUnifiedEffectRecord(t)
			producer := newNormativeProducer(t)
			facts := defaultNormativeFacts(f.req)
			evidence := producer.evidence(t, facts, []string{"human:1", "human:2"}, false, false)
			runNormativeTrial(t, f, "current-truth", policy, normativePolicyHash(policy), evidence, producer.roots)
			if _, err := f.a.db.Exec("UPDATE "+nativeFenceTable("target_state")+" SET digest='later-native-state' WHERE target=$1", f.req.Current.Target); err != nil {
				t.Fatal(err)
			}
			destination, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
			if err != nil {
				t.Fatal(err)
			}
			report := f.inspect(t, "constitutional-substitution/current-truth/"+policy.ID+"/drift", f.req, 1, destination, "UNKNOWN", "EXACT_COMMIT_RECORD", true)
			if report.AuthorityAtCommit != "VALID_AT_COMMIT" || report.Causality != "EXACT_COMMIT_RECORD" || report.Closure != "UNKNOWN" {
				t.Fatalf("normative layer reinterpreted P: %+v", report)
			}
			if f.tally(t) != 1 {
				t.Fatal("current drift replayed the effect")
			}
			writeCompositeJSON(t, filepath.Join(normativeArtifactDir(t, "current-truth/"+policy.ID), "drift.json"), map[string]any{"coordinates": "110", "report": report, "physical_effects": f.tally(t)})
		})
	}
}

func TestPostgresConstitutionAntiCheating(t *testing.T) {
	policies, err := normativePolicies()
	if err != nil {
		t.Fatal(err)
	}
	policy := policies[0]
	t.Run("producer-policy-substitution", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		producer := newNormativeProducer(t)
		evidence := producer.evidence(t, defaultNormativeFacts(f.req), nil, false, false)
		replacement := policy
		replacement.Rules = []normativeRule{{ID: "forged", Source: "adapter:self", Kind: "approvals", Minimum: 1}}
		trial := runNormativeTrial(t, f, "producer-policy-substitution", replacement, normativePolicyHash(policy), evidence, producer.roots)
		if trial.Evaluation.Decision != "DENY" {
			t.Fatal("producer weakened independent policy")
		}
	})
	t.Run("adapter-self-authorizes-admission", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		f.policy.AdmissionPolicyHash = normativePolicyHash(policy)
		_, attacker, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		forged, err := v.Seal("admission", "adapter:untrusted", attacker, f.admission(f.req, 1))
		if err != nil {
			t.Fatal(err)
		}
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, forged, f.policy, nil); !errors.Is(err, errNativeUntrusted) || f.tally(t) != 0 {
			t.Fatal("adapter granted itself authority", err)
		}
		writeCompositeJSON(t, filepath.Join(normativeArtifactDir(t, "anti-cheating"), "self-authorization.json"), map[string]any{"rejected": true, "physical_effects": f.tally(t), "policy_hash": f.policy.AdmissionPolicyHash})
	})
	t.Run("authority-revoked-after-policy-evaluation", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		producer := newNormativeProducer(t)
		evidence := producer.evidence(t, defaultNormativeFacts(f.req), []string{"human:1"}, false, false)
		evaluation := evaluateNormativePolicy(policy, normativePolicyHash(policy), f.req, evidence, producer.roots)
		if evaluation.Decision != "ALLOW" {
			t.Fatal(evaluation)
		}
		f.policy.AdmissionPolicyHash = normativePolicyHash(policy)
		admission := f.seal(t, "admission", f.admission(f.req, 1))
		if _, err := f.a.db.Exec("UPDATE "+nativeFenceTable("authority")+" SET active=FALSE WHERE binding_digest=$1", f.req.Admission.BindingDigest); err != nil {
			t.Fatal(err)
		}
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, admission, f.policy, nil); !errors.Is(err, errNativeAuthority) || f.tally(t) != 0 {
			t.Fatal("normative ALLOW erased commit authority", err)
		}
		writeCompositeJSON(t, filepath.Join(normativeArtifactDir(t, "anti-cheating"), "revoked-at-native-boundary.json"), map[string]any{"external_evaluation": evaluation, "native_rejected": true, "physical_effects": f.tally(t), "commit_coordinates": "UNDEFINED_NO_COMMITTED_EFFECT"})
	})
	t.Run("trusted-admission-issuer-limit-is-exposed", func(t *testing.T) {
		f := setupUnifiedEffectRecord(t)
		producer := newNormativeProducer(t)
		evidence := producer.evidence(t, defaultNormativeFacts(f.req), nil, false, false)
		evaluation := evaluateNormativePolicy(policy, normativePolicyHash(policy), f.req, evidence, producer.roots)
		if evaluation.Decision != "REQUIRE_HUMAN_APPROVAL" {
			t.Fatal(evaluation)
		}
		f.policy.AdmissionPolicyHash = normativePolicyHash(policy)
		// Deliberately violate the trusted issuer contract by bypassing issuance
		// evaluation. This must expose, not conceal, the existing verifier limit:
		// an authentic admission assertion is not normative evidence replay.
		if err := executeUnifiedEffectRecord(context.Background(), f.a.db, f.req, f.seal(t, "admission", f.admission(f.req, 1)), f.policy, nil); err != nil {
			t.Fatal(err)
		}
		destination, err := observeUnifiedEffectRecord(context.Background(), f.a.db, f.req, false)
		if err != nil {
			t.Fatal(err)
		}
		report := f.inspect(t, "constitutional-substitution/trusted-issuer-limit", f.req, 1, destination, "CLOSED", "EXACT_COMMIT_RECORD", true)
		writeCompositeJSON(t, filepath.Join(normativeArtifactDir(t, "anti-cheating"), "trusted-issuer-limit.json"), map[string]any{"limit_exposed": true, "external_policy_satisfied": false, "external_evaluation": evaluation, "physical_effects": f.tally(t), "effect_finality_supported": report.ClaimsSupported, "report": report, "interpretation": "Effect verifier relies on truthful independently trusted admission issuance. It does not prove underlying normative compliance."})
	})
}
