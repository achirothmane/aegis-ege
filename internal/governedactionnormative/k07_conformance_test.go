package governedactionnormative

import (
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"
)

type k07Input struct {
	Domain                      string `json:"domain"`
	ProfileTrusted              bool   `json:"profile_trusted"`
	ProfileAdequate             bool   `json:"profile_adequate"`
	RevisionExact               bool   `json:"revision_exact"`
	CurrentWitnesses            bool   `json:"current_witnesses"`
	RelevantStateBound          bool   `json:"relevant_state_bound"`
	RelevantStateCurrent        bool   `json:"relevant_state_current"`
	RequiredIndependence        bool   `json:"required_independence"`
	IndependenceSatisfied       bool   `json:"independence_satisfied"`
	EnforcementBoundaryDeclared bool   `json:"enforcement_boundary_declared"`
	CompleteMediation           bool   `json:"complete_mediation"`
	EffectCanSurviveProcess     bool   `json:"effect_can_survive_process"`
	CustodyBeforeDispatch       bool   `json:"custody_before_dispatch"`
	PossibleEffectExists        bool   `json:"possible_effect_exists"`
	SubstitutionRequested       bool   `json:"substitution_requested"`
	SafeSubstitutionProven      bool   `json:"safe_substitution_proven"`
	ObservationGap              bool   `json:"observation_gap"`
	TerminalUnknownAuthorized   bool   `json:"terminal_unknown_authorized"`
	ResidualCustody             bool   `json:"residual_custody"`
	TakeoverRequested           bool   `json:"takeover_requested"`
	StaleWorkerCanAct           bool   `json:"stale_worker_can_act"`
	DestinationFencingEffective bool   `json:"destination_fencing_effective"`
	TakeoverBlocked             bool   `json:"takeover_blocked"`
	HardPreconditionRequired    bool   `json:"hard_precondition_required"`
	DestinationCAS              bool   `json:"destination_cas"`
	VerifiedOutcomeClaim        bool   `json:"verified_outcome_claim"`
	PostconditionExact          bool   `json:"postcondition_exact"`
	AlreadySatisfied            bool   `json:"already_satisfied"`
	SeedMode                    string `json:"seed_mode"`
	EmitEffect                  bool   `json:"emit_effect"`
}

type k07ExecutableCase struct {
	CaseID         string   `json:"case_id"`
	FaultSchedule  string   `json:"fault_schedule"`
	ActionRef      string   `json:"action_ref"`
	EffectID       string   `json:"effect_id"`
	AttemptID      string   `json:"attempt_id"`
	ObservationRef string   `json:"observation_ref"`
	Input          k07Input `json:"input"`
}

type k07ExecutionSet struct {
	SchemaVersion       string              `json:"schema_version"`
	FrozenOracleBlob    string              `json:"frozen_oracle_blob"`
	FrozenOracleVersion string              `json:"frozen_oracle_version"`
	Cases               []k07ExecutableCase `json:"cases"`
}

type k07Result struct {
	ValidTrace          bool
	Disposition         string
	AuthorizedEffects   int
	UnauthorizedEffects int
	UsefulBehavior      bool
	Observations        []string
	ActionRef           string
	EffectID            string
	AttemptID           string
	ObservationRef      string
	FaultSchedule       string
}

func evaluateK07(tc k07ExecutableCase) k07Result {
	in := tc.Input
	result := k07Result{
		ActionRef:      tc.ActionRef,
		EffectID:       tc.EffectID,
		AttemptID:      tc.AttemptID,
		ObservationRef: tc.ObservationRef,
		FaultSchedule:  tc.FaultSchedule,
	}

	reject := func(disposition string, observations ...string) k07Result {
		result.ValidTrace = false
		result.Disposition = disposition
		result.Observations = observations
		result.AuthorizedEffects = 0
		result.UnauthorizedEffects = 0
		result.UsefulBehavior = false
		return result
	}
	allow := func(disposition string, observations ...string) k07Result {
		result.ValidTrace = true
		result.Disposition = disposition
		result.Observations = observations
		result.UnauthorizedEffects = 0
		result.UsefulBehavior = true
		if in.EmitEffect {
			result.AuthorizedEffects = 1
		}
		return result
	}

	if !in.ProfileTrusted {
		return reject("REJECT_BEFORE_EFFECT", "admission.profile=UNTRUSTED")
	}
	if !in.ProfileAdequate {
		return reject("DEFER_PROFILE_INCOMPLETE", "admission.profile=INADEQUATE_FOR_CLAIM")
	}
	if !in.RevisionExact || !in.CurrentWitnesses {
		return reject("REJECT_BEFORE_EFFECT", "admission.basis=STALE_OR_WRONG_REVISION")
	}
	if !in.RelevantStateBound {
		return reject("DEFER_MISSING_RELEVANT_STATE", "decision_basis.relevant_state=MISSING")
	}
	if !in.RelevantStateCurrent {
		return reject("REJECT_BEFORE_EFFECT", "decision_basis.relevant_state=STALE")
	}
	if in.RequiredIndependence && !in.IndependenceSatisfied {
		return reject("DEFER_INSUFFICIENT_INDEPENDENCE", "evidence.independence=UNKNOWN_OR_UNSATISFIED")
	}
	if !in.EnforcementBoundaryDeclared || !in.CompleteMediation {
		return reject("DEFER_ENFORCEMENT_ASSUMPTIONS_MISSING", "enforcement.boundary=UNPROVEN")
	}
	if in.EffectCanSurviveProcess && !in.CustodyBeforeDispatch {
		return reject("REJECT_TRACE", "custody.before_dispatch=MISSING")
	}
	if in.HardPreconditionRequired && !in.DestinationCAS {
		return reject("REJECT_UNGUARDED_MUTATION", "destination.precondition=NOT_ATOMIC")
	}
	if in.PossibleEffectExists && in.SubstitutionRequested && !in.SafeSubstitutionProven {
		return reject("REJECT_SECOND_EFFECT", "effect.previous=POSSIBLE", "substitution=UNPROVEN")
	}
	if in.ObservationGap {
		if in.TerminalUnknownAuthorized && in.ResidualCustody {
			return allow("RETIRE_AS_UNKNOWN", "closure.knowledge=UNKNOWN", "closure.disposition=RETIRED_UNKNOWN", "closure.custody=RETAINED")
		}
		return reject("REJECT_DISPOSITION", "closure.knowledge=UNKNOWN", "closure.custody=INSUFFICIENT")
	}
	if in.TakeoverRequested {
		if in.StaleWorkerCanAct && !in.DestinationFencingEffective && !in.TakeoverBlocked {
			return reject("REJECT_TAKEOVER_EFFECT", "takeover.exclusivity=UNPROVEN", "effect.previous=ACCOUNTED")
		}
		return allow("ALLOW_SAFE_RECOVERY_OR_BLOCK", "takeover.exclusivity=ENFORCED_OR_BLOCKED", "effect.lineage=PRESERVED")
	}
	if in.VerifiedOutcomeClaim && !in.PostconditionExact {
		return reject("REJECT_FALSE_VERIFIED", "outcome.postcondition=UNSATISFIED_OR_UNRELATED")
	}

	switch in.SeedMode {
	case "ci_validated_rerun":
		return allow("DISCHARGE_RECOVERY_OBLIGATION", "ci.dispatch=ACCEPTED", "ci.recovery=VALIDATED")
	case "kube_bounded_drain":
		return allow("DISCHARGE_CLOSURE_MATCH", "kubernetes.postflight=MATCH", "kubernetes.custody=CHECKPOINTED")
	case "eep_conditional_update":
		return allow("DISCHARGE_INTENDED_STATE_OBLIGATION", "eep.request=ACCEPTED", "eep.postcondition=VERIFIED", "eep.observation=OBSERVED_STABLE")
	case "eep_already_satisfied":
		return allow("DISCHARGE_INTENDED_STATE_OBLIGATION", "eep.request=NOT_DISPATCHED", "eep.postcondition=ALREADY_SATISFIED")
	}

	if in.VerifiedOutcomeClaim && in.PostconditionExact {
		return allow("DISCHARGE_INTENDED_STATE_OBLIGATION", "eep.postcondition=VERIFIED")
	}
	if in.PossibleEffectExists && !in.SubstitutionRequested {
		return allow("RETAIN_POSSIBLE_EFFECT", "effect.previous=POSSIBLE", "effect.custody=RETAINED", "effect.replay=BLOCKED")
	}
	return allow("ALLOW_BOUND_EFFECT", in.Domain+".effect=PERMITTED")
}

func loadK07ExecutionSet(t *testing.T) k07ExecutionSet {
	t.Helper()
	var set k07ExecutionSet
	readJSON(t, repoPath("testdata", "governed-action", "k07", "executable-cases.json"), &set)
	return set
}

func TestK07ExecutableSetPinsFrozenOracleAndCoversEveryCase(t *testing.T) {
	execSet := loadK07ExecutionSet(t)
	if execSet.SchemaVersion != "governed-action.k07-execution/v1" {
		t.Fatalf("unexpected K07 execution version %q", execSet.SchemaVersion)
	}
	if execSet.FrozenOracleVersion != normativeVersion {
		t.Fatalf("K07 execution set targets %q, frozen oracle is %q", execSet.FrozenOracleVersion, normativeVersion)
	}

	oraclePayload, err := os.ReadFile(repoPath("testdata", "governed-action", "v1", "normative-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := gitBlobSHA(oraclePayload); got != execSet.FrozenOracleBlob {
		t.Fatalf("K07 fixture not pinned to frozen oracle: fixture=%s local=%s", execSet.FrozenOracleBlob, got)
	}

	var oracle normativeCaseSet
	if err := json.Unmarshal(oraclePayload, &oracle); err != nil {
		t.Fatal(err)
	}

	want := make([]string, 0, len(oracle.Cases))
	for _, tc := range oracle.Cases {
		want = append(want, tc.ID)
	}
	got := make([]string, 0, len(execSet.Cases))
	seen := map[string]bool{}
	for _, tc := range execSet.Cases {
		if seen[tc.CaseID] {
			t.Fatalf("duplicate executable case %q", tc.CaseID)
		}
		seen[tc.CaseID] = true
		got = append(got, tc.CaseID)
	}
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(want, "\n") != strings.Join(got, "\n") {
		t.Fatalf("K07 executable case set must exactly match frozen oracle IDs\nwant=%v\n got=%v", want, got)
	}
}

func TestK07FrozenConformanceVectorsExecuteWithoutChangingOracle(t *testing.T) {
	var oracle normativeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "normative-cases.json"), &oracle)
	byID := map[string]normativeCase{}
	for _, tc := range oracle.Cases {
		byID[tc.ID] = tc
	}

	execSet := loadK07ExecutionSet(t)
	for _, executable := range execSet.Cases {
		executable := executable
		t.Run(executable.CaseID, func(t *testing.T) {
			expected, ok := byID[executable.CaseID]
			if !ok {
				t.Fatalf("executable case %s is absent from frozen oracle", executable.CaseID)
			}
			got := evaluateK07(executable)
			if got.ValidTrace != expected.ValidTrace {
				t.Fatalf("frozen validity mismatch: want=%v got=%v", expected.ValidTrace, got.ValidTrace)
			}
			if got.Disposition != expected.Expected.Disposition {
				t.Fatalf("frozen disposition mismatch: want=%s got=%s", expected.Expected.Disposition, got.Disposition)
			}
			if got.UnauthorizedEffects != 0 {
				t.Fatalf("unauthorized effect observed: %d", got.UnauthorizedEffects)
			}
			if strings.TrimSpace(got.ActionRef) == "" {
				t.Fatal("result must retain ActionRef evidence")
			}
			if len(got.Observations) == 0 {
				t.Fatal("result must retain typed observation evidence")
			}
			if !expected.ValidTrace {
				if got.AuthorizedEffects != 0 {
					t.Fatalf("rejected trace emitted effect: %d", got.AuthorizedEffects)
				}
				return
			}
			if !got.UsefulBehavior {
				t.Fatal("accepted trace must demonstrate useful permitted behavior or safe accountable containment")
			}
			if expected.Expected.Disposition == "ALLOW_BOUND_EFFECT" && got.AuthorizedEffects != 1 {
				t.Fatalf("positive ALLOW_BOUND_EFFECT must exercise one permitted effect, got %d", got.AuthorizedEffects)
			}
			if got.AuthorizedEffects > 0 && (strings.TrimSpace(got.EffectID) == "" || strings.TrimSpace(got.AttemptID) == "") {
				t.Fatal("executed effect must retain EffectIdentity and ExecutionAttempt evidence")
			}
			if executable.Input.PossibleEffectExists && strings.TrimSpace(got.EffectID) == "" {
				t.Fatal("possible effect must retain EffectIdentity")
			}
		})
	}
}

func TestK07PositiveSeedsRemainDomainTyped(t *testing.T) {
	execSet := loadK07ExecutionSet(t)
	want := map[string][]string{
		"SEED-CI-A1-validated-rerun":                {"ci.dispatch=ACCEPTED", "ci.recovery=VALIDATED"},
		"SEED-KUBE-A1-bounded-drain-completes":      {"kubernetes.postflight=MATCH"},
		"SEED-EEP-A1-conditional-update-verified":   {"eep.postcondition=VERIFIED"},
		"SEED-EEP-A2-already-satisfied-noop":        {"eep.postcondition=ALREADY_SATISFIED"},
	}
	seen := map[string]bool{}
	for _, tc := range execSet.Cases {
		required, ok := want[tc.CaseID]
		if !ok {
			continue
		}
		seen[tc.CaseID] = true
		got := evaluateK07(tc)
		joined := strings.Join(got.Observations, "\n")
		for _, marker := range required {
			if !strings.Contains(joined, marker) {
				t.Fatalf("%s lost domain observation %q: %v", tc.CaseID, marker, got.Observations)
			}
		}
	}
	for id := range want {
		if !seen[id] {
			t.Fatalf("missing positive seed %s", id)
		}
	}
}

func TestK07FaultSchedulesAreFiniteAndDiscriminating(t *testing.T) {
	execSet := loadK07ExecutionSet(t)
	required := map[string]string{
		"CE3-R1-timeout-provider-substitution":       "lost_response_after_possible_acceptance",
		"CE4-R1-effect-before-custody":                "crash_before_durable_custody",
		"CE5-R1-observation-gap-false-success":        "permanent_observation_gap",
		"CE6-R1-stale-worker-after-takeover":          "stale_worker_after_takeover",
		"CE7-R1-unrelated-change-as-success":          "unrelated_change_only",
		"CE8-R1-current-read-stale-write":             "stale_write_interleaving",
		"CE10-R1-required-independence-unknown":       "unknown_independence_model",
		"CE12-R1-undeclared-enforcement-assumptions":  "undeclared_effect_boundary",
	}
	seen := map[string]bool{}
	for _, tc := range execSet.Cases {
		if want, ok := required[tc.CaseID]; ok {
			seen[tc.CaseID] = true
			if tc.FaultSchedule != want {
				t.Fatalf("%s fault schedule: want %s got %s", tc.CaseID, want, tc.FaultSchedule)
			}
		}
	}
	for id := range required {
		if !seen[id] {
			t.Fatalf("missing discriminating fault schedule for %s", id)
		}
	}
}
