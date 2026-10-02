package governedactionnormative

import (
	"os"
	"strings"
	"testing"
)

type d03AFix struct {
	Type        string `json:"type"`
	Ref         string `json:"ref"`
	MergeCommit string `json:"merge_commit"`
	Summary     string `json:"summary"`
}

type d03AGroundTruth struct {
	RootCause   string  `json:"root_cause"`
	Consequence string  `json:"consequence"`
	Fix         d03AFix `json:"fix"`
}

type d03AKernelMapping struct {
	PrimaryRelations     []string        `json:"primary_relations"`
	Rationale            string          `json:"rationale"`
	HistoricalOverrides  map[string]bool `json:"historical_overrides"`
	HistoricalExpected   string          `json:"historical_expected"`
	HistoricalValidTrace bool            `json:"historical_valid_trace"`
	FixedOverrides       map[string]bool `json:"fixed_overrides"`
	FixedExpected        string          `json:"fixed_expected"`
}

type d03AIncident struct {
	ID         string `json:"id"`
	Repository string `json:"repository"`
	Domain     string `json:"domain"`
	Issue      struct {
		Number int    `json:"number"`
		URL    string `json:"url"`
		State  string `json:"state"`
		Title  string `json:"title"`
	} `json:"issue"`
	GroundTruth   d03AGroundTruth   `json:"ground_truth"`
	KernelMapping d03AKernelMapping `json:"kernel_mapping"`
}

type d03ACorpus struct {
	SchemaVersion                  string         `json:"schema_version"`
	Status                         string         `json:"status"`
	SelectionAfterFreeze           bool           `json:"selection_after_freeze"`
	FrozenContract                 string         `json:"frozen_contract"`
	FrozenOracleBlob               string         `json:"frozen_oracle_blob"`
	Incidents                      []d03AIncident `json:"incidents"`
	StopRule                       string         `json:"stop_rule"`
	NormativeChange                bool           `json:"normative_change"`
	RuntimeChange                  bool           `json:"runtime_change"`
	IndependentImplementationClaim bool           `json:"independent_implementation_claim"`
	D03PassClaim                   bool           `json:"d03_pass_claim"`
}

func loadD03ACorpus(t *testing.T) d03ACorpus {
	t.Helper()
	var corpus d03ACorpus
	readJSON(t, repoPath("testdata", "governed-action", "d03a", "corpus-v1.json"), &corpus)
	return corpus
}

func d03ABaseline(domain string) k07Input {
	return k07Input{
		Domain:                      domain,
		ProfileTrusted:              true,
		ProfileAdequate:             true,
		RevisionExact:               true,
		CurrentWitnesses:            true,
		RelevantStateBound:          true,
		RelevantStateCurrent:        true,
		RequiredIndependence:        false,
		IndependenceSatisfied:       true,
		EnforcementBoundaryDeclared: true,
		CompleteMediation:           true,
		EffectCanSurviveProcess:     false,
		CustodyBeforeDispatch:       true,
		PossibleEffectExists:        false,
		SubstitutionRequested:       false,
		SafeSubstitutionProven:      false,
		ObservationGap:              false,
		TerminalUnknownAuthorized:   false,
		ResidualCustody:             true,
		TakeoverRequested:           false,
		StaleWorkerCanAct:           false,
		DestinationFencingEffective: false,
		TakeoverBlocked:             false,
		HardPreconditionRequired:    false,
		DestinationCAS:              true,
		VerifiedOutcomeClaim:        false,
		PostconditionExact:          false,
		AlreadySatisfied:            false,
		SeedMode:                    "",
		EmitEffect:                  false,
	}
}

func applyD03AOverrides(t *testing.T, in *k07Input, overrides map[string]bool) {
	t.Helper()
	for key, value := range overrides {
		switch key {
		case "profile_trusted":
			in.ProfileTrusted = value
		case "profile_adequate":
			in.ProfileAdequate = value
		case "revision_exact":
			in.RevisionExact = value
		case "current_witnesses":
			in.CurrentWitnesses = value
		case "relevant_state_bound":
			in.RelevantStateBound = value
		case "relevant_state_current":
			in.RelevantStateCurrent = value
		case "required_independence":
			in.RequiredIndependence = value
		case "independence_satisfied":
			in.IndependenceSatisfied = value
		case "enforcement_boundary_declared":
			in.EnforcementBoundaryDeclared = value
		case "complete_mediation":
			in.CompleteMediation = value
		case "effect_can_survive_process":
			in.EffectCanSurviveProcess = value
		case "custody_before_dispatch":
			in.CustodyBeforeDispatch = value
		case "possible_effect_exists":
			in.PossibleEffectExists = value
		case "substitution_requested":
			in.SubstitutionRequested = value
		case "safe_substitution_proven":
			in.SafeSubstitutionProven = value
		case "observation_gap":
			in.ObservationGap = value
		case "terminal_unknown_authorized":
			in.TerminalUnknownAuthorized = value
		case "residual_custody":
			in.ResidualCustody = value
		case "takeover_requested":
			in.TakeoverRequested = value
		case "stale_worker_can_act":
			in.StaleWorkerCanAct = value
		case "destination_fencing_effective":
			in.DestinationFencingEffective = value
		case "takeover_blocked":
			in.TakeoverBlocked = value
		case "hard_precondition_required":
			in.HardPreconditionRequired = value
		case "destination_cas":
			in.DestinationCAS = value
		case "verified_outcome_claim":
			in.VerifiedOutcomeClaim = value
		case "postcondition_exact":
			in.PostconditionExact = value
		case "already_satisfied":
			in.AlreadySatisfied = value
		case "emit_effect":
			in.EmitEffect = value
		default:
			t.Fatalf("D03-A incident uses unknown frozen evaluator fact %q", key)
		}
	}
}

func d03AExecutable(t *testing.T, incident d03AIncident, phase string, overrides map[string]bool) k07ExecutableCase {
	t.Helper()
	in := d03ABaseline(incident.Domain)
	applyD03AOverrides(t, &in, overrides)
	suffix := strings.ToLower(phase)
	return k07ExecutableCase{
		CaseID:         incident.ID + "-" + suffix,
		FaultSchedule:  "public_incident:" + incident.Repository,
		ActionRef:      "action:d03a:" + incident.ID + ":" + suffix,
		EffectID:       "effect:d03a:" + incident.ID + ":" + suffix,
		AttemptID:      "attempt:d03a:" + incident.ID + ":" + suffix,
		ObservationRef: "observation:d03a:" + incident.ID + ":" + suffix,
		Input:          in,
	}
}

func TestD03APublicCorpusPinsFrozenOracleAndCannotClaimD03Pass(t *testing.T) {
	corpus := loadD03ACorpus(t)
	if corpus.SchemaVersion != "governed-action.d03a-public-heldout-corpus/v1" {
		t.Fatalf("unexpected D03-A schema %q", corpus.SchemaVersion)
	}
	if corpus.Status != "HELD_OUT_FALSIFICATION_ACTIVE" {
		t.Fatalf("unexpected D03-A status %q", corpus.Status)
	}
	if !corpus.SelectionAfterFreeze {
		t.Fatal("D03-A corpus must be selected after freeze")
	}
	if corpus.FrozenContract != "candidate-kernel-contract-v1" {
		t.Fatalf("unexpected frozen contract %q", corpus.FrozenContract)
	}

	oraclePayload, err := os.ReadFile(repoPath("testdata", "governed-action", "v1", "normative-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := gitBlobSHA(oraclePayload); got != corpus.FrozenOracleBlob {
		t.Fatalf("D03-A drifted from frozen oracle: corpus=%s local=%s", corpus.FrozenOracleBlob, got)
	}
	if corpus.NormativeChange || corpus.RuntimeChange {
		t.Fatalf("D03-A must not mutate frozen semantics/runtime: normative=%v runtime=%v", corpus.NormativeChange, corpus.RuntimeChange)
	}
	if corpus.IndependentImplementationClaim || corpus.D03PassClaim {
		t.Fatal("public corpus cannot claim independent implementation or D03 PASS")
	}

	var readiness struct {
		Status string `json:"status"`
		OperationalPrerequisite struct {
			Satisfied bool `json:"satisfied"`
		} `json:"operational_prerequisite"`
		CohortSelection struct {
			Selected bool `json:"selected"`
		} `json:"cohort_selection"`
	}
	readJSON(t, repoPath("testdata", "governed-action", "d03", "readiness.json"), &readiness)
	if readiness.Status != "BLOCKED_UNSTARTED" || readiness.OperationalPrerequisite.Satisfied || readiness.CohortSelection.Selected {
		t.Fatalf("D03-A must not silently convert D03 readiness into independent validation: %+v", readiness)
	}
}

func TestD03APublicCorpusSourcesAreExternalClosedAndGrounded(t *testing.T) {
	corpus := loadD03ACorpus(t)
	if len(corpus.Incidents) < 11 {
		t.Fatalf("D03-A v1 expected at least 11 grounded reference mappings, got %d", len(corpus.Incidents))
	}

	seen := map[string]bool{}
	domains := map[string]bool{}
	for _, incident := range corpus.Incidents {
		if incident.ID == "" || seen[incident.ID] {
			t.Fatalf("missing/duplicate D03-A incident id %q", incident.ID)
		}
		seen[incident.ID] = true
		if strings.HasPrefix(strings.ToLower(incident.Repository), "achirothmane/") {
			t.Fatalf("D03-A source must be external, got %s", incident.Repository)
		}
		if incident.Issue.State != "closed" || incident.Issue.Number <= 0 || !strings.HasPrefix(incident.Issue.URL, "https://github.com/") {
			t.Fatalf("%s lacks a closed public issue identity", incident.ID)
		}
		if strings.TrimSpace(incident.GroundTruth.RootCause) == "" || strings.TrimSpace(incident.GroundTruth.Consequence) == "" {
			t.Fatalf("%s lacks public ground-truth summary", incident.ID)
		}
		if strings.TrimSpace(incident.GroundTruth.Fix.Type) == "" || strings.TrimSpace(incident.GroundTruth.Fix.Ref) == "" || strings.TrimSpace(incident.GroundTruth.Fix.Summary) == "" {
			t.Fatalf("%s lacks fix/corrected-behavior evidence", incident.ID)
		}
		if len(incident.KernelMapping.PrimaryRelations) == 0 || strings.TrimSpace(incident.KernelMapping.Rationale) == "" {
			t.Fatalf("%s lacks explicit frozen-kernel applicability rationale", incident.ID)
		}
		domains[incident.Domain] = true
	}
	if len(domains) < 3 {
		t.Fatalf("D03-A v1 must span at least three structurally different domain categories, got %v", domains)
	}
}


func TestD03AExternalSecretsCredentialLifecycleCaseIsStateBound(t *testing.T) {
	corpus := loadD03ACorpus(t)
	var found *d03AIncident
	for i := range corpus.Incidents {
		if corpus.Incidents[i].ID == "D03A-ESO-6640" {
			found = &corpus.Incidents[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing D03A-ESO-6640 credential-lifecycle incident")
	}
	if found.Repository != "external-secrets/external-secrets" || found.Domain != "credential-lifecycle" {
		t.Fatalf("unexpected ESO incident identity: %+v", found)
	}
	if found.GroundTruth.Fix.MergeCommit != "40b04db4543fe3a6e6bab90447cb018a5871c25d" {
		t.Fatalf("ESO fix provenance drifted: %s", found.GroundTruth.Fix.MergeCommit)
	}
	if value, ok := found.KernelMapping.HistoricalOverrides["relevant_state_bound"]; !ok || value {
		t.Fatalf("historical ESO mapping must require missing relevant-state binding: %+v", found.KernelMapping.HistoricalOverrides)
	}
	if found.KernelMapping.HistoricalExpected != "DEFER_MISSING_RELEVANT_STATE" {
		t.Fatalf("unexpected ESO historical disposition %q", found.KernelMapping.HistoricalExpected)
	}
	if found.KernelMapping.FixedExpected != "ALLOW_BOUND_EFFECT" || !found.KernelMapping.FixedOverrides["emit_effect"] {
		t.Fatalf("ESO fixed counterpart must remain a useful permitted path: %+v", found.KernelMapping)
	}
}


func TestD03AArgoStaleWorkflowCaseRequiresCurrentState(t *testing.T) {
	corpus := loadD03ACorpus(t)
	var found *d03AIncident
	for i := range corpus.Incidents {
		if corpus.Incidents[i].ID == "D03A-ARGO-16294" {
			found = &corpus.Incidents[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing D03A-ARGO-16294 workflow-controller incident")
	}
	if found.Repository != "argoproj/argo-workflows" || found.Domain != "workflow-controller-reconciliation" {
		t.Fatalf("unexpected Argo incident identity: %+v", found)
	}
	if found.GroundTruth.Fix.MergeCommit != "a7a7a8dfb53a35314b81616ec35b5e3f7270b250" {
		t.Fatalf("Argo fix provenance drifted: %s", found.GroundTruth.Fix.MergeCommit)
	}
	if value, ok := found.KernelMapping.HistoricalOverrides["relevant_state_current"]; !ok || value {
		t.Fatalf("historical Argo mapping must require stale relevant state: %+v", found.KernelMapping.HistoricalOverrides)
	}
	if found.KernelMapping.HistoricalExpected != "REJECT_BEFORE_EFFECT" {
		t.Fatalf("unexpected Argo historical disposition %q", found.KernelMapping.HistoricalExpected)
	}
	if found.KernelMapping.FixedExpected != "ALLOW_BOUND_EFFECT" || !found.KernelMapping.FixedOverrides["emit_effect"] {
		t.Fatalf("Argo fixed counterpart must remain a useful permitted path: %+v", found.KernelMapping)
	}
}


func TestD03ATerraformOrphanedEffectCaseRequiresPriorEffectReconciliation(t *testing.T) {
	corpus := loadD03ACorpus(t)
	var found *d03AIncident
	for i := range corpus.Incidents {
		if corpus.Incidents[i].ID == "D03A-TFAWS-49231" {
			found = &corpus.Incidents[i]
			break
		}
	}
	if found == nil {
		t.Fatal("missing D03A-TFAWS-49231 infrastructure-provisioning incident")
	}
	if found.Repository != "hashicorp/terraform-provider-aws" || found.Domain != "infrastructure-provisioning-state" {
		t.Fatalf("unexpected Terraform incident identity: %+v", found)
	}
	if found.GroundTruth.Fix.MergeCommit != "079f694ee03602059af6e534d3b14297907ad639" {
		t.Fatalf("Terraform fix provenance drifted: %s", found.GroundTruth.Fix.MergeCommit)
	}
	h := found.KernelMapping.HistoricalOverrides
	if !h["possible_effect_exists"] || !h["substitution_requested"] || h["safe_substitution_proven"] {
		t.Fatalf("historical Terraform mapping must represent an unreconciled possible prior effect: %+v", h)
	}
	if found.KernelMapping.HistoricalExpected != "REJECT_SECOND_EFFECT" {
		t.Fatalf("unexpected Terraform historical disposition %q", found.KernelMapping.HistoricalExpected)
	}
	if found.KernelMapping.FixedExpected != "ALLOW_BOUND_EFFECT" || !found.KernelMapping.FixedOverrides["emit_effect"] {
		t.Fatalf("Terraform fixed counterpart must remain a useful permitted path: %+v", found.KernelMapping)
	}
}

func TestD03APublicHeldOutIncidentsMatchPreregisteredFrozenDispositions(t *testing.T) {
	corpus := loadD03ACorpus(t)
	for _, incident := range corpus.Incidents {
		incident := incident
		t.Run(incident.ID+"/historical", func(t *testing.T) {
			tc := d03AExecutable(t, incident, "historical", incident.KernelMapping.HistoricalOverrides)
			got := evaluateK07(tc)
			if got.Disposition != incident.KernelMapping.HistoricalExpected {
				t.Fatalf("public held-out falsification mismatch: expected=%s got=%s; do not edit frozen v1 to repair this", incident.KernelMapping.HistoricalExpected, got.Disposition)
			}
			if got.ValidTrace != incident.KernelMapping.HistoricalValidTrace {
				t.Fatalf("historical validity mismatch: expected=%v got=%v disposition=%s", incident.KernelMapping.HistoricalValidTrace, got.ValidTrace, got.Disposition)
			}
			if !got.ValidTrace {
				if got.AuthorizedEffects != 0 || got.UnauthorizedEffects != 0 {
					t.Fatalf("historical rejected trace emitted effect: authorized=%d unauthorized=%d", got.AuthorizedEffects, got.UnauthorizedEffects)
				}
			} else {
				if !got.UsefulBehavior {
					t.Fatalf("historical positive boundary case must remain useful: disposition=%s", got.Disposition)
				}
				if got.Disposition == "ALLOW_BOUND_EFFECT" && got.AuthorizedEffects != 1 {
					t.Fatalf("positive historical ALLOW_BOUND_EFFECT must exercise one permitted effect, got %d", got.AuthorizedEffects)
				}
			}
		})

		if strings.TrimSpace(incident.KernelMapping.FixedExpected) != "" {
			t.Run(incident.ID+"/fixed", func(t *testing.T) {
				tc := d03AExecutable(t, incident, "fixed", incident.KernelMapping.FixedOverrides)
				got := evaluateK07(tc)
				if got.Disposition != incident.KernelMapping.FixedExpected {
					t.Fatalf("fixed public counterpart mismatch: expected=%s got=%s; do not edit frozen v1 to repair this", incident.KernelMapping.FixedExpected, got.Disposition)
				}
				if !got.ValidTrace || !got.UsefulBehavior {
					t.Fatalf("fixed counterpart must demonstrate useful permitted/closed behavior: valid=%v useful=%v disposition=%s", got.ValidTrace, got.UsefulBehavior, got.Disposition)
				}
			})
		}
	}
}
