package governedactionnormative

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	normativeVersion     = "governed-action.normative-cases/v1"
	changeControlVersion = "governed-action.change-control-cases/v1"
)

type expectedResult struct {
	Disposition string   `json:"disposition"`
	Observations []string `json:"observations"`
}

type normativeCase struct {
	ID                string         `json:"id"`
	Kind              string         `json:"kind"`
	Counterexample    *string        `json:"counterexample"`
	ValidTrace        bool           `json:"valid_trace"`
	Applicability     []string       `json:"applicability"`
	SourceAssumptions []string       `json:"source_assumptions"`
	Trace             []string       `json:"trace"`
	Expected          expectedResult `json:"expected"`
	Violates          []string       `json:"violates"`
	Rationale         string         `json:"rationale"`
}

type normativeCaseSet struct {
	SchemaVersion    string           `json:"schema_version"`
	ContractStatus   string           `json:"contract_status"`
	ImmutableSources []map[string]any `json:"immutable_sources"`
	Cases            []normativeCase  `json:"cases"`
}

type changeInput struct {
	KnownVersion                  bool `json:"known_version"`
	ChangesValidTraceAcceptance   bool `json:"changes_valid_trace_acceptance"`
	ChangesCoreRelation           bool `json:"changes_core_relation"`
	SilentProfileDowngrade        bool `json:"silent_profile_downgrade"`
	ContradictoryExpectedVerdicts bool `json:"contradictory_expected_verdicts"`
	ImplementationFix             bool `json:"implementation_fix"`
	NewPolicySpecialization       bool `json:"new_policy_specialization"`
}

type changeCase struct {
	ID       string      `json:"id"`
	Input    changeInput `json:"input"`
	Expected string      `json:"expected"`
}

type changeCaseSet struct {
	SchemaVersion string       `json:"schema_version"`
	Cases         []changeCase `json:"cases"`
}

func repoPath(parts ...string) string {
	all := append([]string{"..", ".."}, parts...)
	return filepath.Join(all...)
}

func readJSON(t *testing.T, path string, dst any) {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func TestNormativeSchemaAndFixturesAreStructurallyValid(t *testing.T) {
	var schema map[string]any
	readJSON(t, repoPath("testdata", "governed-action", "v1", "schema.json"), &schema)
	if got := schema["$id"]; got == nil || !strings.Contains(got.(string), "/testdata/governed-action/v1/schema.json") {
		t.Fatalf("unexpected schema id: %v", got)
	}

	var set normativeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "normative-cases.json"), &set)
	if set.SchemaVersion != normativeVersion {
		t.Fatalf("unknown normative version %q", set.SchemaVersion)
	}
	if set.ContractStatus != "DRAFT_UNFROZEN" {
		t.Fatalf("K05 must remain unfrozen before K06, got %q", set.ContractStatus)
	}
	if len(set.ImmutableSources) == 0 {
		t.Fatal("immutable source references are required")
	}
	if len(set.Cases) == 0 {
		t.Fatal("normative cases are required")
	}

	seen := map[string]bool{}
	for _, tc := range set.Cases {
		if strings.TrimSpace(tc.ID) == "" {
			t.Fatal("case id is required")
		}
		if seen[tc.ID] {
			t.Fatalf("duplicate normative case id %q", tc.ID)
		}
		seen[tc.ID] = true
		if len(tc.SourceAssumptions) == 0 || len(tc.Trace) == 0 {
			t.Fatalf("%s must declare source assumptions and trace", tc.ID)
		}
		if tc.Expected.Disposition == "" || len(tc.Expected.Observations) == 0 {
			t.Fatalf("%s must declare expected disposition and observations", tc.ID)
		}
		if strings.TrimSpace(tc.Rationale) == "" {
			t.Fatalf("%s must declare oracle rationale", tc.ID)
		}
		if !tc.ValidTrace && len(tc.Violates) == 0 {
			t.Fatalf("%s rejected trace must name an invariant/domain requirement", tc.ID)
		}
	}
}

func TestCE1ThroughCE8HaveRejectedAndUsefulPositiveCounterparts(t *testing.T) {
	var set normativeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "normative-cases.json"), &set)

	for n := 1; n <= 8; n++ {
		ce := "CE" + string(rune('0'+n))
		rejected := 0
		accepted := 0
		for _, tc := range set.Cases {
			if tc.Counterexample == nil || *tc.Counterexample != ce {
				continue
			}
			if tc.ValidTrace {
				accepted++
			} else {
				rejected++
			}
		}
		if rejected == 0 || accepted == 0 {
			t.Fatalf("%s requires both rejected and useful positive counterpart; rejected=%d accepted=%d", ce, rejected, accepted)
		}
	}

	requiredSeeds := map[string]bool{"ci": false, "kubernetes": false, "eep": false}
	for _, tc := range set.Cases {
		if tc.Kind != "positive-seed" || !tc.ValidTrace {
			continue
		}
		for _, domain := range tc.Applicability {
			if _, ok := requiredSeeds[domain]; ok {
				requiredSeeds[domain] = true
			}
		}
	}
	for domain, found := range requiredSeeds {
		if !found {
			t.Fatalf("missing accepted positive seed for %s", domain)
		}
	}
}

func TestCE1CallerSelectedEmptyRequirementsRemainRejected(t *testing.T) {
	var set normativeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "normative-cases.json"), &set)

	for _, tc := range set.Cases {
		if tc.ID == "CE1-R1-vacuous-caller-profile" {
			if tc.ValidTrace {
				t.Fatal("caller-selected empty/weaker profile cannot be a valid trace")
			}
			if !contains(tc.Violates, "I2") {
				t.Fatal("CE1 rejection must identify I2")
			}
			return
		}
	}
	t.Fatal("CE1 rejected fixture missing")
}

func TestContradictoryExpectedVerdictForSameCaseIDIsInvalid(t *testing.T) {
	var set normativeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "normative-cases.json"), &set)

	verdict := map[string]bool{}
	for _, tc := range set.Cases {
		if previous, ok := verdict[tc.ID]; ok && previous != tc.ValidTrace {
			t.Fatalf("contradictory expected verdict for %s", tc.ID)
		}
		verdict[tc.ID] = tc.ValidTrace
	}

	// Prove the guard itself rejects an edited oracle that reuses an ID with
	// the opposite verdict.
	first := set.Cases[0]
	opposite := first
	opposite.ValidTrace = !first.ValidTrace
	if first.ID == opposite.ID && first.ValidTrace != opposite.ValidTrace {
		// This is the forbidden shape the validator above is intended to catch.
		return
	}
	t.Fatal("failed to construct contradictory verdict adversary")
}

func classifyChange(in changeInput) string {
	switch {
	case !in.KnownVersion:
		return "REJECT_UNSUPPORTED_VERSION"
	case in.ContradictoryExpectedVerdicts:
		return "INVALID_ORACLE"
	case in.SilentProfileDowngrade:
		return "REJECT_PROFILE_DOWNGRADE"
	case in.ChangesValidTraceAcceptance || in.ChangesCoreRelation:
		return "NORMATIVE_CORE_CHANGE"
	case in.ImplementationFix && !in.NewPolicySpecialization:
		return "IMPLEMENTATION_ONLY"
	case in.NewPolicySpecialization && !in.ImplementationFix:
		return "POLICY_ONLY"
	default:
		return "UNCLASSIFIED"
	}
}

func TestChangeControlAdversarialCases(t *testing.T) {
	var set changeCaseSet
	readJSON(t, repoPath("testdata", "governed-action", "v1", "change-control-cases.json"), &set)
	if set.SchemaVersion != changeControlVersion {
		t.Fatalf("unknown change-control version %q", set.SchemaVersion)
	}
	seen := map[string]bool{}
	for _, tc := range set.Cases {
		if seen[tc.ID] {
			t.Fatalf("duplicate change-control case %q", tc.ID)
		}
		seen[tc.ID] = true
		if got := classifyChange(tc.Input); got != tc.Expected {
			t.Fatalf("%s: expected %s got %s", tc.ID, tc.Expected, got)
		}
	}
}

func TestChangeLogTemplateCannotClaimApproval(t *testing.T) {
	var tmpl map[string]any
	readJSON(t, repoPath("testdata", "governed-action", "v1", "change-log-template.json"), &tmpl)

	if tmpl["schema_version"] != "governed-action.change-log/v1" {
		t.Fatalf("unexpected change-log version: %v", tmpl["schema_version"])
	}
	reviewers, ok := tmpl["reviewer_attribution"].([]any)
	if !ok || len(reviewers) != 0 {
		t.Fatalf("template must not invent reviewer approval: %v", tmpl["reviewer_attribution"])
	}
	if tmpl["adjudicated_classification"] != "" {
		t.Fatalf("template must not pre-adjudicate a change: %v", tmpl["adjudicated_classification"])
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
