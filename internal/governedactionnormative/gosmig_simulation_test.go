package governedactionnormative

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const gosmigRegistrationBlob = "1942ec24e31f849e07177d14bb244003ccd8b51e"

type gosmigRegistration struct {
	SchemaVersion string `json:"schema_version"`
	Classification string `json:"classification"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	Claims struct {
		IndependentParticipation bool `json:"independent_participation"`
		D03Pass bool `json:"d03_pass"`
		D04LibraryExtraction bool `json:"d04_library_extraction"`
		FullPlatformKernel bool `json:"full_platform_kernel"`
	} `json:"claims"`
	Cases []struct {
		CaseID string `json:"case_id"`
		Expected struct {
			WorkerExits []int `json:"worker_exits"`
			Effects int `json:"effects"`
			Versions int `json:"versions"`
			Custody int `json:"custody"`
			Observation string `json:"observation"`
			K07Disposition string `json:"k07_disposition"`
		} `json:"expected"`
	} `json:"cases"`
}

func loadGosmigRegistration(t *testing.T) gosmigRegistration {
	t.Helper()
	path:=repoPath("testdata","governed-action","gosmig-simulation","registration-v1.json")
	data,err:=os.ReadFile(path); if err!=nil { t.Fatal(err) }
	if got:=gitBlobSHA(data); got!=gosmigRegistrationBlob { t.Fatalf("pre-execution registration changed: %s",got) }
	var reg gosmigRegistration
	if err:=json.Unmarshal(data,&reg); err!=nil { t.Fatal(err) }
	return reg
}

func TestGosmigSimulationRegistrationPreservesScopeAndOracle(t *testing.T) {
	r:=loadGosmigRegistration(t)
	if r.SchemaVersion!="governed-action.gosmig-simulation-registration/v1" || r.Classification!="SAME_OWNER_SUPPLEMENTAL_FALSIFICATION" || len(r.Cases)!=13 { t.Fatal("incorrect fixture scope") }
	if r.Claims.IndependentParticipation || r.Claims.D03Pass || r.Claims.D04LibraryExtraction || r.Claims.FullPlatformKernel { t.Fatal("same-owner simulation must not claim independent D03, D04 or a platform kernel") }
	data,err:=os.ReadFile(repoPath("testdata","governed-action","v1","normative-cases.json")); if err!=nil { t.Fatal(err) }
	if gitBlobSHA(data)!=r.FrozenOracleBlob { t.Fatal("simulation changed or unpinned frozen oracle") }
	seen:=map[string]bool{}
	for _, c:=range r.Cases {
		if seen[c.CaseID] { t.Fatalf("duplicate simulation case %s",c.CaseID) }; seen[c.CaseID]=true
		if strings.HasPrefix(c.CaseID,"N") && c.Expected.K07Disposition!="CONTROL_ONLY" { t.Fatal("native control cannot be represented as governed acceptance") }
	}
	for _, id:=range []string{"N01","N02","G01","G02","G03","G04","G05","G06","G07","G08","G09","G10","G11"} { if !seen[id] { t.Fatalf("missing registered schedule %s",id) } }
}

type gosmigNativeEvidence struct {
	SchemaVersion string `json:"schema_version"`
	Classification string `json:"classification"`
	SourceHead string `json:"source_head"`
	RegistrationCommit string `json:"registration_commit"`
	RegistrationBlob string `json:"registration_blob"`
	UpstreamCommit string `json:"upstream_commit"`
	UpstreamVersion string `json:"upstream_version"`
	FrozenOracleBlob string `json:"frozen_oracle_blob"`
	PostgreSQLVersion string `json:"postgresql_version"`
	IndependentParticipation bool `json:"independent_participation"`
	D03Pass bool `json:"d03_pass"`
	Passed bool `json:"passed"`
	Cases []struct {
		CaseID string `json:"case_id"`
		Workers []struct { ExitCode int `json:"exit_code"` } `json:"workers"`
		Final struct {
			Effects int `json:"effects"`
			Versions int `json:"versions"`
			CustodyCount int `json:"custody_count"`
		} `json:"final"`
		ObservationLabel string `json:"observation_label"`
		ObservationUnchanged bool `json:"observation_unchanged"`
		ReadOnlyMutationDenied bool `json:"read_only_mutation_denied"`
		Observations []struct {
			EffectID string `json:"effect_id"`
			AttemptID string `json:"attempt_id"`
			ActionRef string `json:"action_ref"`
			DispatchAccepted *bool `json:"dispatch_accepted"`
			PostconditionExact bool `json:"postcondition_exact"`
			ObserverReadOnly bool `json:"observer_read_only"`
		} `json:"observations"`
		Trace k07ExecutableCase `json:"trace"`
	} `json:"cases"`
}

func TestGosmigNativeEvidenceUsesUnchangedK07Evaluator(t *testing.T) {
	path:=os.Getenv("GOSMIG_SIM_EVIDENCE")
	if path=="" { t.Skip("native PostgreSQL evidence is mandatory in the dedicated gosmig workflow") }
	var e gosmigNativeEvidence; readJSON(t,path,&e)
	r:=loadGosmigRegistration(t)
	if !e.Passed || e.SchemaVersion!="governed-action.gosmig-native-evidence/v1" || e.Classification!=r.Classification || e.IndependentParticipation || e.D03Pass { t.Fatal("missing native success or overclaimed independence") }
	if e.RegistrationCommit!="efdffa811a272128248476b273392feb3d369814" || e.RegistrationBlob!=gosmigRegistrationBlob || e.FrozenOracleBlob!=r.FrozenOracleBlob { t.Fatal("native evidence lost pre-execution registration or frozen oracle") }
	if e.UpstreamCommit!="f2cc69c685d654990d01582cb68b2c5b097cb36d" || e.UpstreamVersion!="v0.0.0-20251102200842-f2cc69c685d6" || !strings.Contains(e.PostgreSQLVersion,"PostgreSQL 16.6") { t.Fatal("native source/runtime pin mismatch") }
	if e.SourceHead=="" || e.SourceHead!=os.Getenv("GS_SOURCE_HEAD") { t.Fatal("evidence does not match tested source head") }
	if len(e.Cases)!=len(r.Cases) { t.Fatal("native execution skipped a registered schedule") }
	seen:=map[string]bool{}
	results:=map[string]k07Result{}
	for _, actual:=range e.Cases {
		if seen[actual.CaseID] { t.Fatalf("duplicate native schedule %s",actual.CaseID) }; seen[actual.CaseID]=true
		found:=false
		for _, registered:=range r.Cases {
			if actual.CaseID!=registered.CaseID { continue }; found=true
			want:=registered.Expected
			if actual.Final.Effects!=want.Effects || actual.Final.Versions!=want.Versions || actual.Final.CustodyCount!=want.Custody || actual.ObservationLabel!=want.Observation || len(actual.Workers)!=len(want.WorkerExits) { t.Fatalf("native facts violated registration for %s",actual.CaseID) }
			for i,w:=range actual.Workers { if w.ExitCode!=want.WorkerExits[i] { t.Fatalf("worker exit mismatch for %s",actual.CaseID) } }
			if want.K07Disposition=="CONTROL_ONLY" { continue }
			if actual.Trace.CaseID!=actual.CaseID || actual.Trace.Input.RequiredIndependence || actual.Trace.Input.IndependenceSatisfied { t.Fatal("supplemental trace invented independence") }
			if want.Custody>0 {
				if len(actual.Observations)!=2 || !actual.ObservationUnchanged || !actual.ReadOnlyMutationDenied { t.Fatal("recovery was not separately read-only and repeatable") }
				for _,o:=range actual.Observations {
					if o.EffectID!=actual.Trace.EffectID || o.AttemptID!=actual.Trace.AttemptID || o.ActionRef!=actual.Trace.ActionRef || o.DispatchAccepted!=nil || !o.ObserverReadOnly || o.PostconditionExact!=(want.Observation=="VERIFIED/CLOSED") { t.Fatal("recovery lost original identity or claimed an unavailable receipt") }
				}
			}
			got:=evaluateK07(actual.Trace)
			if got.Disposition!=want.K07Disposition || got.UnauthorizedEffects!=0 { t.Fatalf("unchanged K07 mismatch for %s: want %s got %+v",actual.CaseID,want.K07Disposition,got) }
			results[actual.CaseID]=got
		}
		if !found { t.Fatalf("unregistered native schedule %s",actual.CaseID) }
	}
	if len(results)!=11 { t.Fatal("not every governed schedule passed unchanged K07") }
	if out:=os.Getenv("GOSMIG_SIM_ORACLE_RESULT"); out!="" {
		data,err:=json.MarshalIndent(results,"","  "); if err!=nil { t.Fatal(err) }
		if err:=os.WriteFile(out,append(data,'\n'),0600); err!=nil { t.Fatal(err) }
	}
}
