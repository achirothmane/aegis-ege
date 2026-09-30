package governedactionnormative

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

type freezeArtifact struct {
	Path       string `json:"path"`
	GitBlobSHA string `json:"git_blob_sha"`
}

type freezeSupporting struct {
	Repo   string `json:"repo"`
	PR     int    `json:"pr"`
	Head   string `json:"head"`
	Merge  string `json:"merge"`
	CIRuns []int64 `json:"ci_runs"`
}

type freezePrerequisite struct {
	ID         string             `json:"id"`
	Status     string             `json:"status"`
	Repo       string             `json:"repo"`
	PR         int                `json:"pr"`
	Head       string             `json:"head"`
	Merge      string             `json:"merge"`
	CIRuns     []int64            `json:"ci_runs"`
	Supporting []freezeSupporting `json:"supporting"`
}

type freezeExclusion struct {
	ID     string `json:"id"`
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type freezeReview struct {
	Identity            string   `json:"identity"`
	Roles               []string `json:"roles"`
	Evidence            string   `json:"evidence"`
	IndependentReviewer bool     `json:"independent_reviewer"`
}

type freezeClaims struct {
	DemonstratedPlatformKernel       bool `json:"demonstrated_platform_kernel"`
	RuntimeRelease                   bool `json:"runtime_release"`
	HeldOutGeneralizationCompleted   bool `json:"held_out_generalization_completed"`
	K07ExecutableConformanceCompleted bool `json:"k07_executable_conformance_completed"`
	IndependentReviewClaimed         bool `json:"independent_review_claimed"`
}

type freezeCorpus struct {
	Repo       string `json:"repo"`
	Commit     string `json:"commit"`
	Path       string `json:"path"`
	GitBlobSHA string `json:"git_blob_sha"`
	Profile    string `json:"profile"`
}

type freezeManifest struct {
	SchemaVersion                   string               `json:"schema_version"`
	FreezeID                        string               `json:"freeze_id"`
	Status                          string               `json:"status"`
	NormativeSemanticsParentCommit  string               `json:"normative_semantics_parent_commit"`
	Claims                          freezeClaims         `json:"claims"`
	NormativeArtifacts              []freezeArtifact     `json:"normative_artifacts"`
	ExternalCorpora                 []freezeCorpus       `json:"external_corpora"`
	Prerequisites                   []freezePrerequisite `json:"prerequisites"`
	ExcludedFromFreezePrerequisites []freezeExclusion    `json:"excluded_from_freeze_prerequisites"`
	ReviewAttribution               []freezeReview       `json:"review_attribution"`
}

func loadFreezeManifest(t *testing.T) freezeManifest {
	t.Helper()
	var m freezeManifest
	readJSON(t, repoPath("docs", "governed-action", "kernel-v1-freeze-manifest.json"), &m)
	return m
}

func gitBlobSHA(payload []byte) string {
	h := sha1.New()
	_, _ = fmt.Fprintf(h, "blob %d%c", len(payload), byte(0))
	_, _ = h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func TestFreezeManifestPinsExactNormativeBlobBytes(t *testing.T) {
	m := loadFreezeManifest(t)
	if m.SchemaVersion != "governed-action.freeze-manifest/v1" {
		t.Fatalf("unexpected freeze manifest version %q", m.SchemaVersion)
	}
	if m.FreezeID != "candidate-kernel-contract-v1" || m.Status != "FROZEN" {
		t.Fatalf("unexpected freeze identity/status: %q %q", m.FreezeID, m.Status)
	}
	if m.NormativeSemanticsParentCommit != "43431ac8a2998ccd80cbc546583bb414304df7d7" {
		t.Fatalf("unexpected normative semantics parent %q", m.NormativeSemanticsParentCommit)
	}

	seen := map[string]bool{}
	for _, artifact := range m.NormativeArtifacts {
		if artifact.Path == "" || artifact.GitBlobSHA == "" {
			t.Fatalf("incomplete normative artifact: %+v", artifact)
		}
		if seen[artifact.Path] {
			t.Fatalf("duplicate normative artifact %q", artifact.Path)
		}
		seen[artifact.Path] = true
		payload, err := os.ReadFile(repoPath(artifact.Path))
		if err != nil {
			t.Fatalf("read frozen artifact %s: %v", artifact.Path, err)
		}
		if got := gitBlobSHA(payload); got != artifact.GitBlobSHA {
			t.Fatalf("frozen artifact %s changed: manifest=%s local=%s", artifact.Path, artifact.GitBlobSHA, got)
		}
	}
	if len(seen) != 7 {
		t.Fatalf("expected 7 frozen normative artifacts, got %d", len(seen))
	}
}

func TestFreezePrerequisiteSetIsExactAndComplete(t *testing.T) {
	m := loadFreezeManifest(t)
	want := []string{"C01", "C03", "C04", "C05", "C06", "C07", "C08", "C09", "E01", "K01", "K02", "K03", "K04", "K05"}
	got := make([]string, 0, len(m.Prerequisites))
	for _, p := range m.Prerequisites {
		got = append(got, p.ID)
		if p.Status != "COMPLETE" {
			t.Fatalf("%s not complete: %q", p.ID, p.Status)
		}
		if p.ID != "E01" && len(p.CIRuns) == 0 {
			t.Fatalf("%s missing exact-head CI evidence", p.ID)
		}
		if p.ID != "E01" && (p.Repo == "" || p.PR == 0 || p.Head == "" || p.Merge == "") {
			t.Fatalf("%s missing exact merge provenance: %+v", p.ID, p)
		}
		supportingCI := 0
		for _, s := range p.Supporting {
			if s.Repo == "" || s.PR == 0 || s.Head == "" || s.Merge == "" {
				t.Fatalf("%s has incomplete supporting provenance: %+v", p.ID, s)
			}
			if len(s.CIRuns) > 0 {
				supportingCI++
			}
			if p.ID != "E01" && len(s.CIRuns) == 0 {
				t.Fatalf("%s supporting head missing CI evidence: %+v", p.ID, s)
			}
		}
		if p.ID == "E01" && supportingCI < 2 {
			t.Fatalf("E01 requires CI-backed source and mirror evidence, got %d supporting CI records", supportingCI)
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("freeze prerequisite set mismatch\nwant=%v\n got=%v", want, got)
	}
}

func TestFreezeExplicitlyExcludesNonPrerequisitesAndOpenPRs(t *testing.T) {
	m := loadFreezeManifest(t)
	ex := map[string]freezeExclusion{}
	for _, item := range m.ExcludedFromFreezePrerequisites {
		ex[item.ID] = item
	}
	for _, id := range []string{"C02", "C10", "K07", "D00-D06", "PR64", "PR65"} {
		if _, ok := ex[id]; !ok {
			t.Fatalf("missing freeze exclusion %s", id)
		}
	}
	if ex["PR64"].State != "OPEN" || ex["PR65"].State != "OPEN" {
		t.Fatalf("open PRs must not be represented as merged protection: PR64=%q PR65=%q", ex["PR64"].State, ex["PR65"].State)
	}
}

func TestFreezeDoesNotOverclaimMaturityOrIndependentReview(t *testing.T) {
	m := loadFreezeManifest(t)
	if m.Claims.DemonstratedPlatformKernel ||
		m.Claims.RuntimeRelease ||
		m.Claims.HeldOutGeneralizationCompleted ||
		m.Claims.K07ExecutableConformanceCompleted ||
		m.Claims.IndependentReviewClaimed {
		t.Fatalf("freeze overclaims maturity: %+v", m.Claims)
	}
	if len(m.ReviewAttribution) == 0 {
		t.Fatal("actual review attribution is required")
	}
	for _, review := range m.ReviewAttribution {
		if strings.TrimSpace(review.Identity) == "" || len(review.Roles) == 0 || strings.TrimSpace(review.Evidence) == "" {
			t.Fatalf("incomplete review attribution: %+v", review)
		}
		if review.IndependentReviewer {
			t.Fatalf("no independent reviewer is claimed by this freeze: %+v", review)
		}
	}
}

func TestFreezePreservesByteIdenticalStateBindingCorpus(t *testing.T) {
	m := loadFreezeManifest(t)
	var source, mirror *freezeCorpus
	for i := range m.ExternalCorpora {
		c := &m.ExternalCorpora[i]
		if c.GitBlobSHA != "82d151531da6f98262de1e247658d89a8299c53c" {
			continue
		}
		if c.Repo == "achirothmane/easl" {
			source = c
		}
		if c.Repo == "achirothmane/workflow-failure-lab" {
			mirror = c
		}
	}
	if source == nil || mirror == nil {
		t.Fatal("freeze must pin both EASL StateBinding source and WFL mirror")
	}
	if source.GitBlobSHA != mirror.GitBlobSHA {
		t.Fatalf("StateBinding source/mirror divergence: %s != %s", source.GitBlobSHA, mirror.GitBlobSHA)
	}
}
