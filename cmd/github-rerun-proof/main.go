package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	ga "github.com/achirothmane/aegis-ege/governedaction"
)

const (
	profileID       = "github-ci-rerun/v1"
	custodyVersion  = "aegis.github-rerun-custody/v1"
	boundaryVersion = "aegis.github-rerun-boundary/v1"
	evidenceVersion = "aegis.github-rerun-native-evidence/v1"
)

type workflowRun struct {
	ID         int64  `json:"id"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	RunAttempt int    `json:"run_attempt"`
}

type custodyRecord struct {
	SchemaVersion  string `json:"schema_version"`
	Repository     string `json:"repository"`
	RunID          int64  `json:"run_id"`
	HeadSHA        string `json:"head_sha"`
	InitialAttempt int    `json:"initial_attempt"`
	ActionRef      string `json:"action_ref"`
	EffectID       string `json:"effect_id"`
	AttemptID      string `json:"attempt_id"`
	Target         string `json:"target"`
	Profile        string `json:"profile"`
	AuthorityUntil string `json:"authority_until"`
	RecordedAt     string `json:"recorded_at"`
}

type boundaryRecord struct {
	SchemaVersion string `json:"schema_version"`
	CustodyDigest string `json:"custody_digest"`
	RunID         int64  `json:"run_id"`
	RunAttempt    int    `json:"run_attempt"`
	HeadSHA       string `json:"head_sha"`
	CheckedAt     string `json:"checked_at"`
}

type nativeEvidence struct {
	SchemaVersion            string `json:"schema_version"`
	Repository               string `json:"repository"`
	RunID                    int64  `json:"run_id"`
	HeadSHA                  string `json:"head_sha"`
	ActionRef                string `json:"action_ref"`
	EffectID                 string `json:"effect_id"`
	AttemptID                string `json:"attempt_id"`
	InitialAttempt           int    `json:"initial_attempt"`
	ObservedAttempt          int    `json:"observed_attempt"`
	ObservedStatus           string `json:"observed_status"`
	ObservedConclusion       string `json:"observed_conclusion"`
	CustodyRecorded          bool   `json:"custody_recorded"`
	BoundaryRevalidated      bool   `json:"boundary_revalidated"`
	DispatchReceiptAvailable bool   `json:"dispatch_receipt_available"`
	RecoveryMutation         bool   `json:"recovery_mutation"`
	FinalState               string `json:"final_state"`
	ObservationRef           string `json:"observation_ref"`
	ObservedAt               string `json:"observed_at"`
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: github-rerun-proof <prepare|boundary|reconcile> [flags]")
	}
	switch os.Args[1] {
	case "prepare":
		runPrepare(os.Args[2:])
	case "boundary":
		runBoundary(os.Args[2:])
	case "reconcile":
		runReconcile(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}

func runPrepare(args []string) {
	fs := flag.NewFlagSet("prepare", flag.ExitOnError)
	repo := fs.String("repo", "", "owner/repository")
	snapshotPath := fs.String("snapshot", "", "native workflow-run snapshot")
	expectedHead := fs.String("expected-head", "", "exact admitted head SHA")
	initialAttempt := fs.Int("initial-attempt", 1, "expected pre-effect run attempt")
	authorityUntil := fs.String("authority-until", "", "RFC3339 authority expiry")
	custodyPath := fs.String("custody", "", "durable custody file")
	_ = fs.Parse(args)

	requireNonEmpty("repo", *repo)
	requireNonEmpty("snapshot", *snapshotPath)
	requireNonEmpty("expected-head", *expectedHead)
	requireNonEmpty("authority-until", *authorityUntil)
	requireNonEmpty("custody", *custodyPath)
	until := mustTime(*authorityUntil)

	var run workflowRun
	mustReadJSON(*snapshotPath, &run)
	if run.ID <= 0 || *initialAttempt <= 0 {
		fatalf("run id and initial attempt must be positive")
	}

	actionRef := "github-head:" + *expectedHead
	target := fmt.Sprintf("github://%s/actions/runs/%d", *repo, run.ID)
	admitted := ga.Binding{ActionRevision: actionRef, Target: target, Profile: profileID}
	current := ga.Binding{ActionRevision: "github-head:" + run.HeadSHA, Target: target, Profile: profileID}
	check := func() error {
		if err := ga.CheckBinding(admitted, current); err != nil {
			return err
		}
		if err := ga.CheckValidity(until, time.Now().UTC()); err != nil {
			return err
		}
		if run.RunAttempt != *initialAttempt || run.Status != "completed" || run.Conclusion != "failure" {
			return fmt.Errorf("native state not admitted: attempt=%d status=%s conclusion=%s", run.RunAttempt, run.Status, run.Conclusion)
		}
		return nil
	}

	if err := check(); err != nil {
		fatalf("admission: %v", err)
	}
	record := custodyRecord{
		SchemaVersion:  custodyVersion,
		Repository:     *repo,
		RunID:          run.ID,
		HeadSHA:        *expectedHead,
		InitialAttempt: *initialAttempt,
		ActionRef:      actionRef,
		EffectID:       fmt.Sprintf("github-rerun:%s:%d", *repo, run.ID),
		AttemptID:      fmt.Sprintf("github-rerun:%s:%d:from:%d", *repo, run.ID, *initialAttempt),
		Target:         target,
		Profile:        profileID,
		AuthorityUntil: until.UTC().Format(time.RFC3339Nano),
		RecordedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONAtomic(*custodyPath, record); err != nil {
		fatalf("retain custody: %v", err)
	}
	if err := check(); err != nil {
		fatalf("post-custody revalidation: %v", err)
	}
	fmt.Printf("CUSTODY_READY run=%d effect=%s\n", run.ID, record.EffectID)
}

func runBoundary(args []string) {
	fs := flag.NewFlagSet("boundary", flag.ExitOnError)
	custodyPath := fs.String("custody", "", "durable custody file")
	snapshotPath := fs.String("snapshot", "", "fresh workflow-run snapshot")
	boundaryPath := fs.String("boundary-out", "", "boundary proof file")
	_ = fs.Parse(args)
	requireNonEmpty("custody", *custodyPath)
	requireNonEmpty("snapshot", *snapshotPath)
	requireNonEmpty("boundary-out", *boundaryPath)

	var custody custodyRecord
	mustReadJSON(*custodyPath, &custody)
	if custody.SchemaVersion != custodyVersion {
		fatalf("unsupported custody version %q", custody.SchemaVersion)
	}
	var run workflowRun
	mustReadJSON(*snapshotPath, &run)
	until := mustTime(custody.AuthorityUntil)

	current := ga.Binding{
		ActionRevision: "github-head:" + run.HeadSHA,
		Target:         fmt.Sprintf("github://%s/actions/runs/%d", custody.Repository, run.ID),
		Profile:        profileID,
	}
	admitted := ga.Binding{
		ActionRevision: custody.ActionRef,
		Target:         custody.Target,
		Profile:        custody.Profile,
	}
	if err := ga.CheckBinding(admitted, current); err != nil {
		fatalf("boundary binding: %v", err)
	}
	if err := ga.CheckValidity(until, time.Now().UTC()); err != nil {
		fatalf("boundary authority: %v", err)
	}
	if run.ID != custody.RunID || run.RunAttempt != custody.InitialAttempt || run.Status != "completed" || run.Conclusion != "failure" {
		fatalf("boundary native state changed: run=%d attempt=%d status=%s conclusion=%s", run.ID, run.RunAttempt, run.Status, run.Conclusion)
	}
	digest, err := fileDigest(*custodyPath)
	if err != nil {
		fatalf("digest custody: %v", err)
	}
	record := boundaryRecord{
		SchemaVersion: boundaryVersion,
		CustodyDigest: digest,
		RunID:         run.ID,
		RunAttempt:    run.RunAttempt,
		HeadSHA:       run.HeadSHA,
		CheckedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONAtomic(*boundaryPath, record); err != nil {
		fatalf("write boundary proof: %v", err)
	}
	fmt.Printf("BOUNDARY_READY run=%d attempt=%d\n", run.ID, run.RunAttempt)
}

func runReconcile(args []string) {
	fs := flag.NewFlagSet("reconcile", flag.ExitOnError)
	custodyPath := fs.String("custody", "", "durable custody file")
	boundaryPath := fs.String("boundary", "", "pre-effect boundary proof")
	observationPath := fs.String("observation", "", "post-effect native workflow-run snapshot")
	evidencePath := fs.String("evidence-out", "", "native evidence output")
	_ = fs.Parse(args)
	requireNonEmpty("custody", *custodyPath)
	requireNonEmpty("boundary", *boundaryPath)
	requireNonEmpty("observation", *observationPath)
	requireNonEmpty("evidence-out", *evidencePath)

	var custody custodyRecord
	var boundary boundaryRecord
	var run workflowRun
	mustReadJSON(*custodyPath, &custody)
	mustReadJSON(*boundaryPath, &boundary)
	mustReadJSON(*observationPath, &run)
	if custody.SchemaVersion != custodyVersion || boundary.SchemaVersion != boundaryVersion {
		fatalf("unsupported proof record version")
	}
	digest, err := fileDigest(*custodyPath)
	if err != nil {
		fatalf("digest custody: %v", err)
	}
	if boundary.CustodyDigest != digest || boundary.RunID != custody.RunID || boundary.RunAttempt != custody.InitialAttempt || boundary.HeadSHA != custody.HeadSHA {
		fatalf("boundary proof is not bound to retained custody")
	}

	state := "UNKNOWN"
	observation := "native outcome is not exactly proven"
	if run.ID == custody.RunID && run.HeadSHA == custody.HeadSHA {
		switch {
		case run.RunAttempt > custody.InitialAttempt+1:
			observation = "duplicate rerun attempt observed"
		case run.RunAttempt == custody.InitialAttempt+1 && run.Status == "completed":
			state = "CLOSED"
			observation = "same workflow run observed after executor process loss"
		}
	}
	evidence := nativeEvidence{
		SchemaVersion:            evidenceVersion,
		Repository:               custody.Repository,
		RunID:                    custody.RunID,
		HeadSHA:                  custody.HeadSHA,
		ActionRef:                custody.ActionRef,
		EffectID:                 custody.EffectID,
		AttemptID:                custody.AttemptID,
		InitialAttempt:           custody.InitialAttempt,
		ObservedAttempt:          run.RunAttempt,
		ObservedStatus:           run.Status,
		ObservedConclusion:       run.Conclusion,
		CustodyRecorded:          true,
		BoundaryRevalidated:      true,
		DispatchReceiptAvailable: false,
		RecoveryMutation:         false,
		FinalState:               state,
		ObservationRef:           observation,
		ObservedAt:               time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err := writeJSONAtomic(*evidencePath, evidence); err != nil {
		fatalf("write evidence: %v", err)
	}
	if state != "CLOSED" {
		fatalf("reconciliation remains UNKNOWN: attempt=%d status=%s conclusion=%s", run.RunAttempt, run.Status, run.Conclusion)
	}
	if run.RunAttempt != custody.InitialAttempt+1 || run.Conclusion != "success" {
		fatalf("closed rerun does not satisfy proof postcondition: attempt=%d conclusion=%s", run.RunAttempt, run.Conclusion)
	}
	fmt.Printf("CLOSED run=%d attempt=%d conclusion=%s\n", run.ID, run.RunAttempt, run.Conclusion)
}

func fileDigest(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func writeJSONAtomic(path string, value any) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".aegis-github-rerun-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func mustReadJSON(path string, out any) {
	data, err := os.ReadFile(path)
	if err != nil {
		fatalf("read %s: %v", path, err)
	}
	if err := json.Unmarshal(data, out); err != nil {
		fatalf("decode %s: %v", path, err)
	}
}

func mustTime(value string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(value))
	if err != nil {
		fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func requireNonEmpty(name, value string) {
	if strings.TrimSpace(value) == "" {
		fatalf("%s is required", name)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

