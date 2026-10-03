package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	gaRuntime "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

const (
	targetID       = "terraform:terraform_data.governed"
	operationID    = "terraform.apply"
	custodyVersion = "aegis.terraform-proof-custody/v1"
	evidenceVersion = "aegis.terraform-complexity-dividend/v1"
)

var (
	policyIssuer = gaRuntime.Identity{ID: "policy:terraform-proof", Kind: "policy"}
	observerIssuer = gaRuntime.Identity{ID: "observer:terraform-proof", Kind: "observer"}
	recoveryIssuer = gaRuntime.Identity{ID: "policy:terraform-recovery", Kind: "policy"}
	subjectIdentity = gaRuntime.Identity{ID: "operator:terraform-proof", Kind: "operator"}
	executorIdentity = gaRuntime.Identity{ID: "process:terraform-executor", Kind: "process"}
	recovererIdentity = gaRuntime.Identity{ID: "process:terraform-recoverer", Kind: "process"}
)

type custodyFile struct {
	SchemaVersion string            `json:"schema_version"`
	Custody       gaRuntime.Custody `json:"custody"`
}

type evidence struct {
	SchemaVersion          string                `json:"schema_version"`
	Domain                 string                `json:"domain"`
	Disposition            gaRuntime.Disposition `json:"disposition"`
	EffectID               string                `json:"effect_id"`
	AttemptID              string                `json:"attempt_id"`
	CustodyRecorded        bool                  `json:"custody_recorded"`
	RecoveryBoundaryEntered bool                 `json:"recovery_boundary_entered"`
	ReplayDisposition      gaRuntime.Disposition `json:"replay_disposition"`
	ReplayBoundaryEntered  bool                  `json:"replay_boundary_entered"`
	EffectLogLines         int                   `json:"effect_log_lines"`
	ObservedRevision       string                `json:"observed_revision"`
	ObservedDigest         string                `json:"observed_digest"`
	CoreSemanticDelta      int                   `json:"core_semantic_delta"`
}

type adapter struct {
	workDir       string
	custodyPath   string
	effectLogPath string
	proofValue    string
	crashAfterApply bool
	executeCalls  int
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: terraform-runtime-proof <execute|recover> [flags]")
	}
	switch os.Args[1] {
	case "execute":
		runExecute(os.Args[2:])
	case "recover":
		runRecover(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
}

func runExecute(args []string) {
	fs := flag.NewFlagSet("execute", flag.ExitOnError)
	workDir := fs.String("workdir", "", "Terraform fixture directory")
	custody := fs.String("custody", "", "durable custody file")
	effectLog := fs.String("effect-log", "", "non-idempotent fixture effect log")
	value := fs.String("value", "proof-v1", "intended Terraform output")
	attempt := fs.String("attempt", "attempt:terraform:001", "execution attempt id")
	crash := fs.Bool("crash-after-apply", false, "terminate immediately after Terraform apply returns")
	_ = fs.Parse(args)

	requirePath("workdir", *workDir)
	requirePath("custody", *custody)
	requirePath("effect-log", *effectLog)

	req := buildRequest(*value, *attempt)
	a := &adapter{
		workDir: *workDir,
		custodyPath: *custody,
		effectLogPath: *effectLog,
		proofValue: *value,
		crashAfterApply: *crash,
	}
	result := gaRuntime.Run(context.Background(), req, a)
	if result.Disposition != gaRuntime.DispositionClosed {
		fatalf("execution did not close: disposition=%s cause=%v effectErr=%v observeErr=%v", result.Disposition, result.Cause, result.EffectError, result.ObservationError)
	}
	if a.executeCalls != 1 {
		fatalf("expected exactly one Terraform effect call, got %d", a.executeCalls)
	}
	fmt.Printf("CLOSED effect=%s attempt=%s\n", result.EffectID, result.AttemptID)
}

func runRecover(args []string) {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	workDir := fs.String("workdir", "", "Terraform fixture directory")
	custodyPath := fs.String("custody", "", "durable custody file")
	effectLog := fs.String("effect-log", "", "non-idempotent fixture effect log")
	evidencePath := fs.String("evidence-out", "", "proof evidence output")
	value := fs.String("value", "proof-v1", "intended Terraform output")
	attempt := fs.String("attempt", "attempt:terraform:001", "execution attempt id")
	_ = fs.Parse(args)

	requirePath("workdir", *workDir)
	requirePath("custody", *custodyPath)
	requirePath("effect-log", *effectLog)
	requirePath("evidence-out", *evidencePath)

	req := buildRequest(*value, *attempt)
	a := &adapter{
		workDir: *workDir,
		custodyPath: *custodyPath,
		effectLogPath: *effectLog,
		proofValue: *value,
	}

	effectID, err := gaRuntime.EffectIdentity(req)
	if err != nil {
		fatalf("derive effect identity: %v", err)
	}
	retained, err := a.LoadCustody(context.Background(), effectID, req.AttemptID)
	if err != nil {
		fatalf("load retained custody: %v", err)
	}
	recoveryBinding := gaRuntime.RecoveryBindingDigest(retained, recovererIdentity)
	recovery := gaRuntime.RecoveryRequest{
		Original:  req,
		Recoverer: recovererIdentity,
		RecoveryAuthorization: gaRuntime.Attestation{
			ID:            "recovery:terraform:001",
			Issuer:        recoveryIssuer,
			BindingDigest: recoveryBinding,
		},
	}
	result := gaRuntime.Recover(context.Background(), recovery, a)
	if result.Disposition != gaRuntime.DispositionClosed {
		fatalf("recovery did not close: disposition=%s cause=%v observeErr=%v", result.Disposition, result.Cause, result.ObservationError)
	}
	if result.BoundaryEntered {
		fatalf("observation-only recovery entered an effect boundary")
	}
	if a.executeCalls != 0 {
		fatalf("recovery executed Terraform unexpectedly: calls=%d", a.executeCalls)
	}

	lines, err := countNonEmptyLines(*effectLog)
	if err != nil {
		fatalf("count fixture effects: %v", err)
	}
	if lines != 1 {
		fatalf("effect cardinality violated before replay check: lines=%d", lines)
	}

	replay := gaRuntime.Run(context.Background(), req, a)
	if replay.Disposition != gaRuntime.DispositionRejected {
		fatalf("stale replay was not rejected: disposition=%s cause=%v", replay.Disposition, replay.Cause)
	}
	if replay.BoundaryEntered || a.executeCalls != 0 {
		fatalf("stale replay crossed the effect boundary")
	}

	lines, err = countNonEmptyLines(*effectLog)
	if err != nil {
		fatalf("count fixture effects after replay check: %v", err)
	}
	if lines != 1 {
		fatalf("effect cardinality violated after replay check: lines=%d", lines)
	}

	ev := evidence{
		SchemaVersion:           evidenceVersion,
		Domain:                  "terraform",
		Disposition:             result.Disposition,
		EffectID:                result.EffectID,
		AttemptID:               result.AttemptID,
		CustodyRecorded:         result.CustodyRecorded,
		RecoveryBoundaryEntered: result.BoundaryEntered,
		ReplayDisposition:       replay.Disposition,
		ReplayBoundaryEntered:   replay.BoundaryEntered,
		EffectLogLines:          lines,
		ObservedRevision:        result.Observation.State.Revision,
		ObservedDigest:          result.Observation.State.Digest,
		CoreSemanticDelta:       0,
	}
	if err := writeJSONAtomic(*evidencePath, ev); err != nil {
		fatalf("write evidence: %v", err)
	}
	fmt.Printf("CLOSED recovery effect=%s replay=%s lines=%d\n", result.EffectID, replay.Disposition, lines)
}

func buildRequest(value, attempt string) gaRuntime.Request {
	current := absentState()
	after := presentState(value)
	req := gaRuntime.Request{
		Subject:    subjectIdentity,
		Executor:   executorIdentity,
		Current:    current,
		Transition: gaRuntime.Transition{Operation: operationID, From: current, To: after},
		AttemptID:  attempt,
	}
	binding, err := gaRuntime.AdmissionBindingDigest(req)
	if err != nil {
		fatalf("admission binding: %v", err)
	}
	req.Admission = gaRuntime.Attestation{
		ID:            "admission:terraform:001",
		Issuer:        policyIssuer,
		BindingDigest: binding,
	}
	return req
}

func (a *adapter) CurrentState(ctx context.Context, target string) (gaRuntime.State, error) {
	if target != targetID {
		return gaRuntime.State{}, fmt.Errorf("unexpected Terraform target %q", target)
	}
	statePath := filepath.Join(a.workDir, "terraform.tfstate")
	if _, err := os.Stat(statePath); errors.Is(err, os.ErrNotExist) {
		return absentState(), nil
	} else if err != nil {
		return gaRuntime.State{}, err
	}

	cmd := exec.CommandContext(ctx, "terraform", "output", "-raw", "governed_value")
	cmd.Dir = a.workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return gaRuntime.State{}, fmt.Errorf("terraform output: %w: %s", err, strings.TrimSpace(string(out)))
	}
	value := strings.TrimSpace(string(out))
	if value == "" {
		return gaRuntime.State{}, errors.New("terraform output governed_value is empty")
	}
	return presentState(value), nil
}

func (a *adapter) VerifyAttestation(_ context.Context, att gaRuntime.Attestation, expected string) error {
	if att.BindingDigest != expected {
		return errors.New("attestation binding digest mismatch")
	}
	switch att.Issuer.ID {
	case policyIssuer.ID, observerIssuer.ID, recoveryIssuer.ID:
		return nil
	default:
		return fmt.Errorf("untrusted attestation issuer %q", att.Issuer.ID)
	}
}

func (a *adapter) RetainCustody(_ context.Context, custody gaRuntime.Custody) error {
	if err := os.MkdirAll(filepath.Dir(a.custodyPath), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(custodyFile{SchemaVersion: custodyVersion, Custody: custody}, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.custodyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return errors.New("custody already retained for effect attempt")
	}
	if err != nil {
		return err
	}
	if _, err := f.Write(append(payload, '\n')); err != nil {
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
	d, err := os.Open(filepath.Dir(a.custodyPath))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func (a *adapter) Execute(ctx context.Context, transition gaRuntime.Transition, _ gaRuntime.Custody) (gaRuntime.Acceptance, error) {
	a.executeCalls++
	if transition.Operation != operationID || !transition.To.Equal(presentState(a.proofValue)) {
		return gaRuntime.Acceptance{}, errors.New("unexpected Terraform transition")
	}
	cmd := exec.CommandContext(
		ctx,
		"terraform", "apply",
		"-auto-approve",
		"-input=false",
		"-no-color",
		"-var", "proof_value="+a.proofValue,
		"-var", "effect_log="+a.effectLogPath,
	)
	cmd.Dir = a.workDir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return gaRuntime.Acceptance{}, fmt.Errorf("terraform apply: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if a.crashAfterApply {
		os.Exit(93)
	}
	return gaRuntime.Acceptance{Reference: "terraform:apply:completed"}, nil
}

func (a *adapter) Observe(ctx context.Context, _ gaRuntime.Transition, custody gaRuntime.Custody) (gaRuntime.Observation, error) {
	state, err := a.CurrentState(ctx, custody.Target)
	if err != nil {
		return gaRuntime.Observation{}, err
	}
	return gaRuntime.Observation{
		State: state,
		Attestation: gaRuntime.Attestation{
			ID:            "observation:terraform:001",
			Issuer:        observerIssuer,
			BindingDigest: gaRuntime.ObservationBindingDigest(custody.EffectID, state),
		},
	}, nil
}

func (a *adapter) LoadCustody(_ context.Context, effectID, attemptID string) (gaRuntime.Custody, error) {
	data, err := os.ReadFile(a.custodyPath)
	if err != nil {
		return gaRuntime.Custody{}, err
	}
	var wrapper custodyFile
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return gaRuntime.Custody{}, err
	}
	if wrapper.SchemaVersion != custodyVersion {
		return gaRuntime.Custody{}, fmt.Errorf("unsupported custody version %q", wrapper.SchemaVersion)
	}
	if wrapper.Custody.EffectID != effectID || wrapper.Custody.AttemptID != attemptID {
		return gaRuntime.Custody{}, errors.New("custody identity mismatch")
	}
	return wrapper.Custody, nil
}

func absentState() gaRuntime.State {
	return gaRuntime.State{
		Target:   targetID,
		Revision: "tfstate:absent",
		Digest:   stateDigest("absent"),
	}
}

func presentState(value string) gaRuntime.State {
	return gaRuntime.State{
		Target:   targetID,
		Revision: "tfstate:present:" + value,
		Digest:   stateDigest("present:" + value),
	}
}

func stateDigest(value string) string {
	sum := sha256.Sum256([]byte("terraform-proof-state-v1\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func countNonEmptyLines(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	count := 0
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count, nil
}

func writeJSONAtomic(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".terraform-proof-*")
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
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

func requirePath(name, value string) {
	if strings.TrimSpace(value) == "" {
		fatalf("%s is required", name)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
