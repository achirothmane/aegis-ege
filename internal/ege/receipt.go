package ege

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	ExecutionReceiptKind = "ExecutionReceipt"
	ReceiptEvidenceKind   = "Evidence"
)

type Integrity struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type ReceiptTarget struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type ReceiptResourceChange struct {
	Resource  string `json:"resource"`
	Operation string `json:"operation"`
	Result    string `json:"result"`
	Error     string `json:"error,omitempty"`
}

type ExecutionReceipt struct {
	ContractVersion      string                  `json:"contract_version"`
	Kind                 string                  `json:"kind"`
	ID                   string                  `json:"id"`
	TraceID              string                  `json:"trace_id"`
	Producer             string                  `json:"producer"`
	CreatedAt            time.Time               `json:"created_at"`
	RequestRef           string                  `json:"request_ref"`
	DecisionRef          string                  `json:"decision_ref"`
	ActionDigest         string                  `json:"action_digest"`
	StartedAt            time.Time               `json:"started_at"`
	FinishedAt           time.Time               `json:"finished_at"`
	Outcome              string                  `json:"outcome"`
	PlanDigest           string                  `json:"plan_digest"`
	ReasonCodes          []string                `json:"reason_codes,omitempty"`
	ResourceChanges      []ReceiptResourceChange `json:"resource_changes"`
	ActualUsage          map[string]int64        `json:"actual_usage"`
	ProducedEvidenceRefs []string                `json:"produced_evidence_refs"`
	Integrity            Integrity               `json:"integrity"`
}

type ReceiptEvidenceSubject struct {
	IntentID string        `json:"intent_id"`
	Kind     string        `json:"kind"`
	Target   ReceiptTarget `json:"target"`
}

type ReceiptEvidenceClaims struct {
	Outcome               string   `json:"outcome"`
	PlanDigest            string   `json:"plan_digest"`
	ReasonCodes           []string `json:"reason_codes,omitempty"`
	ActionDigest          string   `json:"action_digest"`
	DecisionRef           string   `json:"decision_ref"`
	ResourceChangesDigest string   `json:"resource_changes_digest"`
}

type ReceiptEvidence struct {
	ContractVersion string                `json:"contract_version"`
	Kind            string                `json:"kind"`
	ID              string                `json:"id"`
	TraceID         string                `json:"trace_id"`
	Producer        string                `json:"producer"`
	CreatedAt       time.Time             `json:"created_at"`
	EvidenceType    string                `json:"evidence_type"`
	Subject         ReceiptEvidenceSubject `json:"subject"`
	SourceRef       string                `json:"source_ref"`
	ObservedAt      time.Time             `json:"observed_at"`
	Claims          ReceiptEvidenceClaims `json:"claims"`
	Integrity       Integrity             `json:"integrity"`
}

type ExecutionReceiptInput struct {
	Permit          Permit
	Decision        string
	ReasonCodes     []string
	PlanDigest      string
	StartedAt       time.Time
	FinishedAt      time.Time
	ResourceChanges []ReceiptResourceChange
}

func BuildExecutionReceiptFeedback(input ExecutionReceiptInput) (ExecutionReceipt, ReceiptEvidence, error) {
	if input.Permit.Claims.IntentID == "" {
		return ExecutionReceipt{}, ReceiptEvidence{}, errors.New("receipt intent id is required")
	}
	if input.Permit.Claims.Kind == "" || input.Permit.Claims.Target.Type == "" || input.Permit.Claims.Target.Name == "" {
		return ExecutionReceipt{}, ReceiptEvidence{}, errors.New("receipt action target is required")
	}
	if input.StartedAt.IsZero() || input.FinishedAt.IsZero() {
		return ExecutionReceipt{}, ReceiptEvidence{}, errors.New("receipt start/finish times are required")
	}
	startedAt := input.StartedAt.UTC()
	finishedAt := input.FinishedAt.UTC()
	if finishedAt.Before(startedAt) {
		return ExecutionReceipt{}, ReceiptEvidence{}, errors.New("receipt finished_at precedes started_at")
	}

	permitRef, err := permitReference(input.Permit)
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}
	actionDigest, err := executionActionDigest(input.Permit.Claims)
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}
	traceID, err := stableID("tr", map[string]any{
		"profile":   "aegis-ege/kubernetes-drain",
		"intent_id": input.Permit.Claims.IntentID,
		"kind":      input.Permit.Claims.Kind,
		"target":    input.Permit.Claims.Target,
	})
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}

	outcome := executionOutcome(input.Decision)
	receiptID, err := stableID("receipt", map[string]any{
		"trace_id":      traceID,
		"permit_ref":    permitRef,
		"action_digest": actionDigest,
		"finished_at":   finishedAt,
		"outcome":       outcome,
	})
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}

	receipt := ExecutionReceipt{
		ContractVersion: EBAContractVersion,
		Kind:            ExecutionReceiptKind,
		ID:              receiptID,
		TraceID:         traceID,
		Producer:        "aegis-ege/kubernetes-drain",
		CreatedAt:       finishedAt,
		RequestRef:      "intent:" + input.Permit.Claims.IntentID,
		DecisionRef:     permitRef,
		ActionDigest:    actionDigest,
		StartedAt:       startedAt,
		FinishedAt:      finishedAt,
		Outcome:         outcome,
		PlanDigest:      input.PlanDigest,
		ReasonCodes:     append([]string(nil), input.ReasonCodes...),
		ResourceChanges: append([]ReceiptResourceChange(nil), input.ResourceChanges...),
		ActualUsage:     map[string]int64{},
	}

	changesDigest, err := digestJSON(receipt.ResourceChanges)
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}
	evidenceID, err := stableID("ev", map[string]any{
		"source_ref": receipt.ID,
		"observed_at": finishedAt,
		"outcome": outcome,
		"action_digest": actionDigest,
		"resource_changes_digest": changesDigest,
	})
	if err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}
	evidence := ReceiptEvidence{
		ContractVersion: EBAContractVersion,
		Kind:            ReceiptEvidenceKind,
		ID:              evidenceID,
		TraceID:         traceID,
		Producer:        "aegis-ege/execution-receipt",
		CreatedAt:       finishedAt,
		EvidenceType:    "execution_receipt",
		Subject: ReceiptEvidenceSubject{
			IntentID: input.Permit.Claims.IntentID,
			Kind:     input.Permit.Claims.Kind,
			Target: ReceiptTarget{
				Type: input.Permit.Claims.Target.Type,
				Name: input.Permit.Claims.Target.Name,
			},
		},
		SourceRef:  receipt.ID,
		ObservedAt: finishedAt,
		Claims: ReceiptEvidenceClaims{
			Outcome:               outcome,
			PlanDigest:            input.PlanDigest,
			ReasonCodes:           append([]string(nil), input.ReasonCodes...),
			ActionDigest:          actionDigest,
			DecisionRef:           permitRef,
			ResourceChangesDigest: changesDigest,
		},
	}
	if err := attachIntegrity(&evidence); err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}

	receipt.ProducedEvidenceRefs = []string{evidence.ID}
	if err := attachIntegrity(&receipt); err != nil {
		return ExecutionReceipt{}, ReceiptEvidence{}, err
	}
	return receipt, evidence, nil
}

func ValidateExecutionReceipt(receipt ExecutionReceipt) error {
	if receipt.ContractVersion != EBAContractVersion || receipt.Kind != ExecutionReceiptKind {
		return errors.New("EXECUTION_RECEIPT_CONTRACT_INVALID")
	}
	return validateTypedIntegrity(receipt.Integrity, receipt)
}

func ValidateReceiptEvidence(evidence ReceiptEvidence, receipt ExecutionReceipt) error {
	if evidence.ContractVersion != EBAContractVersion || evidence.Kind != ReceiptEvidenceKind {
		return errors.New("RECEIPT_EVIDENCE_CONTRACT_INVALID")
	}
	if evidence.SourceRef != receipt.ID || evidence.TraceID != receipt.TraceID {
		return errors.New("RECEIPT_EVIDENCE_BINDING_INVALID")
	}
	if len(receipt.ProducedEvidenceRefs) != 1 || receipt.ProducedEvidenceRefs[0] != evidence.ID {
		return errors.New("RECEIPT_EVIDENCE_REFERENCE_INVALID")
	}
	return validateTypedIntegrity(evidence.Integrity, evidence)
}

func executionOutcome(decision string) string {
	switch decision {
	case "ALLOW":
		return "SUCCEEDED"
	case "BLOCK":
		return "BLOCKED"
	case "ESCALATE":
		return "ESCALATED"
	default:
		return "UNKNOWN"
	}
}

func permitReference(permit Permit) (string, error) {
	digest, err := digestJSON(permit)
	if err != nil {
		return "", fmt.Errorf("digest execution permit: %w", err)
	}
	return "permit_" + digest[:24], nil
}

func executionActionDigest(claims PermitClaims) (string, error) {
	return digestJSON(map[string]any{
		"intent_id":        claims.IntentID,
		"kind":             claims.Kind,
		"target":           claims.Target,
		"action":           claims.Action,
		"resource_version": claims.ResourceVersion,
		"plan_digest":      claims.PlanDigest,
	})
}

func stableID(prefix string, seed any) (string, error) {
	digest, err := digestJSON(seed)
	if err != nil {
		return "", err
	}
	return prefix + "_" + digest[:24], nil
}

func digestJSON(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("marshal canonical receipt payload: %w", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func attachIntegrity(value any) error {
	switch artifact := value.(type) {
	case *ExecutionReceipt:
		copyValue := *artifact
		copyValue.Integrity = Integrity{}
		digest, err := digestJSON(copyValue)
		if err != nil {
			return err
		}
		artifact.Integrity = Integrity{Algorithm: "sha256", Digest: digest}
		return nil
	case *ReceiptEvidence:
		copyValue := *artifact
		copyValue.Integrity = Integrity{}
		digest, err := digestJSON(copyValue)
		if err != nil {
			return err
		}
		artifact.Integrity = Integrity{Algorithm: "sha256", Digest: digest}
		return nil
	default:
		return fmt.Errorf("unsupported integrity artifact %T", value)
	}
}

func validateTypedIntegrity(integrity Integrity, value any) error {
	if integrity.Algorithm != "sha256" || integrity.Digest == "" {
		return errors.New("EBA_INTEGRITY_INVALID")
	}
	switch artifact := value.(type) {
	case ExecutionReceipt:
		artifact.Integrity = Integrity{}
		digest, err := digestJSON(artifact)
		if err != nil {
			return err
		}
		if digest != integrity.Digest {
			return errors.New("EBA_INTEGRITY_INVALID")
		}
	case ReceiptEvidence:
		artifact.Integrity = Integrity{}
		digest, err := digestJSON(artifact)
		if err != nil {
			return err
		}
		if digest != integrity.Digest {
			return errors.New("EBA_INTEGRITY_INVALID")
		}
	default:
		return fmt.Errorf("unsupported integrity artifact %T", value)
	}
	return nil
}
