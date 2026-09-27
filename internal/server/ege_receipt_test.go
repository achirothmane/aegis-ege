package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/achirothmane/aegis-ege/internal/decision"
	egeproto "github.com/achirothmane/aegis-ege/internal/ege"
)

type recordingAuditSink struct {
	records []SecurityAuditRecord
}

func (s *recordingAuditSink) Record(_ context.Context, record SecurityAuditRecord) {
	s.records = append(s.records, record)
}

func executeEBARequest(
	t *testing.T,
	s *Server,
	permit egeproto.Permit,
	bundle egeExecutionEBABundle,
) egeExecuteResponse {
	t.Helper()
	payload, err := json.Marshal(egeExecuteRequest{
		IntentID: "intent-eba-1",
		Kind:     egeNodeDrainKind,
		Target:   egeTargetDTO{Type: egeNodeTarget, Name: "node-7"},
		Permit:   permit,
		EBA:      &bundle,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/ege/execute", bytes.NewReader(payload))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%s", recorder.Code, recorder.Body.String())
	}
	var response egeExecuteResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestEGEExecuteReturnsIntegrityBoundReceiptAndEvidence(t *testing.T) {
	s, controller, permit, bundle := newEBAExecuteFixture(t)
	audit := &recordingAuditSink{}
	s.config.AuditSink = audit

	response := executeEBARequest(t, s, permit, bundle)

	if controller.executeCalls != 1 {
		t.Fatalf("expected one controller execution, got %d", controller.executeCalls)
	}
	if response.FeedbackError != "" {
		t.Fatalf("unexpected feedback error: %s", response.FeedbackError)
	}
	if response.ExecutionReceipt == nil || response.ProducedEvidence == nil {
		t.Fatalf("expected receipt and produced evidence, got %+v", response)
	}
	if err := egeproto.ValidateExecutionReceipt(*response.ExecutionReceipt); err != nil {
		t.Fatalf("invalid execution receipt: %v", err)
	}
	if err := egeproto.ValidateReceiptEvidence(
		*response.ProducedEvidence,
		*response.ExecutionReceipt,
	); err != nil {
		t.Fatalf("invalid receipt evidence: %v", err)
	}
	if response.ExecutionReceipt.Outcome != "SUCCEEDED" {
		t.Fatalf("expected SUCCEEDED receipt, got %s", response.ExecutionReceipt.Outcome)
	}
	if response.ExecutionReceipt.RequestRef != "intent:intent-eba-1" {
		t.Fatalf("unexpected request ref: %s", response.ExecutionReceipt.RequestRef)
	}
	if len(response.ExecutionReceipt.ActualUsage) != 0 {
		t.Fatalf("kubernetes drain must not report token usage: %+v", response.ExecutionReceipt.ActualUsage)
	}

	var feedbackAudit *SecurityAuditRecord
	for i := range audit.records {
		if audit.records[i].ReceiptID != "" || audit.records[i].EvidenceID != "" {
			feedbackAudit = &audit.records[i]
		}
	}
	if feedbackAudit == nil {
		t.Fatal("execution audit did not contain receipt/evidence ids")
	}
	if feedbackAudit.ReceiptID != response.ExecutionReceipt.ID {
		t.Fatalf("audit receipt id mismatch: %s != %s", feedbackAudit.ReceiptID, response.ExecutionReceipt.ID)
	}
	if feedbackAudit.EvidenceID != response.ProducedEvidence.ID {
		t.Fatalf("audit evidence id mismatch: %s != %s", feedbackAudit.EvidenceID, response.ProducedEvidence.ID)
	}
}

func TestEGEExecuteEscalationReceiptDoesNotClaimSuccess(t *testing.T) {
	s, controller, permit, bundle := newEBAExecuteFixture(t)
	controller.report.Decision = decision.Escalate
	controller.report.ReasonCodes = []decision.ReasonCode{decision.ExecutionPlanChanged}

	response := executeEBARequest(t, s, permit, bundle)

	if response.ExecutionReceipt == nil {
		t.Fatal("expected receipt for execution report")
	}
	if response.ExecutionReceipt.Outcome != "ESCALATED" {
		t.Fatalf("expected ESCALATED receipt, got %s", response.ExecutionReceipt.Outcome)
	}
	if len(response.ExecutionReceipt.ReasonCodes) != 1 ||
		response.ExecutionReceipt.ReasonCodes[0] != string(decision.ExecutionPlanChanged) {
		t.Fatalf("receipt lost escalation reason: %+v", response.ExecutionReceipt.ReasonCodes)
	}
}

func TestEGEExecuteReceiptEvidenceBindsSameTrace(t *testing.T) {
	s, _, permit, bundle := newEBAExecuteFixture(t)
	response := executeEBARequest(t, s, permit, bundle)

	if response.ExecutionReceipt == nil || response.ProducedEvidence == nil {
		t.Fatal("expected feedback artifacts")
	}
	if response.ExecutionReceipt.TraceID != response.ProducedEvidence.TraceID {
		t.Fatalf(
			"trace mismatch receipt=%s evidence=%s",
			response.ExecutionReceipt.TraceID,
			response.ProducedEvidence.TraceID,
		)
	}
	if response.ProducedEvidence.SourceRef != response.ExecutionReceipt.ID {
		t.Fatalf("evidence source ref does not point to receipt")
	}
}
