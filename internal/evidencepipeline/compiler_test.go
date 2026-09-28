package evidencepipeline

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestCompileRedactsAndBindsDeclaredContext(t *testing.T) {
	req := fixtureRequest()
	packet, err := Compile(req)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	if err := Verify(packet); err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	customer := packet.Evidence["customer"].(map[string]any)
	if got := customer["email"]; got != redactedValue {
		t.Fatalf("email = %v, want redacted", got)
	}
	auth := packet.Evidence["auth"].(map[string]any)
	if got := auth["token"]; got != redactedValue {
		t.Fatalf("token = %v, want redacted", got)
	}
	if req.Event.Data["customer"].(map[string]any)["email"] == redactedValue {
		t.Fatal("Compile mutated the input event")
	}
	if packet.Context.AuthorityRef != "authority://crm/customer-update/v3" {
		t.Fatalf("authority_ref = %q", packet.Context.AuthorityRef)
	}
	if len(packet.Context.ControlRefs) != 2 || packet.Context.ControlRefs[0] != "iso27001:A.5.15" {
		t.Fatalf("control refs not canonicalized: %#v", packet.Context.ControlRefs)
	}

	body, err := json.Marshal(packet)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"alice@example.com", "secret-token"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("compiled packet leaked %q", secret)
		}
	}
}

func TestCompileRejectsImplicitAuthority(t *testing.T) {
	req := fixtureRequest()
	req.Context.AuthorityRef = ""
	_, err := Compile(req)
	if err == nil || !strings.Contains(err.Error(), "authority_ref is required") {
		t.Fatalf("Compile() error = %v, want authority failure", err)
	}
}

func TestCompileFailsClosedWhenDeclaredSensitivePathIsMissing(t *testing.T) {
	req := fixtureRequest()
	req.SensitivePaths = append(req.SensitivePaths, "/customer/ssn")
	_, err := Compile(req)
	if err == nil || !strings.Contains(err.Error(), "sensitive path does not exist") {
		t.Fatalf("Compile() error = %v, want missing sensitive path failure", err)
	}
}

func TestVerifyDetectsEvidenceTampering(t *testing.T) {
	packet, err := Compile(fixtureRequest())
	if err != nil {
		t.Fatal(err)
	}
	packet.Evidence["ticket"] = "T-999"
	if err := Verify(packet); err == nil {
		t.Fatal("Verify() accepted a tampered evidence packet")
	}
}

func TestDigestIsStableAcrossMapInsertionOrder(t *testing.T) {
	left := fixtureRequest()
	right := fixtureRequest()
	left.Event.Data = map[string]any{
		"customer": map[string]any{"id": "c-17", "email": "alice@example.com"},
		"auth":     map[string]any{"token": "secret-token"},
		"ticket":   "T-42",
	}
	right.Event.Data = map[string]any{
		"ticket": "T-42",
		"auth":   map[string]any{"token": "secret-token"},
		"customer": map[string]any{
			"email": "alice@example.com",
			"id":    "c-17",
		},
	}

	p1, err := Compile(left)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := Compile(right)
	if err != nil {
		t.Fatal(err)
	}
	if p1.Integrity.Digest != p2.Integrity.Digest {
		t.Fatalf("digests differ: %q != %q", p1.Integrity.Digest, p2.Integrity.Digest)
	}
}

func fixtureRequest() CompileRequest {
	observed := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	captured := observed.Add(2 * time.Second)
	return CompileRequest{
		Event: RuntimeEvent{
			EventID:    "evt-42",
			WorkflowID: "n8n-crm-sync",
			RunID:      "run-7",
			Actor: Actor{
				PrincipalID: "user:ops@example.test",
				AgentID:     "agent:crm-updater",
			},
			Action: Action{
				Kind:       "crm.customer_update",
				Tool:       "salesforce",
				Operation:  "update_customer",
				Target:     "customer/c-17",
				SideEffect: true,
			},
			ObservedAt: observed,
			Data: map[string]any{
				"ticket": "T-42",
				"customer": map[string]any{
					"id":    "c-17",
					"email": "alice@example.com",
				},
				"auth": map[string]any{"token": "secret-token"},
			},
		},
		Source: Source{
			Name:        "n8n.webhook.crm",
			TrustDomain: "workflow-runtime",
		},
		Context: BootstrapContext{
			AuthorityRef:        "authority://crm/customer-update/v3",
			PolicyRef:           "policy://agent-actions/v8",
			RedactionProfileRef: "redaction://crm/pii/v4",
			ConsequenceClass:    "customer-record-write",
			ControlRefs:         []string{"soc2:CC6.1", "iso27001:A.5.15", "soc2:CC6.1"},
			ApprovalRefs:        []string{"approval://ticket/T-42"},
		},
		SensitivePaths: []string{"/customer/email", "/auth/token"},
		CapturedAt:     captured,
	}
}
