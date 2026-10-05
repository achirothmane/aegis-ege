package simulation

// This translator/evaluator is experiment-only. It has no database, custody,
// execution, observation, signing-key or kernel-claim responsibilities.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"sort"

	v "github.com/achirothmane/aegis-ege/evidenceverify"
	r "github.com/achirothmane/aegis-ege/governedaction/runtime"
)

type normativeCondition struct {
	Field string `json:"field"`
	Value bool   `json:"value"`
}

type normativeRule struct {
	ID         string               `json:"id"`
	Source     string               `json:"source"`
	Kind       string               `json:"kind"`
	Conditions []normativeCondition `json:"conditions,omitempty"`
	Minimum    int                  `json:"minimum,omitempty"`
	Threshold  float64              `json:"threshold,omitempty"`
}

type normativePolicy struct {
	ID     string          `json:"id"`
	Source string          `json:"source"`
	Rules  []normativeRule `json:"rules"`
}

type normativeSpecification struct {
	Schema              string            `json:"schema"`
	ConflictDisposition string            `json:"conflict_disposition"`
	Constitutions       []normativePolicy `json:"constitutions"`
}

// compileNormativePolicies is a small transparent DSL compiler. It validates
// requirement structure, not religious validity. It cannot select trust roots.
func compileNormativePolicies(raw []byte) ([]normativePolicy, error) {
	var spec normativeSpecification
	if err := v.Decode(raw, &spec); err != nil {
		return nil, err
	}
	if spec.Schema != "aegis.constitution-fragments/v1" || spec.ConflictDisposition != "REQUIRE_EXTERNAL_RESOLUTION" {
		return nil, errors.New("unsupported external policy contract")
	}
	seen := map[string]bool{}
	for _, policy := range spec.Constitutions {
		if policy.ID == "" || policy.Source == "" || seen[policy.ID] || len(policy.Rules) == 0 {
			return nil, errors.New("incomplete or duplicate policy")
		}
		seen[policy.ID] = true
		rules := map[string]bool{}
		for _, rule := range policy.Rules {
			if rule.ID == "" || rule.Source == "" || rules[rule.ID] {
				return nil, errors.New("incomplete or duplicate requirement")
			}
			rules[rule.ID] = true
			fields := map[string]bool{}
			for _, condition := range rule.Conditions {
				if condition.Field == "" || fields[condition.Field] {
					return nil, errors.New("empty or duplicate condition")
				}
				fields[condition.Field] = true
			}
			switch rule.Kind {
			case "require_facts", "forbid_all":
				if len(rule.Conditions) == 0 || rule.Minimum != 0 || rule.Threshold != 0 {
					return nil, errors.New("invalid factual requirement")
				}
			case "approvals":
				if rule.Minimum < 1 || rule.Threshold != 0 {
					return nil, errors.New("invalid approval requirement")
				}
			case "disclosure":
				if rule.Threshold <= 0 || rule.Threshold > 1 || math.IsNaN(rule.Threshold) || rule.Minimum != 0 || len(rule.Conditions) != 0 {
					return nil, errors.New("invalid declared disclosure threshold")
				}
			default:
				return nil, fmt.Errorf("unknown external requirement kind: %s", rule.Kind)
			}
		}
	}
	return spec.Constitutions, nil
}

func normativePolicies() ([]normativePolicy, error) {
	raw, err := os.ReadFile("../constitutional-substitution/policies.json")
	if err != nil {
		return nil, err
	}
	return compileNormativePolicies(raw)
}

func normativePolicyHash(policy normativePolicy) string {
	raw, _ := json.Marshal(policy)
	return v.ContentDigest(raw)
}

type normativeFacts struct {
	RecordID         string          `json:"record_id"`
	RequestBinding   string          `json:"request_binding"`
	Before           v.State         `json:"before"`
	AccountableOwner string          `json:"accountable_owner"`
	ControlRecord    string          `json:"control_record"`
	Flags            map[string]bool `json:"flags"`
	Uncertainty      float64         `json:"uncertainty"`
}

type normativeEvent struct {
	Kind           string  `json:"kind"`
	RequestBinding string  `json:"request_binding"`
	Before         v.State `json:"before"`
	FactsDigest    string  `json:"facts_digest"`
	Sequence       uint64  `json:"sequence"`
	Uncertainty    float64 `json:"uncertainty"`
	Statement      string  `json:"statement"`
}

type normativeRoot struct {
	Role      string            `json:"role"`
	Principal string            `json:"principal"`
	Key       ed25519.PublicKey `json:"key"`
}

// These public roots are supplied by the relying party separately from both
// policy and producer evidence. The translator has no root field.
type normativeEvidence struct {
	Facts  []v.Envelope `json:"facts"`
	Events []v.Envelope `json:"events"`
}

type normativeRuleResult struct {
	ID              string   `json:"id"`
	Source          string   `json:"source"`
	Kind            string   `json:"kind"`
	Outcome         string   `json:"outcome"`
	Required        int      `json:"required,omitempty"`
	ValidPrincipals []string `json:"valid_principals,omitempty"`
	Witnesses       []string `json:"witnesses,omitempty"`
}

type normativeEvaluation struct {
	PolicyID         string                `json:"policy_id"`
	PolicyHash       string                `json:"policy_hash"`
	EvidenceDigest   string                `json:"evidence_digest"`
	FactsDigest      string                `json:"facts_digest"`
	AccountableOwner string                `json:"accountable_owner"`
	ControlRecord    string                `json:"control_record"`
	Decision         string                `json:"decision"`
	Rules            []normativeRuleResult `json:"rules"`
	Errors           []string              `json:"errors"`
}

func normativeSigningBytes(role string, raw []byte) []byte {
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return nil
	}
	return append([]byte("aegis/normative-fixture/v1\x00"+role+"\x00"), compact.Bytes()...)
}

func verifyNormativeStatement(role string, envelope v.Envelope, roots map[string]normativeRoot, out any) error {
	root, ok := roots[envelope.KeyID]
	signature, err := base64.StdEncoding.DecodeString(envelope.Signature)
	if !ok || root.Role != role || err != nil || len(root.Key) != ed25519.PublicKeySize || !ed25519.Verify(root.Key, normativeSigningBytes(role, envelope.Payload), signature) {
		return errors.New("normative evidence issuer/role/signature is not independently trusted")
	}
	return v.Decode(envelope.Payload, out)
}

func evaluateNormativePolicy(policy normativePolicy, independentlyExpectedHash string, req r.Request, evidence normativeEvidence, roots map[string]normativeRoot) normativeEvaluation {
	raw, _ := json.Marshal(evidence)
	evaluation := normativeEvaluation{PolicyID: policy.ID, PolicyHash: normativePolicyHash(policy), EvidenceDigest: v.ContentDigest(raw), Decision: "ALLOW", Rules: []normativeRuleResult{}, Errors: []string{}}
	stop := func(decision, reason string) normativeEvaluation {
		evaluation.Decision = decision
		evaluation.Errors = append(evaluation.Errors, reason)
		return evaluation
	}
	if evaluation.PolicyHash != independentlyExpectedHash {
		return stop("DENY", "producer/translator policy differs from independently provisioned policy")
	}
	if len(evidence.Facts) == 0 {
		return stop("REQUIRE_EVIDENCE", "no authenticated requirement evaluation facts")
	}
	var facts normativeFacts
	for i, envelope := range evidence.Facts {
		var candidate normativeFacts
		if err := verifyNormativeStatement("facts", envelope, roots, &candidate); err != nil {
			return stop("DENY", err.Error())
		}
		binding, err := r.AdmissionBindingDigest(req)
		if err != nil || candidate.RecordID == "" || candidate.RequestBinding != binding || candidate.Before != noCustodyState(req.Current) || candidate.Uncertainty < 0 || candidate.Uncertainty > 1 || math.IsNaN(candidate.Uncertainty) {
			return stop("REQUIRE_EVIDENCE", "fact statement is not bound to the exact proposal/current state")
		}
		canonical, _ := json.Marshal(candidate)
		digest := v.ContentDigest(canonical)
		if i > 0 {
			comparison := candidate
			comparison.RecordID = facts.RecordID
			material, _ := json.Marshal(comparison)
			if v.ContentDigest(material) != evaluation.FactsDigest {
				return stop("REQUIRE_EXTERNAL_RESOLUTION", "equally trusted exact-state fact statements conflict; no source priority supplied")
			}
			continue
		}
		facts, evaluation.FactsDigest = candidate, digest
	}
	evaluation.AccountableOwner, evaluation.ControlRecord = facts.AccountableOwner, facts.ControlRecord
	if owner, present := facts.Flags["owner_recorded"]; present && owner != (facts.AccountableOwner != "") {
		return stop("REQUIRE_EVIDENCE", "accountability flag contradicts the actual owner record")
	}
	if audit, present := facts.Flags["audit_recorded"]; present && audit != (facts.ControlRecord != "") {
		return stop("REQUIRE_EVIDENCE", "audit flag contradicts the actual control record")
	}
	approvers := map[string]bool{}
	var disclosures, consents []normativeEvent
	for _, envelope := range evidence.Events {
		var event normativeEvent
		if err := v.Decode(envelope.Payload, &event); err != nil {
			return stop("DENY", err.Error())
		}
		if event.Kind != "approval" && event.Kind != "disclosure" && event.Kind != "consent" {
			return stop("DENY", "unknown evidence event kind")
		}
		if err := verifyNormativeStatement(event.Kind, envelope, roots, &event); err != nil {
			return stop("DENY", err.Error())
		}
		if event.RequestBinding != facts.RequestBinding || event.Before != facts.Before || event.FactsDigest != evaluation.FactsDigest || event.Sequence == 0 {
			return stop("REQUIRE_EVIDENCE", "valid signature does not bind this exact state and reviewed facts")
		}
		switch event.Kind {
		case "approval":
			if event.Statement != "VALIDATED" || roots[envelope.KeyID].Principal == "" {
				return stop("REQUIRE_HUMAN_APPROVAL", "signed event does not record validation")
			}
			approvers[roots[envelope.KeyID].Principal] = true
		case "disclosure":
			if event.Statement == "DISCLOSED" && event.Uncertainty == facts.Uncertainty {
				disclosures = append(disclosures, event)
			}
		case "consent":
			if event.Statement == "CONSENTED" {
				consents = append(consents, event)
			}
		}
	}
	principals := make([]string, 0, len(approvers))
	for key := range approvers {
		principals = append(principals, key)
	}
	sort.Strings(principals)
	for _, rule := range policy.Rules {
		result := normativeRuleResult{ID: rule.ID, Source: rule.Source, Kind: rule.Kind, Outcome: "SATISFIED", Witnesses: []string{facts.RecordID}}
		matches, known := true, true
		for _, condition := range rule.Conditions {
			actual, exists := facts.Flags[condition.Field]
			if !exists {
				known = false
			} else if actual != condition.Value {
				matches = false
			}
		}
		if !known {
			result.Outcome = "REQUIRE_EVIDENCE"
		} else {
			switch rule.Kind {
			case "require_facts":
				if !matches {
					result.Outcome = "DENY"
				}
			case "forbid_all":
				if matches {
					result.Outcome = "DENY"
				}
			case "approvals":
				if matches {
					result.Required, result.ValidPrincipals = rule.Minimum, principals
					result.Witnesses = append(result.Witnesses, principals...)
					if len(principals) < rule.Minimum {
						result.Outcome = "REQUIRE_HUMAN_APPROVAL"
					}
				} else {
					result.Outcome = "NOT_APPLICABLE"
				}
			case "disclosure":
				if facts.Uncertainty > rule.Threshold {
					ordered := false
					for _, disclosure := range disclosures {
						for _, consent := range consents {
							ordered = ordered || disclosure.Sequence < consent.Sequence
						}
					}
					if !ordered {
						result.Outcome = "REQUIRE_DISCLOSURE"
					}
				} else {
					result.Outcome = "NOT_APPLICABLE"
				}
			}
		}
		evaluation.Rules = append(evaluation.Rules, result)
		// Conjunction is explicit external provisioning: every requirement must
		// hold. All failed requirements stay visible; none is silently balanced.
		if result.Outcome != "SATISFIED" && result.Outcome != "NOT_APPLICABLE" {
			if result.Outcome == "DENY" || evaluation.Decision == "ALLOW" {
				evaluation.Decision = result.Outcome
			}
		}
	}
	return evaluation
}
