package evidencepipeline

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const redactedValue = "[REDACTED]"

func Compile(req CompileRequest) (Packet, error) {
	if err := validateCompileRequest(req); err != nil {
		return Packet{}, err
	}

	evidence, err := cloneMap(req.Event.Data)
	if err != nil {
		return Packet{}, fmt.Errorf("clone event data: %w", err)
	}

	redactedPaths := uniqueSorted(req.SensitivePaths)
	for _, path := range redactedPaths {
		if err := redactJSONPointer(evidence, path); err != nil {
			return Packet{}, fmt.Errorf("redact %q: %w", path, err)
		}
	}

	inputDigest, err := digestJSON(req.Event)
	if err != nil {
		return Packet{}, fmt.Errorf("digest runtime event: %w", err)
	}

	ctx := req.Context
	ctx.ControlRefs = uniqueSorted(ctx.ControlRefs)
	ctx.ApprovalRefs = uniqueSorted(ctx.ApprovalRefs)

	packet := Packet{
		APIVersion: PacketVersion,
		IntentID:   req.Event.IntentID,
		Provenance: Provenance{
			Source:      req.Source,
			EventID:     req.Event.EventID,
			WorkflowID:  req.Event.WorkflowID,
			RunID:       req.Event.RunID,
			InputDigest: inputDigest,
			ObservedAt:  req.Event.ObservedAt.UTC(),
			CapturedAt:  req.CapturedAt.UTC(),
		},
		Actor:    req.Event.Actor,
		Action:   req.Event.Action,
		Context:  ctx,
		Evidence: evidence,
		Redaction: RedactionSummary{
			ProfileRef:    ctx.RedactionProfileRef,
			RedactedPaths: redactedPaths,
		},
	}

	digest, err := digestPacket(packet)
	if err != nil {
		return Packet{}, err
	}
	packet.Integrity = Integrity{Algorithm: "sha256", Digest: digest}
	return packet, nil
}

func Verify(packet Packet) error {
	if packet.APIVersion != PacketVersion {
		return fmt.Errorf("unsupported evidence packet version %q", packet.APIVersion)
	}
	if packet.Integrity.Algorithm != "sha256" || packet.Integrity.Digest == "" {
		return errors.New("invalid evidence packet integrity metadata")
	}
	actual, err := digestPacket(packet)
	if err != nil {
		return err
	}
	if actual != packet.Integrity.Digest {
		return errors.New("evidence packet integrity mismatch")
	}
	return nil
}

func validateCompileRequest(req CompileRequest) error {
	switch {
	case req.Event.IntentID == "":
		return errors.New("intent_id is required")
	case req.Event.EventID == "":
		return errors.New("event_id is required")
	case req.Event.ObservedAt.IsZero():
		return errors.New("observed_at is required")
	case req.CapturedAt.IsZero():
		return errors.New("captured_at is required")
	case req.Source.Name == "":
		return errors.New("source name is required")
	case req.Source.TrustDomain == "":
		return errors.New("source trust_domain is required")
	case req.Event.Actor.PrincipalID == "":
		return errors.New("actor principal_id is required")
	case req.Event.Action.Kind == "":
		return errors.New("action kind is required")
	case req.Event.Action.Tool == "":
		return errors.New("action tool is required")
	case req.Event.Action.Operation == "":
		return errors.New("action operation is required")
	case req.Event.Action.Target == "":
		return errors.New("action target is required")
	case req.Context.AuthorityRef == "":
		return errors.New("authority_ref is required; authority must not be inferred from runtime behavior")
	case req.Context.PolicyRef == "":
		return errors.New("policy_ref is required")
	case req.Context.RedactionProfileRef == "":
		return errors.New("redaction_profile_ref is required")
	case req.Context.ConsequenceClass == "":
		return errors.New("consequence_class is required")
	case req.Event.Data == nil:
		return errors.New("event data is required")
	}
	if binding := req.Context.ExecutionBinding; binding != nil {
		switch {
		case strings.TrimSpace(binding.DestinationID) == "":
			return errors.New("execution binding destination_id is required")
		case strings.TrimSpace(binding.AccountID) == "":
			return errors.New("execution binding account_id is required")
		case strings.TrimSpace(binding.Endpoint) == "":
			return errors.New("execution binding endpoint is required")
		case strings.TrimSpace(binding.AdapterProfile) == "":
			return errors.New("execution binding adapter_profile is required")
		case strings.TrimSpace(binding.ExpectedResourceVersion) == "":
			return errors.New("execution binding expected_resource_version is required")
		}
	}
	return nil
}

func digestPacket(packet Packet) (string, error) {
	unsigned := struct {
		APIVersion string           `json:"api_version"`
		IntentID   string           `json:"intent_id"`
		Provenance Provenance       `json:"provenance"`
		Actor      Actor            `json:"actor"`
		Action     Action           `json:"action"`
		Context    BootstrapContext `json:"context"`
		Evidence   map[string]any   `json:"evidence"`
		Redaction  RedactionSummary `json:"redaction"`
	}{
		APIVersion: packet.APIVersion,
		IntentID:   packet.IntentID,
		Provenance: packet.Provenance,
		Actor:      packet.Actor,
		Action:     packet.Action,
		Context:    packet.Context,
		Evidence:   packet.Evidence,
		Redaction:  packet.Redaction,
	}
	return digestJSON(unsigned)
}

func digestJSON(value any) (string, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(body)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func cloneMap(input map[string]any) (map[string]any, error) {
	body, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func uniqueSorted(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

func redactJSONPointer(root map[string]any, pointer string) error {
	if pointer == "" || pointer[0] != '/' {
		return errors.New("sensitive path must be an RFC 6901 JSON Pointer")
	}
	segments := strings.Split(pointer[1:], "/")
	for i := range segments {
		segments[i] = strings.ReplaceAll(strings.ReplaceAll(segments[i], "~1", "/"), "~0", "~")
	}
	return redactAt(root, segments)
}

func redactAt(current any, segments []string) error {
	if len(segments) == 0 {
		return errors.New("cannot redact the document root")
	}
	segment := segments[0]
	last := len(segments) == 1

	switch node := current.(type) {
	case map[string]any:
		value, ok := node[segment]
		if !ok {
			return errors.New("sensitive path does not exist")
		}
		if last {
			node[segment] = redactedValue
			return nil
		}
		return redactAt(value, segments[1:])
	case []any:
		index, err := strconv.Atoi(segment)
		if err != nil || index < 0 || index >= len(node) {
			return errors.New("sensitive array index does not exist")
		}
		if last {
			node[index] = redactedValue
			return nil
		}
		return redactAt(node[index], segments[1:])
	default:
		return errors.New("sensitive path traverses a scalar value")
	}
}
