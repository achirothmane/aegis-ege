package prometheusprobe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/achirothmane/state-latch/internal/decision"
)

const (
	DefaultSource = "prometheus-http"
	nodeHealthClaim = "node_health"
)

type BinaryNodeHealthProbe struct {
	BaseURL string
	Client  *http.Client
	Source  string
}

func NewBinaryNodeHealthProbe(baseURL string, client *http.Client) *BinaryNodeHealthProbe {
	if client == nil {
		client = http.DefaultClient
	}
	return &BinaryNodeHealthProbe{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  client,
		Source:  DefaultSource,
	}
}

func (p *BinaryNodeHealthProbe) Name() string {
	return "prometheus-http-node-health"
}

func (p *BinaryNodeHealthProbe) SafetyClass() decision.ProbeSafetyClass {
	return decision.ProbeReadOnly
}

func (p *BinaryNodeHealthProbe) Supports(req decision.Request, result decision.Result) bool {
	if p == nil || p.BaseURL == "" || p.Client == nil {
		return false
	}
	if !strings.HasPrefix(req.Target, "node/") {
		return false
	}
	for _, reason := range result.ReasonCodes {
		if result.Decision == decision.Escalate && reason == decision.InsufficientEvidence {
			return true
		}
		if result.Decision == decision.Block && reason == decision.EvidenceContradicted {
			return true
		}
	}
	return false
}

func (p *BinaryNodeHealthProbe) Acquire(
	ctx context.Context,
	req decision.Request,
) (decision.ProbeOutcome, error) {
	nodeName := strings.TrimPrefix(req.Target, "node/")
	if nodeName == "" || nodeName == req.Target {
		return decision.ProbeOutcome{}, fmt.Errorf("target %q is not a node target", req.Target)
	}

	endpoint, err := url.Parse(p.BaseURL + "/api/v1/query")
	if err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("parse Prometheus endpoint: %w", err)
	}
	q := endpoint.Query()
	q.Set("query", "state_latch_node_health{node="+strconv.Quote(nodeName)+"}")
	endpoint.RawQuery = q.Encode()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("build Prometheus query: %w", err)
	}
	resp, err := p.Client.Do(httpReq)
	if err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("query Prometheus: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return decision.ProbeOutcome{}, fmt.Errorf(
			"Prometheus returned HTTP %d: %s",
			resp.StatusCode,
			strings.TrimSpace(string(body)),
		)
	}

	var payload apiResponse
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 1<<20))
	if err := decoder.Decode(&payload); err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("decode Prometheus response: %w", err)
	}
	if payload.Status != "success" {
		return decision.ProbeOutcome{}, fmt.Errorf("Prometheus query status %q: %s", payload.Status, payload.Error)
	}
	if payload.Data.ResultType != "vector" {
		return decision.ProbeOutcome{}, fmt.Errorf("expected Prometheus vector result, got %q", payload.Data.ResultType)
	}
	if len(payload.Data.Result) != 1 {
		return decision.ProbeOutcome{}, fmt.Errorf(
			"expected exactly one Prometheus series, got %d",
			len(payload.Data.Result),
		)
	}

	sample := payload.Data.Result[0]
	if len(sample.Value) != 2 {
		return decision.ProbeOutcome{}, fmt.Errorf("Prometheus sample must contain timestamp and value")
	}

	var timestamp float64
	if err := json.Unmarshal(sample.Value[0], &timestamp); err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("decode Prometheus sample timestamp: %w", err)
	}
	var value string
	if err := json.Unmarshal(sample.Value[1], &value); err != nil {
		return decision.ProbeOutcome{}, fmt.Errorf("decode Prometheus sample value: %w", err)
	}

	health := ""
	switch value {
	case "1":
		health = "healthy"
	case "0":
		health = "unhealthy"
	default:
		return decision.ProbeOutcome{}, fmt.Errorf("unsupported node health sample value %q", value)
	}

	observedAt := unixFloat(timestamp)
	source := p.Source
	if source == "" {
		source = DefaultSource
	}

	return decision.ProbeOutcome{
		Evidence: []decision.EvidenceObservation{{
			Claim:      nodeHealthClaim,
			Source:     source,
			Value:      health,
			ObservedAt: observedAt,
		}},
	}, nil
}

type apiResponse struct {
	Status string
	Error  string
	Data   struct {
		ResultType string
		Result     []struct {
			Value []json.RawMessage
		}
	}
}

func unixFloat(v float64) time.Time {
	seconds := int64(v)
	nanos := int64((v - float64(seconds)) * 1e9)
	return time.Unix(seconds, nanos).UTC()
}
