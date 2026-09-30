package originadmissionexperiment

import (
	"crypto/ed25519"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

type originCase struct {
	ID                  string `json:"id"`
	Capability          string `json:"capability"`
	Fault               string `json:"fault"`
	ExpectedReason      string `json:"expected_reason"`
	ExpectedActivations int    `json:"expected_activations"`
	ExpectedInvocations int    `json:"expected_invocations"`
}

type originCaseSet struct {
	SchemaVersion string       `json:"schema_version"`
	Profile       string       `json:"profile"`
	FrozenOracle  string       `json:"frozen_oracle_blob"`
	Cases         []originCase `json:"cases"`
}

func experimentPath(parts ...string) string {
	_, source, _, _ := runtime.Caller(0)
	return filepath.Join(append([]string{filepath.Dir(source), "..", ".."}, parts...)...)
}

func loadOriginCases(t *testing.T) originCaseSet {
	t.Helper()
	payload, err := os.ReadFile(experimentPath("testdata", "governed-action", "origin-admission", "v0.1", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var cases originCaseSet
	if err := json.Unmarshal(payload, &cases); err != nil {
		t.Fatal(err)
	}
	return cases
}

func newOriginFixture(scope string) (*fixtureBoundary, activationRequest, ed25519.PrivateKey) {
	seed := sha256.Sum256([]byte("origin-admission-fixture-owner; TEST ONLY"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	b := &fixtureBoundary{
		owner: "fixture-policy-owner", ownerKey: privateKey.Public().(ed25519.PublicKey),
		origin: executionOrigin{ID: "fixture-plugin", Kind: "repo", SourceRef: "fixture://repo/plugin"},
		files: []artifact{
			{Path: "manifest.json", Data: "instructions,tools,hooks,code"},
			{Path: "hooks/pre-tool.sh", Data: "fixture hook revision 1"},
			{Path: "mcp/server.json", Data: "fixture server and exact tool descriptor revision 1"},
			{Path: "skills/SKILL.md", Data: "fixture instructions revision 1"},
		},
		sourceKnown: true, policyStatus: "READY", policyHash: "fixture-policy-v1",
		epoch: 1, now: 100, target: "fixture-tool-registry", namespace: "fixture-tenant",
		actorScopes: map[string]map[string]bool{"fixture-agent": {"instructions": true, "tools": true, "hooks": true, "code": true}},
		registry: make(map[capabilityKey]string),
	}
	hash, err := bundleHash(b.files)
	if err != nil {
		panic(err)
	}
	req := activationRequest{
		ActionID: "fixture-activation", Profile: originProfile, Actor: "fixture-agent",
		Origin: b.origin, SourceHash: hash, Capability: scope, Target: b.target, Namespace: b.namespace,
	}
	grant := signGrant(grantBody{
		Issuer: b.owner, Profile: originProfile, Validator: originValidator, Actor: req.Actor,
		Origin: req.Origin, SourceHash: hash, Capability: scope, Target: b.target, Namespace: b.namespace,
		PolicyHash: b.policyHash, RevocationEpoch: b.epoch, NotBefore: 90, ExpiresAt: 110,
	}, privateKey)
	req.Grant = &grant
	return b, req, privateKey
}

func applyOriginFault(t *testing.T, fault string, b *fixtureBoundary, req *activationRequest, ownerKey ed25519.PrivateKey) bool {
	t.Helper()
	// A true result delays the fault until after successful activation.
	switch fault {
	case "none", "optional_cost_missing":
	case "missing_grant":
		req.Grant = nil
	case "forged_signer":
		seed := sha256.Sum256([]byte("untrusted repository signer; TEST ONLY"))
		forged := signGrant(req.Grant.Body, ed25519.NewKeyFromSeed(seed[:]))
		req.Grant = &forged
	case "tampered_grant":
		req.Grant.Body.SourceHash = "caller-modified-after-signature"
	case "wrong_actor":
		req.Actor = "other-agent"
	case "wrong_origin":
		req.Origin.ID = "different-plugin"
	case "source_changed_after_admission":
		if !b.admit(*req).Allowed {
			t.Fatal("positive preflight must succeed before source-change fault")
		}
		b.files[1].Data = "different executable content"
	case "dependency_changed_after_admission":
		if !b.admit(*req).Allowed {
			t.Fatal("positive preflight must succeed before dependency-change fault")
		}
		b.files[2].Data = "different MCP tool descriptor"
	case "revoked_after_admission":
		if !b.admit(*req).Allowed {
			t.Fatal("positive preflight must succeed before revocation fault")
		}
		b.revoke(*req)
	case "revoked_after_activation", "policy_changed_after_activation", "actor_scope_removed_after_activation", "source_changed_after_activation":
		return true
	case "unknown_validator":
		body := req.Grant.Body
		body.Validator = "unknown-validator/v99"
		signed := signGrant(body, ownerKey)
		req.Grant = &signed
	case "wrong_namespace":
		req.Namespace = "another-tenant"
	case "expired_at_boundary":
		b.now = req.Grant.Body.ExpiresAt
	case "not_yet_valid":
		b.now = req.Grant.Body.NotBefore - 1
	case "unknown_source":
		b.sourceKnown = false
	case "mandatory_failure_low_consequence", "mandatory_failure_high_consequence":
		// Consequence labels cannot downgrade this mandatory predicate.
		b.policyStatus = "FAILED"
	case "unknown_policy":
		b.policyStatus = "UNKNOWN"
	case "actor_scope_missing":
		delete(b.actorScopes[req.Actor], req.Capability)
	case "authority_expansion":
		req.Capability = "expand_authority"
	case "unknown_profile":
		req.Profile = "requester-selected-weaker-profile"
	default:
		t.Fatalf("unknown fault schedule %q", fault)
	}
	return false
}

func TestOriginProfileCasesAtActivationAndUseBoundaries(t *testing.T) {
	cases := loadOriginCases(t)
	seen := make(map[string]bool)
	for _, tc := range cases.Cases {
		if seen[tc.ID] || tc.ID == "" {
			t.Fatalf("duplicate or missing experiment case ID: %q", tc.ID)
		}
		seen[tc.ID] = true
		t.Run(tc.ID, func(t *testing.T) {
			b, req, ownerKey := newOriginFixture(tc.Capability)
			delayed := applyOriginFault(t, tc.Fault, b, &req, ownerKey)
			result := b.activate(req)
			if result.Allowed {
				if delayed {
					switch tc.Fault {
					case "revoked_after_activation":
						b.revoke(req)
					case "policy_changed_after_activation":
						b.policyHash = "fixture-policy-v2"
					case "actor_scope_removed_after_activation":
						delete(b.actorScopes[req.Actor], req.Capability)
					case "source_changed_after_activation":
						b.files[1].Data = "different executable content"
					}
				}
				result = b.invoke(req)
			}
			if result.Reason != tc.ExpectedReason || b.activations != tc.ExpectedActivations || b.invocations != tc.ExpectedInvocations {
				t.Fatalf("reason=%s activation=%d invocation=%d; expected %s/%d/%d", result.Reason, b.activations, b.invocations, tc.ExpectedReason, tc.ExpectedActivations, tc.ExpectedInvocations)
			}
			if result.Allowed != (tc.ExpectedInvocations == 1) {
				t.Fatalf("allowed=%v disagrees with expected effect at use boundary", result.Allowed)
			}
			if result.Allowed && (result.Witness.ActionRevision == "" || result.Witness.GrantHash == "" || result.Witness.SourceHash != req.SourceHash) {
				t.Fatalf("missing exact profile-specific DecisionBasis witness: %+v", result.Witness)
			}
			if tc.Fault == "optional_cost_missing" && b.optionalCostMicros != nil {
				t.Fatal("unreported optional cost must remain unknown, not zero")
			}
		})
	}
	if len(seen) != 27 {
		t.Fatalf("expected all 27 bounded origin cases, got %d", len(seen))
	}
}

func TestDiscoveryAndAdmissionDoNotActivateCapabilities(t *testing.T) {
	b, req, _ := newOriginFixture("hooks")
	// Discovery has only host-read source metadata. No grant means no admission.
	discovered := b.origin
	req.Grant = nil
	if discovered.ID == "" || b.admit(req).Allowed || len(b.registry) != 0 || b.activations != 0 || b.invocations != 0 {
		t.Fatal("discovery silently admitted or activated a capability")
	}
	b, req, _ = newOriginFixture("hooks")
	if !b.admit(req).Allowed || len(b.registry) != 0 || b.activations != 0 || b.invocations != 0 {
		t.Fatal("valid admission must remain distinct from activation")
	}
	if result := b.invoke(req); result.Allowed || result.Reason != "CAPABILITY_NOT_ACTIVATED" || b.invocations != 0 {
		t.Fatal("admission alone authorized invocation")
	}
}

func TestRewindAppendsHistoryWithoutRestoringAuthority(t *testing.T) {
	b, req, _ := newOriginFixture("tools")
	if !b.activate(req).Allowed || !b.invoke(req).Allowed {
		t.Fatal("positive useful effect required before rewind experiment")
	}
	snapshot := make(map[capabilityKey]string)
	for key, value := range b.registry {
		snapshot[key] = value
	}
	target := uint64(len(b.history))
	b.revoke(req)
	before := append([]auditEvent(nil), b.history...)
	epoch := b.epoch
	b.rewindRegistry(req, snapshot, target)
	if !reflect.DeepEqual(before, b.history[:len(before)]) || b.epoch != epoch || b.invocations != 1 {
		t.Fatal("rewind changed historical facts, authority epoch, or effect accounting")
	}
	marker := b.history[len(before)]
	if marker.Kind != "REWIND" || marker.RewindTarget != target || marker.Parent != uint64(len(before)) {
		t.Fatalf("rewind is not a new transition referencing old state: %+v", marker)
	}
	if result := b.invoke(req); result.Allowed || result.Reason != "REVOKED_OR_SUPERSEDED_GRANT" || b.invocations != 1 {
		t.Fatal("rewind restored revoked authority or erased the earlier effect")
	}
	for i, event := range b.history {
		if event.Sequence != uint64(i+1) || event.Parent != uint64(i) {
			t.Fatalf("broken append-only fixture lineage at event %d: %+v", i, event)
		}
	}
}

func TestFreshOwnerGrantCanAuthorizeChangedSource(t *testing.T) {
	b, req, ownerKey := newOriginFixture("code")
	b.files[1].Data = "owner-reviewed executable revision 2"
	b.revoke(req)
	newHash, err := bundleHash(b.files)
	if err != nil {
		t.Fatal(err)
	}
	req.SourceHash = newHash
	body := req.Grant.Body
	body.SourceHash, body.RevocationEpoch = newHash, b.epoch
	fresh := signGrant(body, ownerKey)
	req.Grant = &fresh
	if !b.activate(req).Allowed || !b.invoke(req).Allowed || b.invocations != 1 {
		t.Fatal("deny-all or stale-only implementation rejected useful fresh authorization")
	}
}

func TestOriginTypeDoesNotMintAuthority(t *testing.T) {
	for _, kind := range []string{"repo", "plugin", "MCP", "policy_bundle", "user", "system"} {
		t.Run(kind, func(t *testing.T) {
			b, req, _ := newOriginFixture("hooks")
			b.origin.Kind = kind
			req.Origin, req.Grant = b.origin, nil
			if result := b.activate(req); result.Allowed || result.Reason != "MISSING_GRANT" || b.activations != 0 {
				t.Fatalf("origin type %q silently minted authority: %+v", kind, result)
			}
		})
	}
}

func TestRegistryIdentityDoesNotCollapseDelimitedNames(t *testing.T) {
	left := activationRequest{Actor: "agent/team", Origin: executionOrigin{ID: "plugin"}, Capability: "tools"}
	right := activationRequest{Actor: "agent", Origin: executionOrigin{ID: "team/plugin"}, Capability: "tools"}
	if registryKey(left) == registryKey(right) {
		t.Fatal("distinct actor/origin identities collapsed at the registry boundary")
	}
}

func TestBundleHashBindsCanonicalDependencySnapshot(t *testing.T) {
	one := []artifact{{Path: "hook.sh", Data: "ab"}, {Path: "config.json", Data: "c"}}
	two := []artifact{one[1], one[0]}
	oneHash, err := bundleHash(one)
	if err != nil {
		t.Fatal(err)
	}
	twoHash, err := bundleHash(two)
	if err != nil || oneHash != twoHash {
		t.Fatal("artifact enumeration order changed source identity")
	}
	two[0].Data = "changed dependency"
	changed, _ := bundleHash(two)
	if changed == oneHash {
		t.Fatal("dependency content was omitted from source identity")
	}
	for _, files := range [][]artifact{nil, {{Path: "../escape", Data: "x"}}, {{Path: "hook.sh", Data: "x"}, {Path: "hook.sh", Data: "y"}}} {
		if _, err := bundleHash(files); err == nil {
			t.Fatalf("accepted ambiguous or absent source snapshot: %+v", files)
		}
	}
}

func TestExperimentPinsFrozenOracleAndDeclaresSpecialization(t *testing.T) {
	cases := loadOriginCases(t)
	if cases.SchemaVersion != "origin-admission.experiment-cases/v0.1" || cases.Profile != originProfile {
		t.Fatal("unknown experiment identity")
	}
	oracle, err := os.ReadFile(experimentPath("testdata", "governed-action", "v1", "normative-cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	hash := sha1.New()
	_, _ = fmt.Fprintf(hash, "blob %d%c", len(oracle), byte(0))
	_, _ = hash.Write(oracle)
	if hex.EncodeToString(hash.Sum(nil)) != cases.FrozenOracle || cases.FrozenOracle != "37e2e0a0867fa78df37f9d4243a1c4107d62094b" {
		t.Fatal("experiment changed or stopped pinning frozen v1 oracle")
	}
	payload, err := os.ReadFile(experimentPath("testdata", "governed-action", "origin-admission", "v0.1", "change-record.json"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		ChangesValidTraceAcceptance bool     `json:"changes_valid_trace_acceptance"`
		ChangesCoreRelation         bool     `json:"changes_core_relation"`
		Classification              string   `json:"adjudicated_classification"`
		AffectedProfileIDs          []string `json:"affected_profile_ids"`
	}
	if err := json.Unmarshal(payload, &record); err != nil {
		t.Fatal(err)
	}
	if record.ChangesValidTraceAcceptance || record.ChangesCoreRelation || record.Classification != "POLICY_PROFILE_SPECIALIZATION_EXPERIMENT" || !reflect.DeepEqual(record.AffectedProfileIDs, []string{originProfile}) {
		t.Fatalf("experiment silently reclassified frozen semantics: %+v", record)
	}
}
