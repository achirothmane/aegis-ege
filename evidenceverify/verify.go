package evidenceverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"
	"unicode/utf8"
)

const MaxInputBytes = 8 << 20

// Decode rejects duplicate keys, unknown fields, excess nesting and extra JSON
// values. Different parsers must not be able to assign different claims.
func Decode(data []byte, out any) error {
	if len(data) > MaxInputBytes {
		return fmt.Errorf("input exceeds %d bytes", MaxInputBytes)
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON is not valid UTF-8")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanValue(d, 0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func scanValue(d *json.Decoder, depth int) error {
	if depth > 128 {
		return fmt.Errorf("JSON nesting exceeds 128 levels")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, compound := t.(json.Delim)
	if !compound {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := k.(string)
			if !ok || seen[key] {
				return fmt.Errorf("duplicate or invalid JSON key %q", k)
			}
			seen[key] = true
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}

// Seal signs compact JSON value bytes with role and schema separation. Only
// transport whitespace outside strings is removed; values, escapes and key
// ordering remain signed. Public keys
// deliberately remain outside the bundle.
func Seal(role, keyID string, privateKey ed25519.PrivateKey, value any) (Envelope, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("invalid signing key")
	}
	payload, err := json.Marshal(value)
	if err != nil {
		return Envelope{}, err
	}
	sig := ed25519.Sign(privateKey, signingBytes(role, payload))
	return Envelope{keyID, payload, base64.StdEncoding.EncodeToString(sig)}, nil
}

func signingBytes(role string, payload []byte) []byte {
	return append([]byte(Schema+"\x00"+role+"\x00"), compactPayload(payload)...)
}

// Embedding RawMessage in an indented outer JSON document adds whitespace.
// Normalize that transport formatting for both signatures and history links.
// Decode rejects ambiguous keys before a statement reaches signature checking.
func compactPayload(payload []byte) []byte {
	var compact bytes.Buffer
	if err := json.Compact(&compact, payload); err != nil {
		return nil
	}
	return compact.Bytes()
}

func RelationDigest(parts ...string) string {
	h := sha256.New()
	var size [8]byte
	for _, p := range parts {
		binary.BigEndian.PutUint64(size[:], uint64(len(p)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(p))
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func ContentDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func BundleHistoryBinding(b Bundle) string {
	dest := ""
	if b.Destination != nil {
		dest = string(compactPayload(b.Destination.Payload))
	}
	parts := []string{"composite-history-v1", string(compactPayload(b.Admission.Payload)), string(compactPayload(b.Execution.Payload)), dest}
	if s := b.Succession; s != nil {
		// The immutable predecessor/authorization is bound before the final
		// outcome is appended. A final-head observation cannot bind itself.
		parts = append(parts, "succession-v1", ContentDigest(s.OldGenesis.Payload), ContentDigest(s.NewGenesis.Payload), string(compactPayload(s.AuthorityRotation)), string(compactPayload(s.BeforeAnchor)))
	}
	return RelationDigest(parts...)
}

type assessment struct {
	p Policy
	r Report
}

func (a *assessment) fail(message string)      { a.r.Errors = append(a.r.Errors, message) }
func (a *assessment) uncertain(message string) { a.r.Uncertainty = append(a.r.Uncertainty, message) }

func (a *assessment) key(role, keyID string) (ed25519.PublicKey, bool) {
	expected := a.p.RoleKeys[role]
	key, err := base64.StdEncoding.DecodeString(a.p.PublicKeys[expected])
	if expected == "" || keyID != expected || err != nil || len(key) != ed25519.PublicKeySize {
		a.r.TrustRoots = "INVALID"
		if a.r.Signatures != "INVALID" {
			a.r.Signatures = "NOT_CHECKED"
		}
		a.fail(role + ": key is not trusted by the independent policy")
		return nil, false
	}
	return ed25519.PublicKey(key), true
}

func (a *assessment) statement(role string, env Envelope, value any) bool {
	if err := Decode(env.Payload, value); err != nil {
		a.r.Structure = "INVALID"
		a.fail(role + ": " + err.Error())
		return false
	}
	key, ok := a.key(role, env.KeyID)
	if !ok {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize || !ed25519.Verify(key, signingBytes(role, env.Payload), sig) {
		a.r.Signatures = "INVALID"
		a.fail(role + ": invalid signature")
		return false
	}
	return true
}

var buildPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var gradeRank = map[string]int{"unit": 1, "simulation": 2, "native": 3}

// Verify separates operational closure from historical trust and causality.
// Supporting an UNKNOWN claim grants no permission to retry.
func Verify(bundleJSON, policyJSON []byte) Report {
	a := assessment{r: Report{Schema: Schema, Structure: "VALID", Signatures: "NOT_CHECKED", TrustRoots: "NOT_CHECKED", AuthorityAtCommit: "UNPROVEN", EffectEvidence: "NONE", Causality: "UNPROVEN", Closure: "UNKNOWN", HistoricalTrust: "UNTRUSTED_HISTORY", SuccessionValidity: "NOT_PROVIDED", CustodianAuthority: "UNPROVEN", Uncertainty: []string{}, Errors: []string{}}}
	var b Bundle
	if err := Decode(bundleJSON, &b); err != nil {
		a.r.Structure = "INVALID"
		a.fail("bundle: " + err.Error())
		return a.r
	}
	if err := Decode(policyJSON, &a.p); err != nil {
		a.r.Structure = "INVALID"
		a.fail("independent policy: " + err.Error())
		return a.r
	}
	if b.Schema != Schema || a.p.Schema != Schema || !buildPattern.MatchString(a.p.BuildSHA) || a.p.CaseID == "" || a.p.DestinationProfile != "postgresql/native-fence/v1" || a.p.AdmissionPolicyHash == "" || gradeRank[a.p.MaximumGrade] == 0 {
		a.r.Structure = "INVALID"
		a.fail("unsupported or incomplete schema/policy")
		return a.r
	}
	a.r.Signatures, a.r.TrustRoots = "VALID", "VALID"
	var e Execution
	if !a.statement("execution", b.Execution, &e) {
		return a.r
	}
	a.r.IntentID, a.r.EffectID, a.r.AttemptID, a.r.ClaimType, a.r.Grade = e.IntentID, e.EffectID, e.Request.AttemptID, e.ClaimType, e.Grade
	if e.BuildSHA != a.p.BuildSHA || e.CaseID != a.p.CaseID {
		a.fail("execution does not match the independently expected build/case")
	}
	if gradeRank[e.Grade] == 0 || gradeRank[e.Grade] > gradeRank[a.p.MaximumGrade] {
		a.fail("evidence grade exceeds supported profile or independent policy; hardware and independent reproduction need different evidence")
	}
	q := e.Request
	if q.Subject.ID == "" || q.Subject.Kind == "" || q.Executor.ID == "" || q.Executor.Kind == "" || !q.Before.complete() || !q.After.complete() || q.Before.Target != q.After.Target || q.Operation == "" || q.AttemptID == "" || e.IntentID == "" || e.AuthorityEpoch == 0 || e.AuthorityGeneration == 0 || e.CustodyGeneration == 0 {
		a.fail("execution lacks exact request or authority/custody identity")
	}
	parts := []string{q.Subject.ID, q.Subject.Kind, q.Before.Target, q.Before.Revision, q.Before.Digest, q.Operation, q.After.Revision, q.After.Digest}
	if e.EffectID != RelationDigest(append([]string{"effect-v0"}, parts...)...) || q.AdmissionBinding != RelationDigest(append([]string{"admission-v0"}, parts...)...) {
		a.fail("effect or admission identity is not bound to the exact request")
	}
	if e.ClaimType != "EXACT_EFFECT" && e.ClaimType != "POSTCONDITION" {
		a.fail("unsupported claim type")
	}
	var admission Admission
	if a.statement("admission", b.Admission, &admission) {
		contextValid := admission.BuildSHA == a.p.BuildSHA && admission.CaseID == a.p.CaseID && admission.PolicyHash == a.p.AdmissionPolicyHash
		if !contextValid {
			a.fail("admission does not match the independent build/case/policy")
		}
		a.r.Admitted = contextValid && e.Admitted && admission.AuthorityActive && admission.RequestBinding == q.AdmissionBinding && admission.ObservedBefore == q.Before && admission.AllowedOperation == q.Operation && admission.AuthorityEpoch == e.AuthorityEpoch && admission.AuthorityGeneration == e.AuthorityGeneration
		if e.Admitted && !a.r.Admitted {
			a.fail("claimed admission lacks exact active authority and evidence")
		}
	}
	if b.Destination == nil {
		a.uncertain("No destination evidence; a timeout is not proof of failure or permission to retry")
		if e.Grade == "native" {
			a.fail("native grade requires a trusted native destination statement")
		}
	} else {
		var d Destination
		if a.statement("destination", *b.Destination, &d) {
			a.destination(e, d)
		}
	}
	if b.Succession != nil || a.p.Succession != nil {
		a.succession(b, e)
	} else if e.EvidenceGrades != nil {
		a.fail("component grades require the succession profile")
	}
	if b.History == nil {
		a.uncertain("No external history checkpoint and chain")
	} else {
		a.history(b, e)
	}
	if a.r.SuccessionValidity == "VALID" && a.r.HistoricalTrust != "TRUSTED_HISTORY" {
		a.r.CustodianAuthority = "UNPROVEN"
		a.r.CurrentCustodian = nil
		a.fail("right to continue this history requires verified predecessor continuity")
	}
	if e.ClaimedClosure != a.r.Closure {
		a.fail("closure claim exceeds derived evidence")
	}
	if e.ClaimedCausality != a.r.Causality {
		a.fail("causality claim exceeds derived evidence")
	}
	if e.ClaimedHistory != a.r.HistoricalTrust {
		a.fail("history claim exceeds independently anchored evidence")
	}
	if a.r.Closure == "UNKNOWN" {
		a.uncertain("UNKNOWN does not authorize dispatch, retry or takeover")
	}
	a.r.ClaimsSupported = len(a.r.Errors) == 0
	return a.r
}

func (a *assessment) destination(e Execution, d Destination) {
	if d.BuildSHA != a.p.BuildSHA || d.CaseID != a.p.CaseID || d.Profile != a.p.DestinationProfile {
		a.fail("destination statement does not match independent profile/build/case")
		return
	}
	a.r.AuthorityCurrentlyActive = &d.AuthorityCurrentlyActive
	a.r.ExternallyCommittedEffects = &d.EffectCount
	if d.EffectCount > 1 {
		a.fail("multiple committed effects contradict the one-effect claim")
	}
	if d.CurrentAuthorityGeneration < e.AuthorityGeneration {
		a.fail("current authority generation regressed")
	}
	if d.ObservationError != "" {
		if d.Observed != (State{}) || d.Commit != nil {
			a.fail("unavailable observation also claims exact state/commit")
			return
		}
		a.r.EffectEvidence = "NATIVE_TALLY_ONLY"
		a.uncertain(d.ObservationError)
		return
	}
	if !d.Observed.complete() {
		a.r.Structure = "INVALID"
		a.fail("destination observation is incomplete")
		return
	}
	if d.Observed == e.Request.After {
		a.r.EffectEvidence, a.r.Causality = "POSTCONDITION_ONLY", "STATE_ONLY"
		if e.ClaimType == "POSTCONDITION" {
			a.r.Closure = "CLOSED"
		}
	}
	if d.Commit == nil {
		a.uncertain("Matching state does not establish causality for this attempt")
		return
	}
	c := d.Commit
	q := e.Request
	_, timeErr := time.Parse(time.RFC3339Nano, c.CommittedAt)
	if timeErr != nil || d.EffectCount != 1 || c.EffectID != e.EffectID || c.AttemptID != q.AttemptID || c.Owner != q.Executor || c.CustodyGeneration != e.CustodyGeneration || c.AdmissionBinding != q.AdmissionBinding || c.Operation != q.Operation || c.Before != q.Before || c.After != q.After {
		a.fail("commit evidence does not identify this exact effect/attempt/custody/transition")
		return
	}
	a.r.EffectEvidence = "EXACT_ATTESTED_COMMIT"
	if !c.AuthorityActive || c.AuthorityEpoch != e.AuthorityEpoch || c.AuthorityGeneration != e.AuthorityGeneration || !a.r.Admitted {
		a.r.AuthorityAtCommit = "INVALID_AT_COMMIT"
		a.fail("exact commit lacks the admitted continuing authority")
		return
	}
	a.r.AuthorityAtCommit, a.r.Causality = "VALID_AT_COMMIT", "EXACT_COMMIT_RECORD"
	if d.Observed == q.After {
		a.r.Closure = "CLOSED"
	} else {
		a.uncertain("Exact commit exists but the required postcondition is no longer observed")
	}
}
