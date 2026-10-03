package kernelfabric

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRemoteTaintRecoveryWitnessCompletesPinnedJointAuthorization(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 9)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)

	partial, err := fixture.root.SignAuthorityRequest(auth, fixture.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	policyCalls := 0
	handler, err := NewTaintRecoveryWitnessHandler(
		fixture.root,
		fixture.witnessPrivate,
		TaintRecoveryWitnessPolicyFunc(func(_ context.Context, observed TaintRecoveryAuthorization) error {
			policyCalls++
			if observed.AuthorizationID != auth.AuthorizationID ||
				observed.PlanDigest != auth.PlanDigest ||
				observed.ExpectedDirty != auth.ExpectedDirty {
				return errors.New("unexpected recovery authorization")
			}
			return nil
		}),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	client, err := NewRemoteTaintRecoveryWitness(server.URL, fixture.root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	joint, err := client.CoSign(context.Background(), partial)
	if err != nil {
		t.Fatal(err)
	}
	if policyCalls != 1 {
		t.Fatalf("witness policy calls=%d want=1", policyCalls)
	}
	if err := fixture.root.Verify(joint, now); err != nil {
		t.Fatalf("remote joint authorization did not verify under pinned trust root: %v", err)
	}
	if joint.AuthoritySignature != partial.AuthoritySignature {
		t.Fatal("remote witness replaced authority signature")
	}
	if strings.TrimSpace(joint.WitnessSignature) == "" {
		t.Fatal("remote witness returned no witness co-signature")
	}
}

func TestRemoteTaintRecoveryWitnessRejectsUnpinnedAuthoritySignatureBeforePolicy(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 4)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)

	_, roguePrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(auth)
	if err != nil {
		t.Fatal(err)
	}
	partial := AuthoritySignedTaintRecoveryAuthorization{
		Version:            JointTaintRecoveryAuthorizationVersion,
		Authorization:      auth,
		AuthorityKeyID:     fixture.signedManifest.Manifest.AuthorityKeyID,
		AuthoritySignature: base64.StdEncoding.EncodeToString(ed25519.Sign(roguePrivate, payload)),
		WitnessKeyID:       fixture.signedManifest.Manifest.WitnessKeyID,
	}
	policyCalls := 0
	handler, err := NewTaintRecoveryWitnessHandler(
		fixture.root,
		fixture.witnessPrivate,
		TaintRecoveryWitnessPolicyFunc(func(context.Context, TaintRecoveryAuthorization) error {
			policyCalls++
			return nil
		}),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()

	client, err := NewRemoteTaintRecoveryWitness(server.URL, fixture.root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoSign(context.Background(), partial); err == nil ||
		!strings.Contains(err.Error(), "HTTP 401") {
		t.Fatalf("rogue authority signature result=%v, want HTTP 401", err)
	}
	if policyCalls != 0 {
		t.Fatalf("witness policy ran before authority verification: calls=%d", policyCalls)
	}
}

func TestRemoteTaintRecoveryWitnessPolicyCanDenyValidAuthority(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 5)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	now := auth.NotBefore.Add(30 * time.Second)
	partial, err := fixture.root.SignAuthorityRequest(auth, fixture.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}

	handler, err := NewTaintRecoveryWitnessHandler(
		fixture.root,
		fixture.witnessPrivate,
		TaintRecoveryWitnessPolicyFunc(func(context.Context, TaintRecoveryAuthorization) error {
			return errors.New("independent witness policy denied")
		}),
		func() time.Time { return now },
	)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client, err := NewRemoteTaintRecoveryWitness(server.URL, fixture.root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoSign(context.Background(), partial); err == nil ||
		!strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("policy denial result=%v, want HTTP 403", err)
	}
}

func TestRemoteTaintRecoveryWitnessRejectsReplayedResponseNonce(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 6)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	partial, err := fixture.root.SignAuthorityRequest(auth, fixture.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	joint := completeTestRecoveryAuthorization(t, partial, fixture.witnessPrivate)
	stale := signedTestRecoveryWitnessResponse(
		t,
		"stale-request-nonce",
		joint,
		fixture.signedManifest.Manifest.WitnessKeyID,
		fixture.witnessPrivate,
	)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(stale)
	}))
	defer server.Close()
	client, err := NewRemoteTaintRecoveryWitness(server.URL, fixture.root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoSign(context.Background(), partial); err == nil ||
		!strings.Contains(err.Error(), "freshness nonce mismatch") {
		t.Fatalf("replayed response result=%v, want nonce mismatch", err)
	}
}

func TestRemoteTaintRecoveryWitnessRejectsForgedResponseSignature(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 7)
	auth, _, _ := testTaintRecoveryAuthorization(t)
	partial, err := fixture.root.SignAuthorityRequest(auth, fixture.authorityPrivate)
	if err != nil {
		t.Fatal(err)
	}
	joint := completeTestRecoveryAuthorization(t, partial, fixture.witnessPrivate)
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result := signedTestRecoveryWitnessResponse(
			t,
			r.Header.Get(remoteTaintRecoveryWitnessNonceHeader),
			joint,
			fixture.signedManifest.Manifest.WitnessKeyID,
			wrongPrivate,
		)
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	client, err := NewRemoteTaintRecoveryWitness(server.URL, fixture.root, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CoSign(context.Background(), partial); err == nil ||
		!strings.Contains(err.Error(), "response signature verification failed") {
		t.Fatalf("forged response result=%v, want response signature failure", err)
	}
}

func TestRemoteTaintRecoveryWitnessConstructorsEnforceCustodyBoundary(t *testing.T) {
	fixture := newTaintRecoveryTrustFixture(t, 8)
	if _, err := NewRemoteTaintRecoveryWitness(
		"http://witness.invalid",
		fixture.root,
		&http.Client{},
	); err == nil {
		t.Fatal("HTTP recovery witness endpoint was accepted")
	}
	if _, err := NewRemoteTaintRecoveryWitness(
		"https://witness.invalid",
		nil,
		&http.Client{},
	); err == nil {
		t.Fatal("recovery witness client accepted missing trust root")
	}
	_, wrongWitnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewTaintRecoveryWitnessHandler(
		fixture.root,
		wrongWitnessPrivate,
		TaintRecoveryWitnessPolicyFunc(func(context.Context, TaintRecoveryAuthorization) error { return nil }),
		time.Now,
	); err == nil {
		t.Fatal("witness service accepted private key not pinned by trust root")
	}
	if _, err := NewTaintRecoveryWitnessHandler(
		fixture.root,
		fixture.witnessPrivate,
		nil,
		time.Now,
	); err == nil {
		t.Fatal("witness service accepted missing independent policy")
	}
}

func completeTestRecoveryAuthorization(
	t *testing.T,
	partial AuthoritySignedTaintRecoveryAuthorization,
	witnessPrivate ed25519.PrivateKey,
) JointSignedTaintRecoveryAuthorization {
	t.Helper()
	payload, err := canonicalJointTaintRecoveryAuthorizationPayload(partial.Authorization)
	if err != nil {
		t.Fatal(err)
	}
	return JointSignedTaintRecoveryAuthorization{
		Version:            partial.Version,
		Authorization:      partial.Authorization,
		AuthorityKeyID:     partial.AuthorityKeyID,
		AuthoritySignature: partial.AuthoritySignature,
		WitnessKeyID:       partial.WitnessKeyID,
		WitnessSignature:   base64.StdEncoding.EncodeToString(ed25519.Sign(witnessPrivate, payload)),
	}
}

func signedTestRecoveryWitnessResponse(
	t *testing.T,
	nonce string,
	joint JointSignedTaintRecoveryAuthorization,
	witnessKeyID string,
	responsePrivate ed25519.PrivateKey,
) remoteTaintRecoveryWitnessResponse {
	t.Helper()
	result := remoteTaintRecoveryWitnessResponse{
		Protocol:            remoteTaintRecoveryWitnessProtocolV1,
		Nonce:               nonce,
		WitnessKeyID:        witnessKeyID,
		SignedAuthorization: joint,
	}
	commitment, err := JointTaintRecoveryCommitmentDigest(joint)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := remoteTaintRecoveryWitnessResponsePayload(result, commitment)
	if err != nil {
		t.Fatal(err)
	}
	result.ResponseSignature = base64.StdEncoding.EncodeToString(ed25519.Sign(responsePrivate, payload))
	return result
}
