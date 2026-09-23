package server

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net/http"
	"net/url"
	"testing"
)

func TestMTLSAuthorizerRequiresVerifiedURISAN(t *testing.T) {
	authorizer, err := NewMTLSAuthorizer(AuthzFile{
		Principals: map[string][]Permission{
			"spiffe://state-latch.test/operator": {PermissionPrepare, PermissionExecute},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	request, _ := http.NewRequest(http.MethodPost, "https://state-latch/v1/node-drains/prepare", nil)
	_, err = authorizer.Authorize(request, PermissionPrepare)
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("expected unauthenticated without verified client certificate, got %v", err)
	}

	uri, _ := url.Parse("spiffe://state-latch.test/operator")
	request.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}},
	}
	principal, err := authorizer.Authorize(request, PermissionExecute)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != uri.String() {
		t.Fatalf("unexpected principal: %+v", principal)
	}
}

func TestMTLSAuthorizerSeparatesPrepareAndExecutePermissions(t *testing.T) {
	authorizer, err := NewMTLSAuthorizer(AuthzFile{
		Principals: map[string][]Permission{
			"spiffe://state-latch.test/planner": {PermissionPrepare},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	uri, _ := url.Parse("spiffe://state-latch.test/planner")
	request, _ := http.NewRequest(http.MethodPost, "https://state-latch/v1/node-drains/execute", nil)
	request.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{uri}}}},
	}

	if _, err := authorizer.Authorize(request, PermissionPrepare); err != nil {
		t.Fatalf("prepare should be authorized: %v", err)
	}
	if _, err := authorizer.Authorize(request, PermissionExecute); !errors.Is(err, ErrForbidden) {
		t.Fatalf("execute should be forbidden, got %v", err)
	}
}

func TestMTLSAuthorizerRejectsAmbiguousIdentity(t *testing.T) {
	authorizer, err := NewMTLSAuthorizer(AuthzFile{
		Principals: map[string][]Permission{
			"spiffe://state-latch.test/operator": {PermissionPrepare},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	a, _ := url.Parse("spiffe://state-latch.test/operator")
	b, _ := url.Parse("spiffe://state-latch.test/other")
	request, _ := http.NewRequest(http.MethodPost, "https://state-latch/v1/node-drains/prepare", nil)
	request.TLS = &tls.ConnectionState{
		VerifiedChains: [][]*x509.Certificate{{{URIs: []*url.URL{a, b}}}},
	}
	if _, err := authorizer.Authorize(request, PermissionPrepare); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ambiguous URI SANs must be rejected, got %v", err)
	}
}
