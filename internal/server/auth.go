package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

type Permission string

const (
	PermissionPrepare Permission = "PREPARE"
	PermissionExecute Permission = "EXECUTE"
)

var (
	ErrUnauthenticated = errors.New("caller is not authenticated")
	ErrForbidden       = errors.New("caller is not authorized")
)

type Principal struct {
	ID string
}

type Authorizer interface {
	Authorize(*http.Request, Permission) (Principal, error)
}

type AuthzFile struct {
	Principals map[string][]Permission `json:"principals"`
}

type MTLSAuthorizer struct {
	permissions map[string]map[Permission]struct{}
}

func NewMTLSAuthorizer(config AuthzFile) (*MTLSAuthorizer, error) {
	if len(config.Principals) == 0 {
		return nil, fmt.Errorf("at least one principal is required")
	}
	out := &MTLSAuthorizer{permissions: make(map[string]map[Permission]struct{}, len(config.Principals))}
	for identity, permissions := range config.Principals {
		identity = strings.TrimSpace(identity)
		if identity == "" {
			return nil, fmt.Errorf("principal identity cannot be empty")
		}
		if len(permissions) == 0 {
			return nil, fmt.Errorf("principal %q has no permissions", identity)
		}
		set := make(map[Permission]struct{}, len(permissions))
		for _, permission := range permissions {
			switch permission {
			case PermissionPrepare, PermissionExecute:
				set[permission] = struct{}{}
			default:
				return nil, fmt.Errorf("principal %q has unsupported permission %q", identity, permission)
			}
		}
		out.permissions[identity] = set
	}
	return out, nil
}

func LoadMTLSAuthorizer(path string) (*MTLSAuthorizer, error) {
	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read authz file: %w", err)
	}
	var config AuthzFile
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode authz file: %w", err)
	}
	return NewMTLSAuthorizer(config)
}

func (a *MTLSAuthorizer) Authorize(r *http.Request, permission Permission) (Principal, error) {
	identity, err := mtlsIdentity(r)
	if err != nil {
		return Principal{}, err
	}
	permissions, ok := a.permissions[identity]
	if !ok {
		return Principal{}, fmt.Errorf("%w: principal %q", ErrForbidden, identity)
	}
	if _, ok := permissions[permission]; !ok {
		return Principal{}, fmt.Errorf("%w: principal %q lacks %s", ErrForbidden, identity, permission)
	}
	return Principal{ID: identity}, nil
}

func mtlsIdentity(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return "", ErrUnauthenticated
	}
	cert := r.TLS.VerifiedChains[0][0]
	if len(cert.URIs) != 1 {
		return "", fmt.Errorf("%w: exactly one URI SAN is required", ErrUnauthenticated)
	}
	identity := cert.URIs[0].String()
	if identity == "" {
		return "", fmt.Errorf("%w: empty URI SAN", ErrUnauthenticated)
	}
	return identity, nil
}

func MutualTLSConfig(clientCAPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if ok := pool.AppendCertsFromPEM(clientCAPEM); !ok {
		return nil, fmt.Errorf("client CA PEM did not contain a valid certificate")
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  pool,
	}, nil
}

type SecurityAuditRecord struct {
	OccurredAt time.Time
	Principal  string
	Permission Permission
	Method     string
	Path       string
	Allowed    bool
	Decision   string
	ActionID   string
	NodeName   string
	Reason     string
}

type AuditSink interface {
	Record(context.Context, SecurityAuditRecord)
}

type SlogAuditSink struct{}

func (SlogAuditSink) Record(_ context.Context, record SecurityAuditRecord) {
	slog.Info(
		"security_audit",
		"occurred_at", record.OccurredAt.UTC(),
		"principal", record.Principal,
		"permission", record.Permission,
		"method", record.Method,
		"path", record.Path,
		"allowed", record.Allowed,
		"decision", record.Decision,
		"action_id", record.ActionID,
		"node_name", record.NodeName,
		"reason", record.Reason,
	)
}
