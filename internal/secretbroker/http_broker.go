package secretbroker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/achirothmane/aegis-ege/governedaction"
)

var (
	ErrUnknownHandle            = errors.New("credential handle is unknown")
	ErrCredentialBootstrap      = errors.New("credential bootstrap is invalid")
	ErrCallerCredentialHeader   = errors.New("caller supplied a credential-bearing header")
	ErrDestinationMismatch      = errors.New("request destination does not match credential binding")
	ErrInsecureDestination      = errors.New("credential destination must use HTTPS")
	ErrCredentialURL            = errors.New("credential request URL is invalid")
)

// StaticCredential is trusted bootstrap input for the experimental broker.
// RawSecret must never be passed through the untrusted actor interface.
type StaticCredential struct {
	Binding   governedaction.CredentialUseBinding
	RawSecret []byte
}

// HTTPRequest contains only the opaque handle and boundary facts. It has no
// field for raw credential material.
type HTTPRequest struct {
	HandleID string
	Binding  governedaction.CredentialUseBinding
	Method   string
	URL      string
	Header   http.Header
	Body     []byte
}

// HTTPBroker resolves an opaque handle and injects the raw bearer credential at
// the final outbound HTTP boundary.
//
// This package is an experiment in interface/custody semantics. Running broker
// and actor in the same OS protection domain does not prove secret isolation;
// production isolation still requires a separate process/VM plus authenticated
// IPC and complete mediation.
type HTTPBroker struct {
	records               map[string]credentialRecord
	client                *http.Client
	now                   func() time.Time
	allowInsecureLoopback bool
}

type credentialRecord struct {
	binding governedaction.CredentialUseBinding
	secret  []byte
}

func NewHTTPBroker(
	credentials []StaticCredential,
	client *http.Client,
	now func() time.Time,
	allowInsecureLoopback bool,
) (*HTTPBroker, error) {
	if client == nil {
		client = http.DefaultClient
	}
	if now == nil {
		now = time.Now
	}

	records := make(map[string]credentialRecord, len(credentials))
	for _, credential := range credentials {
		if strings.TrimSpace(credential.Binding.HandleID) == "" || len(credential.RawSecret) == 0 {
			return nil, ErrCredentialBootstrap
		}
		if _, exists := records[credential.Binding.HandleID]; exists {
			return nil, fmt.Errorf("%w: duplicate handle %q", ErrCredentialBootstrap, credential.Binding.HandleID)
		}
		records[credential.Binding.HandleID] = credentialRecord{
			binding: credential.Binding,
			secret:  append([]byte(nil), credential.RawSecret...),
		}
	}

	clientCopy := *client
	// A redirect changes the effective network destination after admission.
	// Return the 3xx response to the caller, but never follow it with the
	// injected credential.
	clientCopy.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &HTTPBroker{
		records:               records,
		client:                &clientCopy,
		now:                   now,
		allowInsecureLoopback: allowInsecureLoopback,
	}, nil
}

// Do performs one HTTP request after exact credential-use validation. It never
// returns the resolved secret. The returned response request is sanitized so a
// caller cannot recover the injected Authorization value through resp.Request.
func (b *HTTPBroker) Do(ctx context.Context, input HTTPRequest) (*http.Response, error) {
	if b == nil {
		return nil, ErrCredentialBootstrap
	}
	record, ok := b.records[input.HandleID]
	if !ok {
		return nil, ErrUnknownHandle
	}
	if input.HandleID != input.Binding.HandleID {
		return nil, fmt.Errorf("%w: request handle and binding differ", governedaction.ErrCredentialBindingChanged)
	}
	if err := governedaction.CheckCredentialUse(record.binding, input.Binding, b.now().UTC()); err != nil {
		return nil, err
	}

	parsed, err := url.Parse(input.URL)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return nil, ErrCredentialURL
	}
	destination := strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
	if destination != record.binding.Destination {
		return nil, ErrDestinationMismatch
	}
	if parsed.Scheme != "https" && !(b.allowInsecureLoopback && isLoopbackHost(parsed.Hostname())) {
		return nil, ErrInsecureDestination
	}

	header := input.Header.Clone()
	if header == nil {
		header = make(http.Header)
	}
	if header.Get("Authorization") != "" || header.Get("Proxy-Authorization") != "" {
		return nil, ErrCallerCredentialHeader
	}
	header.Set("Authorization", "Bearer "+string(record.secret))

	method := strings.TrimSpace(input.Method)
	if method == "" {
		method = http.MethodGet
	}
	request, err := http.NewRequestWithContext(ctx, method, input.URL, bytes.NewReader(input.Body))
	if err != nil {
		return nil, fmt.Errorf("build broker request: %w", err)
	}
	request.Header = header

	response, err := b.client.Do(request)
	if err != nil {
		return nil, err
	}
	response.Request = sanitizedRequest(response.Request)
	return response, nil
}

func sanitizedRequest(request *http.Request) *http.Request {
	if request == nil {
		return nil
	}
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	clone.Header.Del("Authorization")
	clone.Header.Del("Proxy-Authorization")
	return clone
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// DrainAndClose is a test/helper utility that closes a broker response without
// exposing internal request credentials. It is kept here to make callers handle
// response bodies deterministically in experiments.
func DrainAndClose(response *http.Response) error {
	if response == nil || response.Body == nil {
		return nil
	}
	_, copyErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if copyErr != nil {
		return copyErr
	}
	return closeErr
}
