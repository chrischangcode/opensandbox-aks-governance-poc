package authz

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

type recordingChecker struct {
	input    CheckInput
	decision Decision
	err      error
	calls    int
}

func (c *recordingChecker) Check(_ context.Context, input CheckInput) (Decision, error) {
	c.calls++
	c.input = input
	return c.decision, c.err
}

func TestCheckNormalizesAndAllows(t *testing.T) {
	checker := &recordingChecker{decision: Decision{Allow: true}}
	server := NewServer(checker, slog.New(slog.NewTextHandler(io.Discard, nil)))

	response, err := server.Check(context.Background(), checkRequest())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	if checker.calls != 1 {
		t.Fatalf("checker calls = %d, want 1", checker.calls)
	}
	if checker.input.Backend != "goproxy" {
		t.Errorf("backend = %q, want goproxy", checker.input.Backend)
	}
	if checker.input.IdentityToken != "sensitive-token" {
		t.Errorf("identity token was not extracted")
	}
	if checker.input.Method != "GET" || checker.input.Host != "example.test" || checker.input.Path != "/repos" {
		t.Errorf("normalized HTTP input = %#v", checker.input)
	}
	if checker.input.SourceAddress != "10.2.3.4" {
		t.Errorf("source address = %q, want 10.2.3.4", checker.input.SourceAddress)
	}
	if _, ok := checker.input.Headers[IdentityHeader]; ok {
		t.Fatal("identity header is visible to checker policy headers")
	}
	if _, ok := checker.input.Headers[":method"]; ok {
		t.Fatal("pseudo-header is visible to checker policy headers")
	}
	if got := checker.input.Headers["api-key"]; got != "client-key" {
		t.Errorf("api-key = %q, want client-key", got)
	}

	if response.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("response status = %d, want OK", response.GetStatus().GetCode())
	}
	okResponse := response.GetOkResponse()
	if okResponse == nil {
		t.Fatal("missing OK response")
	}
	if len(okResponse.HeadersToRemove) != 1 || okResponse.HeadersToRemove[0] != IdentityHeader {
		t.Fatalf("headers to remove = %v", okResponse.HeadersToRemove)
	}
}

func TestGRPCCheckRoundTrip(t *testing.T) {
	checker := &recordingChecker{decision: Decision{Allow: true}}
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	authv3.RegisterAuthorizationServer(grpcServer, NewServer(checker, slog.New(slog.NewTextHandler(io.Discard, nil))))
	go func() {
		_ = grpcServer.Serve(listener)
	}()
	t.Cleanup(grpcServer.Stop)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.NewClient(
		"passthrough:///bufconn",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	t.Cleanup(func() { _ = connection.Close() })

	response, err := authv3.NewAuthorizationClient(connection).Check(ctx, checkRequest())
	if err != nil {
		t.Fatalf("gRPC Check() error = %v", err)
	}
	if response.GetStatus().GetCode() != int32(codes.OK) {
		t.Fatalf("response status = %d, want OK", response.GetStatus().GetCode())
	}
	if checker.calls != 1 || checker.input.Backend != "goproxy" {
		t.Fatalf("checker input = %#v, calls = %d", checker.input, checker.calls)
	}
}

func TestHostname(t *testing.T) {
	for input, want := range map[string]string{
		"example.test":       "example.test",
		"example.test:8443":  "example.test",
		"[2001:db8::1]:8443": "2001:db8::1",
		"[2001:db8::1]":      "2001:db8::1",
	} {
		got, err := governance.NormalizeHost(input)
		if err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v, want %q", input, got, err, want)
		}
	}
}

func TestCheckRejectsMalformedRequestsBeforeChecker(t *testing.T) {
	tests := map[string]*authv3.CheckRequest{
		"nil":              nil,
		"missing backend":  checkRequestWithoutBackend(),
		"missing identity": checkRequestWithoutIdentity(),
		"missing HTTP": {
			Attributes: &authv3.AttributeContext{
				ContextExtensions: map[string]string{BackendContextKey: "goproxy"},
			},
		},
	}

	for name, request := range tests {
		t.Run(name, func(t *testing.T) {
			checker := &recordingChecker{decision: Decision{Allow: true}}
			server := NewServer(checker, slog.New(slog.NewTextHandler(io.Discard, nil)))
			response, err := server.Check(context.Background(), request)
			if err != nil {
				t.Fatalf("Check() error = %v", err)
			}
			assertDenied(t, response)
			if checker.calls != 0 {
				t.Fatalf("checker calls = %d, want 0", checker.calls)
			}
		})
	}
}

func TestCheckFailsClosedOnCheckerError(t *testing.T) {
	checker := &recordingChecker{err: errors.New("store unavailable")}
	server := NewServer(checker, slog.New(slog.NewTextHandler(io.Discard, nil)))

	response, err := server.Check(context.Background(), checkRequest())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertDenied(t, response)
}

func TestCheckReturnsDeniedDecision(t *testing.T) {
	checker := &recordingChecker{decision: Decision{Reason: "backend not granted"}}
	server := NewServer(checker, slog.New(slog.NewTextHandler(io.Discard, nil)))

	response, err := server.Check(context.Background(), checkRequest())
	if err != nil {
		t.Fatalf("Check() error = %v", err)
	}
	assertDenied(t, response)
}

func assertDenied(t *testing.T, response *authv3.CheckResponse) {
	t.Helper()
	if response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		t.Fatalf("response status = %d, want PermissionDenied", response.GetStatus().GetCode())
	}
	if response.GetDeniedResponse() == nil {
		t.Fatal("missing denied HTTP response")
	}
	if response.GetDeniedResponse().GetStatus().GetCode() != typev3.StatusCode_Forbidden {
		t.Fatalf("HTTP status = %v, want Forbidden", response.GetDeniedResponse().GetStatus().GetCode())
	}
}

func checkRequest() *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			ContextExtensions: map[string]string{BackendContextKey: "goproxy"},
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{Address: "10.2.3.4"},
					},
				},
			},
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Host:   "example.test:8443",
					Path:   "/repos?q=test",
					Headers: map[string]string{
						IdentityHeader: "sensitive-token",
						"API-Key":      "client-key",
						":method":      "GET",
					},
				},
			},
		},
	}
}

func checkRequestWithoutBackend() *authv3.CheckRequest {
	r := checkRequest()
	delete(r.Attributes.ContextExtensions, BackendContextKey)
	return r
}

func checkRequestWithoutIdentity() *authv3.CheckRequest {
	r := checkRequest()
	delete(r.Attributes.Request.Http.Headers, IdentityHeader)
	return r
}
