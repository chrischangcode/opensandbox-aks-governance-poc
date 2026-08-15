// Package authz implements the assignmentd Envoy external authorization endpoint.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
)

const (
	// BackendContextKey is the Agentgateway context_extensions key containing
	// the operator-owned backend name.
	BackendContextKey = "backend"
	// IdentityHeader carries the projected Pod-bound token to assignmentd.
	IdentityHeader = "x-aks-sandbox-identity"
)

// CheckInput is the normalized, fail-closed authorization input. IdentityToken
// is sensitive and must not be logged or exposed to policy expressions.
type CheckInput struct {
	Backend       string
	IdentityToken string
	Method        string
	Host          string
	Path          string
	Headers       map[string]string
	SourceAddress string
}

// Decision is an assignment authorization result.
type Decision struct {
	Allow                    bool
	Reason                   string
	Source                   assignmentv1alpha1.SandboxEgressDecisionSource
	AccessRequestName        string
	AssignmentName           string
	AssignmentUID            string
	SandboxID                string
	PodUID                   string
	CapabilityBundleName     string
	CapabilityBundleRevision string
	LogicalTenant            string
	Team                     string
	PermissionLevel          string
	BoundaryDisplayName      string
	Backend                  string
	Method                   string
	Host                     string
	Path                     string
}

// Checker verifies identity, resolves the assignment and bundle, and evaluates
// the selected backend's allow expression.
type Checker interface {
	Check(context.Context, CheckInput) (Decision, error)
}

// Server serves Envoy service.auth.v3.Authorization checks.
type Server struct {
	authv3.UnimplementedAuthorizationServer
	checker Checker
	logger  *slog.Logger
}

// NewServer returns a fail-closed external authorization server.
func NewServer(checker Checker, logger *slog.Logger) *Server {
	if checker == nil {
		panic("authz: nil checker")
	}
	return &Server{checker: checker, logger: logger}
}

// Check implements Envoy's v3 external authorization protocol.
func (s *Server) Check(ctx context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	input, err := normalize(req)
	if err != nil {
		s.logger.WarnContext(ctx, "rejecting malformed authorization request", "error", err)
		return deniedResponse(), nil
	}

	decision, err := s.checker.Check(ctx, input)
	if err != nil {
		s.logger.ErrorContext(ctx, "assignment authorization failed", append(decisionLogAttributes(input, decision), "error", err)...)
		return deniedResponse(), nil
	}
	if !decision.Allow {
		s.logger.InfoContext(ctx, "assignment authorization denied", decisionLogAttributes(input, decision)...)
		return deniedResponse(), nil
	}

	s.logger.InfoContext(ctx, "assignment authorization allowed", decisionLogAttributes(input, decision)...)
	return allowedResponse(), nil
}

func normalize(req *authv3.CheckRequest) (CheckInput, error) {
	if req == nil || req.Attributes == nil {
		return CheckInput{}, errors.New("missing attribute context")
	}

	backend := strings.TrimSpace(req.Attributes.ContextExtensions[BackendContextKey])
	if backend == "" {
		return CheckInput{}, errors.New("missing backend context")
	}

	httpRequest := req.Attributes.GetRequest().GetHttp()
	if httpRequest == nil {
		return CheckInput{}, errors.New("missing HTTP request attributes")
	}
	if httpRequest.Method == "" || httpRequest.Path == "" {
		return CheckInput{}, errors.New("missing HTTP method or path")
	}

	identity := headerValue(httpRequest.Headers, IdentityHeader)
	if strings.TrimSpace(identity) == "" {
		return CheckInput{}, errors.New("missing sandbox identity")
	}

	headers := make(map[string]string, len(httpRequest.Headers))
	for name, value := range httpRequest.Headers {
		name = strings.ToLower(name)
		if name == IdentityHeader || strings.HasPrefix(name, ":") {
			continue
		}
		headers[name] = value
	}

	target, err := governance.NormalizeTarget(backend, httpRequest.Method, httpRequest.Host, httpRequest.Path)
	if err != nil {
		return CheckInput{}, fmt.Errorf("invalid authorization target: %w", err)
	}

	return CheckInput{
		Backend:       target.Backend,
		IdentityToken: identity,
		Method:        target.Method,
		Host:          target.Host,
		Path:          target.Path,
		Headers:       headers,
		SourceAddress: socketAddress(req.Attributes.GetSource().GetAddress()),
	}, nil
}

func headerValue(headers map[string]string, wanted string) string {
	for name, value := range headers {
		if strings.EqualFold(name, wanted) {
			return value
		}
	}
	return ""
}

func socketAddress(address *corev3.Address) string {
	if address == nil || address.GetSocketAddress() == nil {
		return ""
	}
	return address.GetSocketAddress().Address
}

func decisionLogAttributes(input CheckInput, decision Decision) []any {
	source := decision.Source
	if source == "" {
		source = assignmentv1alpha1.DecisionSourceDeny
	}
	return []any{
		"assignment_name", decision.AssignmentName,
		"assignment_uid", decision.AssignmentUID,
		"sandbox_id", decision.SandboxID,
		"pod_uid", decision.PodUID,
		"capability_bundle", decision.CapabilityBundleName,
		"capability_bundle_revision", decision.CapabilityBundleRevision,
		"logical_tenant", decision.LogicalTenant,
		"team", decision.Team,
		"permission_level", decision.PermissionLevel,
		"backend", firstNonEmpty(decision.Backend, input.Backend),
		"method", firstNonEmpty(decision.Method, input.Method),
		"host", firstNonEmpty(decision.Host, input.Host),
		"path", firstNonEmpty(decision.Path, input.Path),
		"decision_source", source,
		"access_request", decision.AccessRequestName,
		"allowed", decision.Allow,
		"reason", decision.Reason,
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func allowedResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{
			OkResponse: &authv3.OkHttpResponse{
				HeadersToRemove: []string{IdentityHeader},
			},
		},
	}
}

func deniedResponse() *authv3.CheckResponse {
	return &authv3.CheckResponse{
		Status: &statuspb.Status{Code: int32(codes.PermissionDenied)},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{
			DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Body:   http.StatusText(http.StatusForbidden),
			},
		},
	}
}
