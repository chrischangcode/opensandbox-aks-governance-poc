package credentialbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/authz"
)

type staticChecker struct {
	decision authz.Decision
}

func (s staticChecker) Check(context.Context, authz.CheckInput) (authz.Decision, error) {
	return s.decision, nil
}

type staticValidator struct {
	err error
}

func (s *staticValidator) ValidateGrant(context.Context, GrantClaims) error {
	return s.err
}

type memoryAudit struct {
	actions []string
}

func (m *memoryAudit) Record(_ context.Context, event AuditEvent) error {
	m.actions = append(m.actions, event.Action)
	return nil
}

type memoryRevocations struct {
	values map[string]time.Time
}

func newMemoryRevocations() *memoryRevocations {
	return &memoryRevocations{values: map[string]time.Time{}}
}

func (m *memoryRevocations) Revoke(_ context.Context, claims GrantClaims) error {
	m.values[claims.ID] = claims.ExpiresAt.Time
	return nil
}

func (m *memoryRevocations) IsRevoked(_ context.Context, grantID string) (bool, error) {
	_, ok := m.values[grantID]
	return ok, nil
}

func TestBrokerIssuesVerifiesAndRevokesExactCredential(t *testing.T) {
	validator := &staticValidator{}
	audit := &memoryAudit{}
	revocations := newMemoryRevocations()
	broker, err := New(staticChecker{decision: authz.Decision{
		Allow: true, Source: assignmentv1alpha1.DecisionSourceBundle,
		AssignmentName: "assignment-a", AssignmentUID: "assignment-uid",
		SandboxID: "sandbox-a", PodUID: "pod-uid",
		CapabilityBundleName: "coding", CapabilityBundleRevision: "sha256:0123456789",
		Backend: "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
	}}, validator, audit, revocations, Config{SigningKey: bytes.Repeat([]byte("k"), 32)}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
	broker.now = func() time.Time { return now }

	issue := request(t, broker, http.MethodPost, "/broker/v1/credentials", map[string]any{
		"identityToken": "pod-token",
		"backend":       "source-control", "method": "GET", "host": "github.com",
		"path": "/org/repo", "taskId": "validate-123", "ttlSeconds": 300,
	}, "")
	if issue.Code != http.StatusCreated {
		t.Fatalf("issue status=%d body=%s", issue.Code, issue.Body.String())
	}
	var issued map[string]any
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	credential, _ := issued["credential"].(string)
	if credential == "" {
		t.Fatal("credential was not returned")
	}

	verify := request(t, broker, http.MethodPost, "/broker/v1/verify", nil, credential)
	if verify.Code != http.StatusOK || len(audit.actions) != 2 ||
		audit.actions[0] != "issued" || audit.actions[1] != "used" {
		t.Fatalf("verify status=%d audit=%v body=%s", verify.Code, audit.actions, verify.Body.String())
	}

	revoke := request(t, broker, http.MethodPost, "/broker/v1/revoke", nil, credential)
	if revoke.Code != http.StatusNoContent {
		t.Fatalf("revoke status=%d body=%s", revoke.Code, revoke.Body.String())
	}
	secondBroker, err := New(broker.checker, validator, audit, revocations, broker.config, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondBroker.now = broker.now
	verify = request(t, secondBroker, http.MethodPost, "/broker/v1/verify", nil, credential)
	if verify.Code != http.StatusUnauthorized {
		t.Fatalf("revoked verify status=%d body=%s", verify.Code, verify.Body.String())
	}
}

func TestBrokerRejectsCredentialAfterSandboxBindingChanges(t *testing.T) {
	validator := &staticValidator{}
	broker, err := New(staticChecker{decision: authz.Decision{
		Allow: true, AssignmentName: "assignment-a", AssignmentUID: "assignment-uid",
		SandboxID: "sandbox-a", PodUID: "old-pod", CapabilityBundleName: "coding",
		CapabilityBundleRevision: "sha256:0123456789",
		Backend:                  "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
	}}, validator, nil, newMemoryRevocations(), Config{SigningKey: bytes.Repeat([]byte("k"), 32)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	issue := request(t, broker, http.MethodPost, "/broker/v1/credentials", map[string]any{
		"identityToken": "pod-token",
		"backend":       "source-control", "method": "GET", "host": "github.com",
		"path": "/org/repo", "taskId": "validate-123", "ttlSeconds": 300,
	}, "")
	var issued map[string]any
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	validator.err = errors.New("Pod UID changed")
	verify := request(t, broker, http.MethodPost, "/broker/v1/verify", nil, issued["credential"].(string))
	if verify.Code != http.StatusUnauthorized {
		t.Fatalf("verify status=%d body=%s", verify.Code, verify.Body.String())
	}
}

func TestBrokerAcceptsPreviousKeyDuringRotation(t *testing.T) {
	decision := authz.Decision{
		Allow: true, AssignmentName: "assignment-a", AssignmentUID: "assignment-uid",
		SandboxID: "sandbox-a", PodUID: "pod-uid", CapabilityBundleName: "coding",
		CapabilityBundleRevision: "sha256:0123456789",
		Backend:                  "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
	}
	oldKey := bytes.Repeat([]byte("o"), 32)
	newKey := bytes.Repeat([]byte("n"), 32)
	revocations := newMemoryRevocations()
	oldBroker, err := New(
		staticChecker{decision: decision}, &staticValidator{}, nil, revocations,
		Config{SigningKey: oldKey, SigningKeyID: "old"}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	oldBroker.now = func() time.Time { return now }
	issue := request(t, oldBroker, http.MethodPost, "/broker/v1/credentials", map[string]any{
		"identityToken": "pod-token",
		"backend":       "source-control", "method": "GET", "host": "github.com",
		"path": "/org/repo", "taskId": "rotation-test", "ttlSeconds": 300,
	}, "")
	var issued map[string]any
	if err := json.Unmarshal(issue.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	rotatedBroker, err := New(
		staticChecker{decision: decision}, &staticValidator{}, nil, revocations,
		Config{SigningKey: newKey, SigningKeyID: "new", PreviousSigningKeys: map[string][]byte{"old": oldKey}}, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	rotatedBroker.now = oldBroker.now
	verify := request(t, rotatedBroker, http.MethodPost, "/broker/v1/verify", nil, issued["credential"].(string))
	if verify.Code != http.StatusOK {
		t.Fatalf("rotated verify status=%d body=%s", verify.Code, verify.Body.String())
	}
}

func request(t *testing.T, handler http.Handler, method, path string, body any, credential string) *httptest.ResponseRecorder {
	t.Helper()
	var input io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		input = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, input)
	if credential != "" {
		req.Header.Set("Authorization", "Bearer "+credential)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	return response
}
