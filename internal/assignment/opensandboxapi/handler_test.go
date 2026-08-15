package opensandboxapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeStore struct {
	mu              sync.Mutex
	value           *assignment.Assignment
	created         assignment.CreateRequest
	deleted         string
	paused          bool
	resumeUID       string
	createErr       error
	setSandboxIDErr error
	lifecycleErr    error
}

func (s *fakeStore) Create(_ context.Context, request assignment.CreateRequest) (*assignment.Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = request
	if s.createErr != nil {
		return nil, s.createErr
	}
	s.value = &assignment.Assignment{Namespace: request.Namespace, Name: "assignment-a981", UID: "assignment-uid", CapabilityBundleName: request.CapabilityBundleName}
	return s.value, nil
}
func (s *fakeStore) Get(_ context.Context, _, name string) (*assignment.Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value == nil || s.value.Name != name {
		return nil, notFound(name)
	}
	copy := *s.value
	return &copy, nil
}
func (s *fakeStore) GetBySandboxID(_ context.Context, _, id string) (*assignment.Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.value == nil || (s.value.WorkloadRef == nil || s.value.WorkloadRef.Name != id) {
		return nil, notFound(id)
	}
	copy := *s.value
	return &copy, nil
}
func (s *fakeStore) SetSandboxID(_ context.Context, _, _ string, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.setSandboxIDErr != nil {
		return s.setSandboxIDErr
	}
	s.value.WorkloadRef = &assignment.ObjectReference{Name: id}
	return nil
}
func (s *fakeStore) SetLifecycleFence(_ context.Context, _, _ string, paused bool, resumeUID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lifecycleErr != nil {
		return s.lifecycleErr
	}
	s.paused, s.resumeUID = paused, resumeUID
	s.value.Ready = !paused
	return nil
}
func (s *fakeStore) Delete(_ context.Context, _, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted = name
	return nil
}

func TestCreateInjectsTrustedMetadataAndPreservesResponse(t *testing.T) {
	var upstreamBody map[string]any
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sandboxes" || r.Header.Get("OPEN-SANDBOX-API-KEY") != "upstream-key" {
			t.Errorf("upstream request path=%q key=%q", r.URL.Path, r.Header.Get("OPEN-SANDBOX-API-KEY"))
		}
		if err := json.NewDecoder(r.Body).Decode(&upstreamBody); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Pending"},"createdAt":"2026-08-11T00:00:00Z","extensions":{"opensandbox.extensions.aks-sandbox-assignment-uid":"assignment-uid"}}`))
	}))
	defer upstream.Close()

	store := &fakeStore{}
	handler := newTestHandler(t, store, upstream.URL)
	request := httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{
		"image":{"uri":"example/image"},
		"entrypoint":["sleep","infinity"],
		"resourceLimits":{"cpu":"1","memory":"1Gi"},
		"metadata":{"aks-sandbox.azure.com/assignment":"forged","user":"ok"},
		"extensions":{"aks-sandbox.azure.com/capabilityProfile":"coding","other":"kept"}
	}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)

	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var clientResponse createSandboxResponse
	if err := json.Unmarshal(response.Body.Bytes(), &clientResponse); err != nil {
		t.Fatal(err)
	}
	if _, exposed := clientResponse.Metadata[assignment.AssignmentLabel]; exposed {
		t.Fatal("trusted assignment label was exposed to the client")
	}
	if _, exposed := clientResponse.Extensions[assignmentUIDExtension]; exposed {
		t.Fatal("trusted assignment UID extension was exposed to the client")
	}
	if clientResponse.Extensions[CapabilityProfileExtension] != "coding" {
		t.Fatalf("client extensions=%#v", clientResponse.Extensions)
	}
	if store.created.CapabilityBundleName != "coding" {
		t.Fatalf("create request=%#v", store.created)
	}
	metadata := upstreamBody["metadata"].(map[string]any)
	if metadata[assignment.AssignmentLabel] != "assignment-a981" || metadata["user"] != "ok" {
		t.Fatalf("metadata=%#v", metadata)
	}
	extensions := upstreamBody["extensions"].(map[string]any)
	if _, exists := extensions[CapabilityProfileExtension]; exists {
		t.Fatal("capability profile was forwarded")
	}
	if extensions[assignmentUIDExtension] != "assignment-uid" || extensions["other"] != "kept" {
		t.Fatalf("extensions=%#v", extensions)
	}
}

func TestCreateRejectsMissingProfileWithoutSideEffects(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	store := &fakeStore{}
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{"image":{"uri":"example/image"}}`)))
	if response.Code != http.StatusForbidden || store.value != nil || upstreamCalls != 0 {
		t.Fatalf("status=%d assignment=%#v upstreamCalls=%d", response.Code, store.value, upstreamCalls)
	}
}

func TestCreateRejectsMissingCapabilityBundleWithoutCallingUpstream(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	store := &fakeStore{createErr: apierrors.NewNotFound(
		schema.GroupResource{Group: "aks-sandbox.azure.com", Resource: "capabilitybundles"}, "missing-bundle",
	)}
	response := httptest.NewRecorder()
	body := `{"image":{"uri":"example/image"},"extensions":{"aks-sandbox.azure.com/capabilityProfile":"missing-bundle"}}`
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(body)))
	if response.Code != http.StatusNotFound || store.value != nil || upstreamCalls != 0 {
		t.Fatalf("status=%d assignment=%#v upstreamCalls=%d", response.Code, store.value, upstreamCalls)
	}
	if store.created.CapabilityBundleName != "missing-bundle" {
		t.Fatalf("create request=%#v", store.created)
	}
}

func TestCreateUpstreamFailureCompensatesAssignment(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":{"code":"INVALID_PARAMETER"}}`))
	}))
	defer upstream.Close()
	store := &fakeStore{}
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, validCreateRequest())
	if response.Code != http.StatusBadRequest || store.deleted != "assignment-a981" {
		t.Fatalf("status=%d deleted=%q", response.Code, store.deleted)
	}
}

func TestCreateMappingFailureDeletesUpstreamAndAssignment(t *testing.T) {
	var paths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodPost {
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Pending"},"createdAt":"2026-08-11T00:00:00Z"}`))
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	store := &fakeStore{setSandboxIDErr: errors.New("write failed")}
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, validCreateRequest())
	if response.Code != http.StatusInternalServerError || store.deleted != "assignment-a981" {
		t.Fatalf("status=%d deleted=%q", response.Code, store.deleted)
	}
	if len(paths) != 2 || paths[1] != "DELETE /sandboxes/sandbox-123" {
		t.Fatalf("upstream paths=%v", paths)
	}
}

func TestPauseRevokesBeforeUpstream(t *testing.T) {
	store := &fakeStore{value: &assignment.Assignment{Name: "assignment-a981", Ready: true, WorkloadRef: &assignment.ObjectReference{Name: "sandbox-123"}}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		store.mu.Lock()
		paused := store.paused
		store.mu.Unlock()
		if !paused {
			t.Error("upstream pause called before assignment was fenced")
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes/sandbox-123/pause", nil))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d", response.Code)
	}
}

func TestResumeFencesOldPodBeforeUpstreamAndRollsBackOnFailure(t *testing.T) {
	store := &fakeStore{value: &assignment.Assignment{
		Name: "assignment-a981", Ready: false,
		WorkloadRef: &assignment.ObjectReference{Name: "sandbox-123"},
		PodRef:      &assignment.ObjectReference{UID: "old-pod"},
	}}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		store.mu.Lock()
		paused, resumeUID := store.paused, store.resumeUID
		store.mu.Unlock()
		if paused || resumeUID != "old-pod" {
			t.Errorf("resume fence paused=%v uid=%q", paused, resumeUID)
		}
		w.WriteHeader(http.StatusConflict)
	}))
	defer upstream.Close()
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes/sandbox-123/resume", nil))
	if response.Code != http.StatusConflict || !store.paused || store.resumeUID != "" {
		t.Fatalf("status=%d paused=%v resumeUID=%q", response.Code, store.paused, store.resumeUID)
	}
}

func TestDeleteManagedSandboxDeletesAssignmentWithoutProxy(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	store := &fakeStore{value: &assignment.Assignment{Name: "assignment-a981", WorkloadRef: &assignment.ObjectReference{Name: "sandbox-123"}}}
	handler := newTestHandler(t, store, upstream.URL)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/opensandbox/sandboxes/sandbox-123", nil))
	if response.Code != http.StatusNoContent || store.deleted != "assignment-a981" || upstreamCalls != 0 {
		t.Fatalf("status=%d deleted=%q upstreamCalls=%d", response.Code, store.deleted, upstreamCalls)
	}
}

func TestPassThroughStripsPrefix(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sandboxes/sandbox-123" || r.URL.RawQuery != "view=full" {
			t.Errorf("path=%q query=%q", r.URL.Path, r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Running"},"createdAt":"2026-08-11T00:00:00Z","metadata":{"aks-sandbox.azure.com/assignment":"internal","user":"visible"},"extensions":{"opensandbox.extensions.aks-sandbox-assignment-uid":"internal"}}`))
	}))
	defer upstream.Close()
	handler := newTestHandler(t, &fakeStore{}, upstream.URL)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/opensandbox/sandboxes/sandbox-123?view=full", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d", response.Code)
	}
	var value sandboxResponse
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	if _, found := value.Metadata[assignment.AssignmentLabel]; found || value.Metadata["user"] != "visible" {
		t.Fatalf("metadata=%#v", value.Metadata)
	}
	if _, found := value.Extensions[assignmentUIDExtension]; found {
		t.Fatalf("extensions=%#v", value.Extensions)
	}
}

func TestPatchRejectsReservedMetadata(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	handler := newTestHandler(t, &fakeStore{}, upstream.URL)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPatch, "/opensandbox/sandboxes/sandbox-123/metadata", stringsReader(`{"aks-sandbox.azure.com/assignment":null}`)))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status=%d", response.Code)
	}
}

func newTestHandler(t *testing.T, store assignment.Store, upstream string) http.Handler {
	t.Helper()
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	return NewHandler(store, Config{
		Upstream:  parsed,
		APIKey:    "upstream-key",
		Namespace: "aks-sandbox-system",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func notFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "aks-sandbox.azure.com", Resource: "sandboxassignments"}, name)
}

func validCreateRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{
		"image":{"uri":"example/image"},
		"entrypoint":["sleep","infinity"],
		"resourceLimits":{"cpu":"1","memory":"1Gi"},
		"extensions":{"aks-sandbox.azure.com/capabilityProfile":"coding"}
	}`))
}

func stringsReader(value string) io.Reader { return bytes.NewBufferString(value) }
