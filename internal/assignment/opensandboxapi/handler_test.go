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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
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

type trackingAdmission struct {
	mu        sync.Mutex
	active    int
	maxActive int
}

type staticTemplateResolver struct {
	value ResolvedTemplate
	err   error
}

func (r staticTemplateResolver) Resolve(context.Context, string) (ResolvedTemplate, error) {
	return r.value, r.err
}

func (a *trackingAdmission) AuthorizeCreate(context.Context, string, *ossandbox.CreateSandboxRequest) (func(), error) {
	a.mu.Lock()
	a.active++
	if a.active > a.maxActive {
		a.maxActive = a.active
	}
	a.mu.Unlock()
	time.Sleep(25 * time.Millisecond)
	a.mu.Lock()
	a.active--
	a.mu.Unlock()
	return func() {}, nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func (s *fakeStore) Create(_ context.Context, request assignment.CreateRequest) (*assignment.Assignment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = request
	if s.createErr != nil {
		return nil, s.createErr
	}
	if s.value != nil && request.Name != "" && s.value.Name == request.Name {
		if s.value.RequestHash != request.RequestHash || s.value.IdempotencyKey != request.IdempotencyKey {
			return nil, assignment.ErrIdempotencyConflict
		}
		copy := *s.value
		copy.Existing = true
		return &copy, nil
	}
	name := request.Name
	if name == "" {
		name = "assignment-a981"
	}
	s.value = &assignment.Assignment{
		Namespace: request.Namespace, Name: name, UID: "assignment-uid",
		LogicalTenant: request.LogicalTenant, CapabilityBundleName: request.CapabilityBundleName,
		IdempotencyKey: request.IdempotencyKey, RequestHash: request.RequestHash,
		CreatedAt: time.Now().UTC(),
	}
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
	if s.value == nil || (s.value.SandboxID != id && (s.value.WorkloadRef == nil || s.value.WorkloadRef.Name != id)) {
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
	s.value.SandboxID = id
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

func TestCreateResolvesTrustedTemplateAndPreservesResponse(t *testing.T) {
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
		"image":{"uri":"attacker/image"},
		"snapshotId":"attacker-snapshot",
		"entrypoint":["attacker"],
		"resourceLimits":{"cpu":"99","memory":"99Gi"},
		"resourceRequests":{"cpu":"99","memory":"99Gi"},
		"volumes":[{"name":"attacker"}],
		"metadata":{"aks-sandbox.azure.com/assignment":"forged","user":"ok"},
		"extensions":{"aks-sandbox.azure.com/template":"python-kata-reader-v2","aks-sandbox.azure.com/capabilityProfile":"forged","other":"discarded"}
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
	if clientResponse.Extensions[SandboxTemplateExtension] != "python-kata-reader-v2" ||
		clientResponse.Extensions[SandboxTemplateRevisionExtension] != testTemplateRevision {
		t.Fatalf("client template extensions=%#v", clientResponse.Extensions)
	}
	if store.created.CapabilityBundleName != "coding" {
		t.Fatalf("create request=%#v", store.created)
	}
	if store.created.TemplateName != "python-kata-reader-v2" ||
		store.created.TemplateUID != "template-uid" ||
		store.created.TemplateRevision != testTemplateRevision ||
		store.created.LogicalTenant != "tenant-a" {
		t.Fatalf("trusted template assignment=%#v", store.created)
	}
	metadata := upstreamBody["metadata"].(map[string]any)
	if metadata[assignment.AssignmentLabel] != "assignment-a981" ||
		metadata[SandboxTemplateExtension] != "python-kata-reader-v2" ||
		metadata["user"] != "ok" {
		t.Fatalf("metadata=%#v", metadata)
	}
	if image := upstreamBody["image"].(map[string]any)["uri"]; image != "python@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("trusted image=%v", image)
	}
	if entrypoint := upstreamBody["entrypoint"].([]any); len(entrypoint) != 3 || entrypoint[0] != "tail" {
		t.Fatalf("trusted entrypoint=%#v", entrypoint)
	}
	limits := upstreamBody["resourceLimits"].(map[string]any)
	if limits["cpu"] != "500m" || limits["memory"] != "512Mi" {
		t.Fatalf("trusted resource limits=%#v", limits)
	}
	if upstreamBody["timeout"] != float64(1800) {
		t.Fatalf("trusted timeout=%v", upstreamBody["timeout"])
	}
	for _, forbidden := range []string{"snapshotId", "resourceRequests", "volumes", "networkPolicy", "credentialProxy", "platform"} {
		if _, exists := upstreamBody[forbidden]; exists {
			t.Fatalf("caller-controlled field %q was forwarded: %#v", forbidden, upstreamBody)
		}
	}
	extensions := upstreamBody["extensions"].(map[string]any)
	if extensions[assignmentUIDExtension] != "assignment-uid" || len(extensions) != 1 {
		t.Fatalf("extensions=%#v", extensions)
	}
}

func TestCreateRequiresAndReplaysIdempotencyKey(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Pending"},"createdAt":"2026-08-11T00:00:00Z"}`))
	}))
	defer upstream.Close()
	store := &fakeStore{}
	handler := newTestHandlerWithConfig(t, store, upstream.URL, Config{RequireIdempotency: true})

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, validCreateRequest())
	if missing.Code != http.StatusBadRequest {
		t.Fatalf("missing key status=%d body=%s", missing.Code, missing.Body.String())
	}

	firstRequest := validCreateRequest()
	firstRequest.Header.Set("Idempotency-Key", "create-12345678")
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, firstRequest)
	if first.Code != http.StatusAccepted {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}

	retryRequest := validCreateRequest()
	retryRequest.Header.Set("Idempotency-Key", "create-12345678")
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, retryRequest)
	if retry.Code != http.StatusOK || upstreamCalls != 1 || !strings.Contains(retry.Body.String(), `"id":"sandbox-123"`) {
		t.Fatalf("retry status=%d upstream=%d body=%s", retry.Code, upstreamCalls, retry.Body.String())
	}
}

func TestCreateRejectsIdempotencyKeyWithDifferentIntent(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Pending"},"createdAt":"2026-08-11T00:00:00Z"}`))
	}))
	defer upstream.Close()
	handler := newTestHandlerWithConfig(t, &fakeStore{}, upstream.URL, Config{RequireIdempotency: true})
	firstRequest := validCreateRequest()
	firstRequest.Header.Set("Idempotency-Key", "create-12345678")
	handler.ServeHTTP(httptest.NewRecorder(), firstRequest)

	secondRequest := httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{
		"metadata":{"purpose":"different"},
		"extensions":{"aks-sandbox.azure.com/template":"python-kata-reader-v2"}
	}`))
	secondRequest.Header.Set("Idempotency-Key", "create-12345678")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, secondRequest)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestCreateExpiresStalePendingOperation(t *testing.T) {
	store := &fakeStore{}
	handler := newTestHandlerWithConfig(t, store, "http://127.0.0.1:1", Config{
		RequireIdempotency:  true,
		PendingOperationTTL: time.Second,
	})
	firstRequest := validCreateRequest()
	firstRequest.Header.Set("Idempotency-Key", "create-stale-1234")
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, firstRequest)
	if first.Code != http.StatusBadGateway {
		t.Fatalf("first status=%d body=%s", first.Code, first.Body.String())
	}
	store.value.CreatedAt = time.Now().Add(-2 * time.Second)

	retryRequest := validCreateRequest()
	retryRequest.Header.Set("Idempotency-Key", "create-stale-1234")
	retry := httptest.NewRecorder()
	handler.ServeHTTP(retry, retryRequest)
	if retry.Code != http.StatusServiceUnavailable || store.deleted != store.value.Name {
		t.Fatalf("retry status=%d deleted=%q body=%s", retry.Code, store.deleted, retry.Body.String())
	}
}

func TestCreateRejectsMissingTemplateWithoutSideEffects(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	store := &fakeStore{}
	response := httptest.NewRecorder()
	newTestHandler(t, store, upstream.URL).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{"image":{"uri":"example/image"},"extensions":{"aks-sandbox.azure.com/capabilityProfile":"coding"}}`)))
	if response.Code != http.StatusForbidden || store.value != nil || upstreamCalls != 0 {
		t.Fatalf("status=%d assignment=%#v upstreamCalls=%d", response.Code, store.value, upstreamCalls)
	}
}

func TestCreateRejectsUnavailableTemplateWithoutCallingUpstream(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { upstreamCalls++ }))
	defer upstream.Close()
	store := &fakeStore{}
	response := httptest.NewRecorder()
	body := `{"extensions":{"aks-sandbox.azure.com/template":"missing-template"}}`
	handler := newTestHandlerWithConfig(t, store, upstream.URL, Config{
		Templates: staticTemplateResolver{err: apierrors.NewNotFound(
			schema.GroupResource{Group: "aks-sandbox.azure.com", Resource: "sandboxtemplates"}, "missing-template",
		)},
	})
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(body)))
	if response.Code != http.StatusNotFound || store.value != nil || upstreamCalls != 0 {
		t.Fatalf("status=%d assignment=%#v upstreamCalls=%d", response.Code, store.value, upstreamCalls)
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

func TestCreateMappingFailureRetainsOperationForControllerRecovery(t *testing.T) {
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
	if response.Code != http.StatusInternalServerError || store.deleted != "" {
		t.Fatalf("status=%d deleted=%q", response.Code, store.deleted)
	}
	if len(paths) != 1 || paths[0] != "POST /sandboxes" {
		t.Fatalf("upstream paths=%v", paths)
	}
}

func TestCreateSerializesAdmissionAndAssignmentReservation(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"sandbox-123","status":{"state":"Pending"},"createdAt":"2026-08-11T00:00:00Z"}`))
	}))
	defer upstream.Close()
	admission := &trackingAdmission{}
	handler := newTestHandlerWithAdmission(t, &fakeStore{}, upstream.URL, admission)
	var wait sync.WaitGroup
	wait.Add(2)
	for range 2 {
		go func() {
			defer wait.Done()
			handler.ServeHTTP(httptest.NewRecorder(), validCreateRequest())
		}()
	}
	wait.Wait()
	if admission.maxActive != 1 {
		t.Fatalf("maximum concurrent admissions = %d", admission.maxActive)
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

func TestPauseTransportFailureKeepsAssignmentFenced(t *testing.T) {
	store := &fakeStore{value: &assignment.Assignment{
		Name: "assignment-a981", Ready: true,
		WorkloadRef: &assignment.ObjectReference{Name: "sandbox-123"},
	}}
	handler := newTestHandler(t, store, "http://upstream.invalid").(*Handler)
	handler.httpClient = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("response lost")
	})}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes/sandbox-123/pause", nil))
	if response.Code != http.StatusBadGateway || !store.paused {
		t.Fatalf("status=%d paused=%v", response.Code, store.paused)
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
	return newTestHandlerWithAdmission(t, store, upstream, nil)
}

func newTestHandlerWithAdmission(t *testing.T, store assignment.Store, upstream string, admission Admission) http.Handler {
	return newTestHandlerWithConfig(t, store, upstream, Config{Admission: admission})
}

const testTemplateRevision = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

func newTestHandlerWithConfig(t *testing.T, store assignment.Store, upstream string, config Config) http.Handler {
	t.Helper()
	parsed, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if config.Templates == nil {
		config.Templates = staticTemplateResolver{value: ResolvedTemplate{
			Name: "python-kata-reader-v2", UID: "template-uid", Revision: testTemplateRevision,
			Image:      "python@sha256:" + strings.Repeat("a", 64),
			Entrypoint: []string{"tail", "-f", "/dev/null"},
			CPU:        "500m", Memory: "512Mi", TimeoutSeconds: 1800,
			CapabilityBundleName: "coding", CapabilityBundleRevision: "sha256:" + strings.Repeat("c", 64),
			LogicalTenant: "tenant-a",
		}}
	}
	config.Upstream = parsed
	config.APIKey = "upstream-key"
	config.Namespace = "aks-sandbox-system"
	return NewHandler(store, config, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func notFound(name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Group: "aks-sandbox.azure.com", Resource: "sandboxassignments"}, name)
}

func validCreateRequest() *http.Request {
	return httptest.NewRequest(http.MethodPost, "/opensandbox/sandboxes", stringsReader(`{
		"extensions":{"aks-sandbox.azure.com/template":"python-kata-reader-v2"}
	}`))
}

func stringsReader(value string) io.Reader { return bytes.NewBufferString(value) }
