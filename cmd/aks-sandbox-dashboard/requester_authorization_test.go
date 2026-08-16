package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	osbclient "github.com/bahe-msft/osb-dashboard/opensandbox"
	"github.com/coder/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
)

const testTenantBUserID = "44444444-4444-4444-4444-444444444444"

func TestRequesterLifecycleMiddlewareAuthorizesConfiguredTemplateTenant(t *testing.T) {
	fakeClient := &fakeDashboardClient{
		sandboxes: []osbclient.Sandbox{{ID: "sandbox-a"}},
		snapshots: []osbclient.Snapshot{{ID: "snapshot-a", SandboxID: "sandbox-a"}},
	}
	authorizer := newRequesterTestAuthorizer(t, fakeClient)
	handler := authorizer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	response := serveRequesterLifecycle(handler, http.MethodPost, "/dashboard/dashboard/sandboxes", authenticatedIdentity{
		TenantID: testTenantID, ObjectID: testUserID, Name: "Requester A",
	})
	if response.Code != http.StatusNoContent {
		t.Fatalf("authorized create response = %d body=%s", response.Code, response.Body.String())
	}

	response = serveRequesterLifecycle(handler, http.MethodPost, "/dashboard/dashboard/sandboxes", authenticatedIdentity{
		TenantID: testTenantID, ObjectID: testTenantBUserID, Name: "Requester B",
	})
	if response.Code != http.StatusForbidden {
		t.Fatalf("cross-tenant create response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestRequesterLifecycleMiddlewareRejectsAggregateViewsWithUnauthorizedData(t *testing.T) {
	t.Run("sandboxes", func(t *testing.T) {
		fakeClient := &fakeDashboardClient{
			sandboxes: []osbclient.Sandbox{
				{ID: "sandbox-a", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-a"}},
				{ID: "sandbox-b", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-b"}},
			},
			snapshots: []osbclient.Snapshot{{ID: "snapshot-a", SandboxID: "sandbox-a"}},
		}
		authorizer := newRequesterTestAuthorizer(t, fakeClient)
		handler := authorizer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		response := serveRequesterLifecycle(handler, http.MethodGet, "/dashboard/", authenticatedIdentity{
			TenantID: testTenantID, ObjectID: testUserID, Name: "Requester A",
		})
		if response.Code != http.StatusForbidden {
			t.Fatalf("mixed-tenant list response = %d body=%s", response.Code, response.Body.String())
		}
	})

	t.Run("snapshots", func(t *testing.T) {
		fakeClient := &fakeDashboardClient{
			sandboxes: []osbclient.Sandbox{{ID: "sandbox-a"}},
			snapshots: []osbclient.Snapshot{
				{ID: "snapshot-a", SandboxID: "sandbox-a"},
				{ID: "snapshot-b", SandboxID: "sandbox-b"},
			},
		}
		authorizer := newRequesterTestAuthorizer(t, fakeClient)
		handler := authorizer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}))

		response := serveRequesterLifecycle(handler, http.MethodGet, "/dashboard/", authenticatedIdentity{
			TenantID: testTenantID, ObjectID: testUserID, Name: "Requester A",
		})
		if response.Code != http.StatusForbidden {
			t.Fatalf("mixed-snapshot list response = %d body=%s", response.Code, response.Body.String())
		}
	})
}

func TestRequesterLifecycleMiddlewareAuthorizesSandboxSpecificRoutes(t *testing.T) {
	fakeClient := &fakeDashboardClient{
		sandboxes: []osbclient.Sandbox{
			{ID: "sandbox-a", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-a"}},
			{ID: "sandbox-b", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-b"}},
		},
		snapshots: []osbclient.Snapshot{{ID: "snapshot-a", SandboxID: "sandbox-a"}},
	}
	authorizer := newRequesterTestAuthorizer(t, fakeClient)
	handler := authorizer.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	requesterA := authenticatedIdentity{TenantID: testTenantID, ObjectID: testUserID, Name: "Requester A"}

	for _, route := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/dashboard/dashboard/sandboxes/sandbox-a/terminal/pty"},
		{method: http.MethodPost, path: "/dashboard/dashboard/sandboxes/sandbox-a/pause"},
		{method: http.MethodPost, path: "/dashboard/dashboard/sandboxes/sandbox-a/resume"},
		{method: http.MethodDelete, path: "/dashboard/dashboard/sandboxes/sandbox-a"},
		{method: http.MethodGet, path: "/dashboard/sandboxes/sandbox-a"},
	} {
		response := serveRequesterLifecycle(handler, route.method, route.path, requesterA)
		if response.Code != http.StatusNoContent {
			t.Fatalf("%s %s response = %d body=%s", route.method, route.path, response.Code, response.Body.String())
		}
	}

	for _, route := range []struct {
		method string
		path   string
	}{
		{method: http.MethodGet, path: "/dashboard/dashboard/sandboxes/sandbox-b/terminal/pty"},
		{method: http.MethodPost, path: "/dashboard/dashboard/sandboxes/sandbox-b/pause"},
		{method: http.MethodPost, path: "/dashboard/dashboard/sandboxes/sandbox-b/resume"},
		{method: http.MethodDelete, path: "/dashboard/dashboard/sandboxes/sandbox-b"},
		{method: http.MethodGet, path: "/dashboard/sandboxes/sandbox-b"},
	} {
		response := serveRequesterLifecycle(handler, route.method, route.path, requesterA)
		if response.Code != http.StatusForbidden {
			t.Fatalf("cross-tenant %s %s response = %d body=%s", route.method, route.path, response.Code, response.Body.String())
		}
	}
}

func TestAuthorizedDashboardClientFiltersRequesterScopedDataAndActions(t *testing.T) {
	fakeClient := &fakeDashboardClient{
		sandboxes: []osbclient.Sandbox{
			{ID: "sandbox-a", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-a"}},
			{ID: "sandbox-b", Metadata: map[string]string{assignment.AssignmentLabel: "assignment-b"}},
		},
		snapshots: []osbclient.Snapshot{
			{ID: "snapshot-a", SandboxID: "sandbox-a"},
			{ID: "snapshot-b", SandboxID: "sandbox-b"},
		},
	}
	authorizer := newRequesterTestAuthorizer(t, fakeClient)
	client := authorizer.WrapClient(fakeClient)
	ctx := context.WithValue(context.Background(), identityContextKey{}, authenticatedIdentity{
		TenantID: testTenantID, ObjectID: testUserID, Name: "Requester A",
	})

	sandboxes, err := client.ListSandboxes(ctx)
	if err != nil {
		t.Fatalf("ListSandboxes() error = %v", err)
	}
	if len(sandboxes) != 1 || sandboxes[0].ID != "sandbox-a" {
		t.Fatalf("ListSandboxes() = %+v", sandboxes)
	}

	snapshots, err := client.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("ListSnapshots() error = %v", err)
	}
	if len(snapshots) != 1 || snapshots[0].ID != "snapshot-a" {
		t.Fatalf("ListSnapshots() = %+v", snapshots)
	}

	if err := client.PauseSandbox(ctx, "sandbox-a"); err != nil {
		t.Fatalf("PauseSandbox() error = %v", err)
	}
	if len(fakeClient.pausedSandboxes) != 1 || fakeClient.pausedSandboxes[0] != "sandbox-a" {
		t.Fatalf("paused sandboxes = %+v", fakeClient.pausedSandboxes)
	}

	if err := client.DeleteSandbox(ctx, osbclient.Sandbox{ID: "sandbox-b"}); !errors.Is(err, errRequesterForbidden) {
		t.Fatalf("DeleteSandbox() error = %v", err)
	}
	if _, err := client.OpenPTY(ctx, "sandbox-b"); !errors.Is(err, errRequesterForbidden) {
		t.Fatalf("OpenPTY() error = %v", err)
	}
}

func newRequesterTestAuthorizer(t *testing.T, sandboxReader osbclient.Reader) *requesterLifecycleAuthorizer {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClient(scheme, requesterAuthorizationObjects()...)
	cfg := config{
		assignmentNamespace: "aks-sandbox-system",
		basePath:            "/dashboard",
		sandboxTemplate:     "python-kata-reader-v2",
	}
	authorizer, err := newRequesterLifecycleAuthorizer(client, sandboxReader, cfg)
	if err != nil {
		t.Fatal(err)
	}
	return authorizer
}

func requesterAuthorizationObjects() []runtime.Object {
	return []runtime.Object{
		testPrincipalBinding("requester-a", testUserID, []string{"tenant-a"}, nil),
		testPrincipalBinding("requester-b", testTenantBUserID, []string{"tenant-b"}, nil),
		&assignmentv1alpha1.CapabilityBundle{
			TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
			ObjectMeta: metav1.ObjectMeta{Name: "team-a-bundle", Namespace: "aks-sandbox-system", UID: types.UID("bundle-a-uid")},
			Spec: assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{
				LogicalTenant: "tenant-a", Team: "team-a", PermissionLevel: "reader", DisplayName: "Tenant A reader",
			}},
		},
		&assignmentv1alpha1.CapabilityBundle{
			TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
			ObjectMeta: metav1.ObjectMeta{Name: "team-b-bundle", Namespace: "aks-sandbox-system", UID: types.UID("bundle-b-uid")},
			Spec: assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{
				LogicalTenant: "tenant-b", Team: "team-b", PermissionLevel: "reader", DisplayName: "Tenant B reader",
			}},
		},
		&assignmentv1alpha1.SandboxTemplate{
			TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTemplate"},
			ObjectMeta: metav1.ObjectMeta{Name: "python-kata-reader-v2", Namespace: "aks-sandbox-system"},
			Spec: assignmentv1alpha1.SandboxTemplateSpec{
				DisplayName: "Python Kata reader",
				Image:       "python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				Entrypoint:  []string{"tail", "-f", "/dev/null"},
				CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{
					Name:           "team-a-bundle",
					PolicyRevision: "sha256:template",
				},
				Resources:      assignmentv1alpha1.SandboxTemplateResources{CPU: "500m", Memory: "512Mi"},
				TimeoutSeconds: 1800,
				Enabled:        true,
			},
		},
		&assignmentv1alpha1.SandboxAssignment{
			TypeMeta: metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAssignment"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "assignment-a", Namespace: "aks-sandbox-system", UID: types.UID("assignment-a-uid"),
				Annotations: map[string]string{assignment.SandboxIDAnnotation: "sandbox-a"},
				Labels:      map[string]string{assignment.SandboxIDLabel: "sandbox-a"},
			},
			Spec: assignmentv1alpha1.SandboxAssignmentSpec{
				LogicalTenant: "tenant-a",
				CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{
					Name: "team-a-bundle",
				},
			},
		},
		&assignmentv1alpha1.SandboxAssignment{
			TypeMeta: metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAssignment"},
			ObjectMeta: metav1.ObjectMeta{
				Name: "assignment-b", Namespace: "aks-sandbox-system", UID: types.UID("assignment-b-uid"),
				Annotations: map[string]string{assignment.SandboxIDAnnotation: "sandbox-b"},
				Labels:      map[string]string{assignment.SandboxIDLabel: "sandbox-b"},
			},
			Spec: assignmentv1alpha1.SandboxAssignmentSpec{
				LogicalTenant: "tenant-b",
				CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{
					Name: "team-b-bundle",
				},
			},
		},
	}
}

func serveRequesterLifecycle(handler http.Handler, method, path string, identity authenticatedIdentity) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, "https://dashboard.example"+path, nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, identity))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

type fakeDashboardClient struct {
	sandboxes []osbclient.Sandbox
	snapshots []osbclient.Snapshot

	createdSnapshots []string
	deletedSnapshots []string
	deletedSandboxes []string
	pausedSandboxes  []string
	resumedSandboxes []string
	openedPTY        []string
}

func (f *fakeDashboardClient) ListSandboxes(context.Context) ([]osbclient.Sandbox, error) {
	return append([]osbclient.Sandbox(nil), f.sandboxes...), nil
}

func (f *fakeDashboardClient) ListSnapshots(context.Context) ([]osbclient.Snapshot, error) {
	return append([]osbclient.Snapshot(nil), f.snapshots...), nil
}

func (f *fakeDashboardClient) GetSnapshot(_ context.Context, snapshotID string) (osbclient.Snapshot, error) {
	for _, snapshot := range f.snapshots {
		if snapshot.ID == snapshotID {
			return snapshot, nil
		}
	}
	return osbclient.Snapshot{}, errors.New("snapshot not found")
}

func (*fakeDashboardClient) ListSandboxNodeLoads(context.Context) ([]osbclient.SandboxNodeLoad, error) {
	return nil, nil
}

func (*fakeDashboardClient) ListPodEvents(context.Context, string) ([]osbclient.SandboxEvent, error) {
	return nil, nil
}

func (*fakeDashboardClient) ListRecentSandboxEvents(context.Context, []osbclient.Sandbox) ([]osbclient.SandboxEvent, error) {
	return nil, nil
}

func (*fakeDashboardClient) CreateSandbox(context.Context, osbclient.CreateSandboxRequest) (osbclient.Sandbox, error) {
	return osbclient.Sandbox{ID: "sandbox-created"}, nil
}

func (f *fakeDashboardClient) DeleteSandbox(_ context.Context, sandbox osbclient.Sandbox) error {
	f.deletedSandboxes = append(f.deletedSandboxes, sandbox.ID)
	return nil
}

func (f *fakeDashboardClient) PauseSandbox(_ context.Context, sandboxID string) error {
	f.pausedSandboxes = append(f.pausedSandboxes, sandboxID)
	return nil
}

func (f *fakeDashboardClient) ResumeSandbox(_ context.Context, sandboxID string) error {
	f.resumedSandboxes = append(f.resumedSandboxes, sandboxID)
	return nil
}

func (f *fakeDashboardClient) CreateSnapshot(_ context.Context, sandboxID, _ string) (osbclient.Snapshot, error) {
	f.createdSnapshots = append(f.createdSnapshots, sandboxID)
	return osbclient.Snapshot{ID: "snapshot-created", SandboxID: sandboxID}, nil
}

func (f *fakeDashboardClient) DeleteSnapshot(_ context.Context, snapshotID string) error {
	f.deletedSnapshots = append(f.deletedSnapshots, snapshotID)
	return nil
}

func (f *fakeDashboardClient) OpenPTY(_ context.Context, sandboxID string) (*websocket.Conn, error) {
	f.openedPTY = append(f.openedPTY, sandboxID)
	return nil, nil
}

func (*fakeDashboardClient) RunCommand(context.Context, string, string) (osbclient.CommandResult, error) {
	return osbclient.CommandResult{}, nil
}

func (*fakeDashboardClient) Close() error { return nil }
