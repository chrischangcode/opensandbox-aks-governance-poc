package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
)

const (
	testTenantID = "11111111-1111-1111-1111-111111111111"
	testUserID   = "22222222-2222-2222-2222-222222222222"
	testAdminID  = "33333333-3333-3333-3333-333333333333"
)

func TestGovernanceRoutesRequireAdminRole(t *testing.T) {
	governanceDashboard, handler := newGovernanceTestHandler(t)
	_ = governanceDashboard
	user := authenticatedIdentity{TenantID: testTenantID, ObjectID: testUserID, Name: "Requester", Roles: []string{"OpenSandbox.User"}}

	response := serveGovernance(handler, http.MethodGet, "/admin", nil, user, "csrf")
	if response.Code != http.StatusForbidden {
		t.Fatalf("admin response = %d", response.Code)
	}
	response = serveGovernance(handler, http.MethodPost, "/admin/bundles", url.Values{"csrf": {"csrf"}}, user, "csrf")
	if response.Code != http.StatusForbidden {
		t.Fatalf("admin bundle response = %d", response.Code)
	}
	response = serveGovernance(handler, http.MethodGet, "/access", nil, user, "csrf")
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Sandbox access requests") {
		t.Fatalf("access response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestGovernanceCSRFRejectsCrossSiteMutation(t *testing.T) {
	_, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	user := authenticatedIdentity{TenantID: testTenantID, ObjectID: testUserID, Name: "Requester"}
	form := url.Values{"csrf": {"wrong"}, "eventName": {"denied-a"}, "reason": {"Need temporary repository access."}, "durationMinutes": {"30"}}
	response := serveGovernance(handler, http.MethodPost, "/access/requests", form, user, "csrf")
	if response.Code != http.StatusForbidden {
		t.Fatalf("CSRF response = %d body=%s", response.Code, response.Body.String())
	}

	request := governanceRequest(http.MethodPost, "/access/requests", form, user, "wrong")
	request.Header.Set("Origin", "https://evil.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("origin response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestGovernanceCreatesRequestFromDeniedEventAndAuthenticatedIdentity(t *testing.T) {
	governanceDashboard, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	user := authenticatedIdentity{TenantID: testTenantID, ObjectID: testUserID, Name: "Requester", Roles: []string{"OpenSandbox.User"}}
	form := url.Values{
		"csrf": {"csrf"}, "eventName": {"denied-a"},
		"reason": {"Need temporary repository access."}, "durationMinutes": {"30"},
	}
	response := serveGovernance(handler, http.MethodPost, "/access/requests", form, user, "csrf")
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create response = %d body=%s", response.Code, response.Body.String())
	}
	list, err := governanceDashboard.client.Resource(dashboardRequestsGVR).Namespace("aks-sandbox-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("requests = %d", len(list.Items))
	}
	request := &assignmentv1alpha1.SandboxAccessRequest{}
	if err := fromUnstructured(&list.Items[0], request); err != nil {
		t.Fatal(err)
	}
	if request.Spec.Requester.TenantID != testTenantID || request.Spec.Requester.ObjectID != testUserID ||
		request.Spec.Requester.DisplayName != "Requester" || request.Spec.Requester.LogicalTenant != "tenant-a" ||
		request.Spec.Requester.Team != "team-a" {
		t.Fatalf("requester = %+v", request.Spec.Requester)
	}
	if request.Spec.AssignmentRef.UID != types.UID("assignment-uid") || request.Spec.BasePolicyRevision != "sha256:0123456789" ||
		request.Spec.PodUID != types.UID("pod-uid") ||
		request.Spec.Backend != "cachew" || request.Spec.Method != "GET" || request.Spec.Host != "cachew.example.test" ||
		request.Spec.Path != "/repo/info/refs" || request.Status.State != assignmentv1alpha1.SandboxAccessRequestPending {
		t.Fatalf("request = %+v", request)
	}
}

func TestGovernanceApproveAndDenyUseAuthenticatedAdmin(t *testing.T) {
	t.Run("approve", func(t *testing.T) {
		request := pendingDashboardAccessRequest("access-a")
		governanceDashboard, handler := newGovernanceTestHandler(t, append(governanceFixtureObjects(t), request)...)
		now := time.Date(2026, 8, 15, 12, 0, 0, 0, time.UTC)
		governanceDashboard.now = func() time.Time { return now }
		admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
		form := url.Values{"csrf": {"csrf"}, "decisionReason": {"Approved for one repository refresh."}, "durationMinutes": {"30"}}
		response := serveGovernance(handler, http.MethodPost, "/admin/requests/access-a/approve", form, admin, "csrf")
		if response.Code != http.StatusSeeOther {
			t.Fatalf("approve response = %d body=%s", response.Code, response.Body.String())
		}

		updated := getDashboardAccessRequest(t, governanceDashboard, "access-a")
		if updated.Status.State != assignmentv1alpha1.SandboxAccessRequestApproved || updated.Status.Approver == nil ||
			updated.Status.Approver.ObjectID != testAdminID || !updated.Status.ExpiresAt.Time.Equal(now.Add(30*time.Minute)) {
			t.Fatalf("approved status = %+v", updated.Status)
		}
	})

	t.Run("deny", func(t *testing.T) {
		request := pendingDashboardAccessRequest("access-b")
		governanceDashboard, handler := newGovernanceTestHandler(t, append(governanceFixtureObjects(t), request)...)
		admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
		form := url.Values{"csrf": {"csrf"}, "decisionReason": {"Request is broader than needed."}}
		response := serveGovernance(handler, http.MethodPost, "/admin/requests/access-b/deny", form, admin, "csrf")
		if response.Code != http.StatusSeeOther {
			t.Fatalf("deny response = %d body=%s", response.Code, response.Body.String())
		}
		updated := getDashboardAccessRequest(t, governanceDashboard, "access-b")
		if updated.Status.State != assignmentv1alpha1.SandboxAccessRequestDenied || updated.Status.Approver == nil ||
			updated.Status.Approver.ObjectID != testAdminID || updated.Status.ExpiresAt != nil {
			t.Fatalf("denied status = %+v", updated.Status)
		}
	})
}

func TestGovernanceAdminCreatesImmutableSandboxTemplate(t *testing.T) {
	governanceDashboard, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
	form := url.Values{
		"csrf": {"csrf"}, "name": {"python-reader-v1"}, "displayName": {"Python reader"},
		"description": {"Governed Python sandbox."}, "image": {"python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		"entrypoint": {`["tail","-f","/dev/null"]`}, "capabilityBundle": {"coding"},
		"cpu": {"500m"}, "memory": {"512Mi"}, "timeoutSeconds": {"1800"}, "enabled": {"true"},
	}
	response := serveGovernance(handler, http.MethodPost, "/admin/templates", form, admin, "csrf")
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create template response = %d body=%s", response.Code, response.Body.String())
	}
	object, err := governanceDashboard.client.Resource(dashboardTemplatesGVR).Namespace("aks-sandbox-system").Get(
		context.Background(), "python-reader-v1", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	image, _, _ := unstructured.NestedString(object.Object, "spec", "image")
	bundle, _, _ := unstructured.NestedString(object.Object, "spec", "capabilityBundleRef", "name")
	revision, _, _ := unstructured.NestedString(object.Object, "spec", "capabilityBundleRef", "policyRevision")
	timeout, _, _ := unstructured.NestedInt64(object.Object, "spec", "timeoutSeconds")
	if image != "python@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" ||
		bundle != "coding" || !strings.HasPrefix(revision, "sha256:") || timeout != 1800 {
		t.Fatalf("created template = %#v", object.Object["spec"])
	}
}

func TestGovernanceAdminCreatesCapabilityBundleFromExactRules(t *testing.T) {
	governanceDashboard, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
	form := url.Values{
		"csrf": {"csrf"}, "name": {"web-reader-v1"}, "displayName": {"Approved web reader"},
		"logicalTenant": {"tenant-a"}, "team": {"readers"}, "permissionLevel": {"reader"},
		"egressRules":     {"external-web GET https://example.com/docs\nexternal-web GET https://example.com/reference"},
		"allowedCommands": {"uname -a && python --version\ngo test ./internal/..."},
		"validationRules": {"internal/ => go test ./internal/..."},
	}
	response := serveGovernance(handler, http.MethodPost, "/admin/bundles", form, admin, "csrf")
	if response.Code != http.StatusSeeOther {
		t.Fatalf("create bundle response = %d body=%s", response.Code, response.Body.String())
	}
	object, err := governanceDashboard.client.Resource(dashboardBundlesGVR).Namespace("aks-sandbox-system").Get(
		context.Background(), "web-reader-v1", metav1.GetOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}
	bundle := &assignmentv1alpha1.CapabilityBundle{}
	if err := fromUnstructured(object, bundle); err != nil {
		t.Fatal(err)
	}
	policy := bundle.Spec.Egress.Agentgateway["external-web"].Allow
	if !strings.Contains(policy, `request.host == "example.com"`) ||
		!strings.Contains(policy, `request.path == "/docs"`) ||
		!strings.Contains(policy, `request.path == "/reference"`) ||
		len(bundle.Spec.Harness.CommandPolicy) != 2 ||
		bundle.Spec.Harness.CommandPolicy[0].Pattern != `^uname -a && python --version$` ||
		len(bundle.Spec.Harness.ValidationRules) != 1 ||
		bundle.Spec.Harness.ValidationRules[0].PathPrefix != "internal/" ||
		bundle.Spec.Harness.ValidationRules[0].Command != "go test ./internal/..." ||
		bundle.Spec.Governance.DisplayName != "Approved web reader" {
		t.Fatalf("created bundle = %+v", bundle.Spec)
	}
}

func TestGovernanceCapabilityBundleRejectsNonExactURL(t *testing.T) {
	_, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
	form := url.Values{
		"csrf": {"csrf"}, "name": {"web-reader-v1"}, "displayName": {"Approved web reader"},
		"logicalTenant": {"tenant-a"}, "team": {"readers"}, "permissionLevel": {"reader"},
		"egressRules": {"external-web GET https://example.com/docs?token=not-allowed"},
	}

	response := serveGovernance(handler, http.MethodPost, "/admin/bundles", form, admin, "csrf")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("create bundle response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestGovernanceCapabilityBundleRejectsExplicitPort(t *testing.T) {
	_, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
	form := url.Values{
		"csrf": {"csrf"}, "name": {"web-reader-v1"}, "displayName": {"Approved web reader"},
		"logicalTenant": {"tenant-a"}, "team": {"readers"}, "permissionLevel": {"reader"},
		"egressRules": {"external-web GET https://example.com:8443/docs"},
	}
	response := serveGovernance(handler, http.MethodPost, "/admin/bundles", form, admin, "csrf")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("create bundle response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestGovernancePolicySimulationDoesNotCreateBundle(t *testing.T) {
	governanceDashboard, handler := newGovernanceTestHandler(t, governanceFixtureObjects(t)...)
	admin := authenticatedIdentity{TenantID: testTenantID, ObjectID: testAdminID, Name: "Administrator", Roles: []string{"OpenSandbox.Admin"}}
	form := url.Values{
		"csrf":        {"csrf"},
		"egressRules": {"cachew GET https://cachew.example.test/repo/info/refs"},
	}
	response := serveGovernance(handler, http.MethodPost, "/admin/bundles/simulate", form, admin, "csrf")
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "1</strong> of 1 historical denials") ||
		!strings.Contains(response.Body.String(), "tenant-a / team-a") {
		t.Fatalf("simulation response = %d body=%s", response.Code, response.Body.String())
	}
	list, err := governanceDashboard.client.Resource(dashboardBundlesGVR).Namespace("aks-sandbox-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("simulation mutated bundles: %d", len(list.Items))
	}
}

func newGovernanceTestHandler(t *testing.T, objects ...runtime.Object) (*governanceDashboard, http.Handler) {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClient(scheme, objects...)
	cfg := config{
		basePath: "/dashboard", assignmentNamespace: "aks-sandbox-system",
		redirectURI: "https://dashboard.example/dashboard/auth/redirect/", adminRole: "OpenSandbox.Admin",
	}
	governanceDashboard, err := newGovernanceDashboard(client, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	governanceDashboard.RegisterRoutes(mux)
	return governanceDashboard, mux
}

func serveGovernance(handler http.Handler, method, path string, form url.Values, identity authenticatedIdentity, csrf string) *httptest.ResponseRecorder {
	request := governanceRequest(method, path, form, identity, csrf)
	if method == http.MethodPost {
		request.Header.Set("Origin", "https://dashboard.example")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func governanceRequest(method, path string, form url.Values, identity authenticatedIdentity, csrf string) *http.Request {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	request := httptest.NewRequest(method, "https://dashboard.example"+path, body)
	if form != nil {
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	ctx := context.WithValue(request.Context(), identityContextKey{}, identity)
	ctx = context.WithValue(ctx, csrfContextKey{}, csrf)
	return request.WithContext(ctx)
}

func governanceFixtureObjects(t *testing.T) []runtime.Object {
	t.Helper()
	bundle := &assignmentv1alpha1.CapabilityBundle{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
		ObjectMeta: metav1.ObjectMeta{Name: "coding", Namespace: "aks-sandbox-system", UID: types.UID("bundle-uid")},
		Spec: assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{
			LogicalTenant: "tenant-a", Team: "team-a", PermissionLevel: "contributor", DisplayName: "Team A contributor",
		}},
	}
	assignmentObject := &assignmentv1alpha1.SandboxAssignment{
		TypeMeta: metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAssignment"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "assignment-a", Namespace: "aks-sandbox-system", UID: types.UID("assignment-uid"),
			Annotations: map[string]string{assignment.SandboxIDAnnotation: "sandbox-a"},
		},
		Spec: assignmentv1alpha1.SandboxAssignmentSpec{CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{Name: "coding"}},
		Status: assignmentv1alpha1.SandboxAssignmentStatus{
			PodRef: &assignmentv1alpha1.ObjectReference{Name: "pod-a", UID: types.UID("pod-uid")},
			ResolvedCapabilityBundle: &assignmentv1alpha1.ResolvedCapabilityBundle{
				Name: "coding", UID: types.UID("bundle-uid"), PolicyRevision: "sha256:0123456789",
			},
			Conditions: []metav1.Condition{{Type: "Ready", Status: metav1.ConditionTrue}},
		},
	}
	event := &assignmentv1alpha1.SandboxEgressEvent{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxEgressEvent"},
		ObjectMeta: metav1.ObjectMeta{Name: "denied-a", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxEgressEventSpec{
			Timestamp: metav1.NewTime(time.Now().UTC()),
			AssignmentRef: assignmentv1alpha1.AssignmentReference{
				Name: "assignment-a", UID: types.UID("assignment-uid"),
			},
			SandboxID: "sandbox-a", PodUID: types.UID("pod-uid"),
			CapabilityBundleName: "coding", CapabilityBundleRevision: "sha256:0123456789",
			LogicalTenant: "tenant-a", Team: "team-a", PermissionLevel: "contributor",
			Backend: "cachew", Method: "GET", Host: "cachew.example.test", Path: "/repo/info/refs",
			Allowed: false, Reason: "backend is not granted", DecisionSource: assignmentv1alpha1.DecisionSourceDeny,
		},
	}
	tenantPolicy := &assignmentv1alpha1.SandboxTenantPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTenantPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a-v1", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxTenantPolicySpec{
			LogicalTenant: "tenant-a", WorkloadNamespace: "opensandbox",
			AllowedCapabilityBundles: []string{"coding"}, AllowedCapabilityBundlePrefixes: []string{"demo-"},
			MaxConcurrentSandboxes: 4,
			MaxLifetimeSeconds:     3600, MaxAccessRequestDurationSeconds: 3600,
			MaxCPU: "2", MaxMemory: "2Gi", Enabled: true,
		},
	}
	return []runtime.Object{bundle, assignmentObject, event, tenantPolicy}
}

func pendingDashboardAccessRequest(name string) *assignmentv1alpha1.SandboxAccessRequest {
	return &assignmentv1alpha1.SandboxAccessRequest{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAccessRequest"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxAccessRequestSpec{
			AssignmentRef:            assignmentv1alpha1.AssignmentReference{Name: "assignment-a", UID: types.UID("assignment-uid")},
			PodUID:                   types.UID("pod-uid"),
			BasePolicyRevision:       "sha256:0123456789",
			Backend:                  "cachew",
			Method:                   "GET",
			Host:                     "cachew.example.test",
			Path:                     "/repo/info/refs",
			Reason:                   "Need temporary repository access.",
			RequestedDurationSeconds: 3600,
			Requester: assignmentv1alpha1.GovernanceIdentity{
				TenantID: testTenantID, ObjectID: testUserID, DisplayName: "Requester",
			},
		},
		Status: assignmentv1alpha1.SandboxAccessRequestStatus{State: assignmentv1alpha1.SandboxAccessRequestPending},
	}
}

func getDashboardAccessRequest(t *testing.T, dashboard *governanceDashboard, name string) *assignmentv1alpha1.SandboxAccessRequest {
	t.Helper()
	object, err := dashboard.client.Resource(dashboardRequestsGVR).Namespace("aks-sandbox-system").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	request := &assignmentv1alpha1.SandboxAccessRequest{}
	if err := fromUnstructured(object, request); err != nil {
		t.Fatal(err)
	}
	return request
}
