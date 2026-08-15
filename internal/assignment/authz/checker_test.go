package authz

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	"github.com/golang-jwt/jwt/v5"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func TestJWTExpirationUsesJWTParser(t *testing.T) {
	expiresAt := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Second)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiresAt)}).SignedString([]byte("test-key"))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := jwtExpiration(token)
	if !ok || !got.Equal(expiresAt) {
		t.Fatalf("jwtExpiration() = %v, %v; want %v, true", got, ok, expiresAt)
	}
	if _, ok := jwtExpiration("not-a-jwt"); ok {
		t.Fatal("invalid JWT accepted")
	}
}

func TestKubernetesCheckerAllowsExactReadyPodAndBundle(t *testing.T) {
	checker := newCheckerFixture(t)
	decision, err := checker.Check(context.Background(), CheckInput{
		Backend: "goproxy", IdentityToken: "pod-token", Method: "GET", Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestKubernetesCheckerDeniesTokenReplayFromAnotherPodIP(t *testing.T) {
	checker := newCheckerFixture(t)
	decision, err := checker.Check(context.Background(), CheckInput{
		Backend: "goproxy", IdentityToken: "pod-token", Method: "GET", Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.99",
	})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.Reason != "request source does not match token Pod" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestSourceMatchesPodNormalizesAddresses(t *testing.T) {
	pod := &corev1.Pod{Status: corev1.PodStatus{PodIPs: []corev1.PodIP{{IP: "10.2.3.4"}, {IP: "2001:db8::4"}}}}
	for _, value := range []string{"10.2.3.4", "::ffff:10.2.3.4", "2001:db8::4"} {
		address, err := netip.ParseAddr(value)
		if err != nil {
			t.Fatal(err)
		}
		if !sourceMatchesPod(address.Unmap(), pod) {
			t.Fatalf("source %s did not match", value)
		}
	}
	address := netip.MustParseAddr("10.2.3.5")
	if sourceMatchesPod(address, pod) {
		t.Fatal("unexpected source matched")
	}
}

func TestKubernetesCheckerCachesOnlyTokenReviewIdentity(t *testing.T) {
	checker := newCheckerFixture(t)
	input := CheckInput{Backend: "goproxy", IdentityToken: "pod-token", Method: "GET", Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.4"}
	for range 2 {
		decision, err := checker.Check(context.Background(), input)
		if err != nil || !decision.Allow {
			t.Fatalf("decision=%#v err=%v", decision, err)
		}
	}
	if checker.metrics.tokenReviews.Load() != 1 || checker.metrics.tokenCacheHits.Load() != 1 {
		t.Fatalf("reviews=%d hits=%d", checker.metrics.tokenReviews.Load(), checker.metrics.tokenCacheHits.Load())
	}
}

func TestKubernetesCheckerDeniesStaleCachesBeforeTokenReview(t *testing.T) {
	checker := newCheckerFixture(t)
	checker.lastFreshUnixNano.Store(time.Now().Add(-freshnessLimit - time.Second).UnixNano())
	decision, err := checker.Check(context.Background(), CheckInput{Backend: "goproxy", IdentityToken: "pod-token", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.Reason != "authorization cache is stale" || checker.metrics.tokenReviews.Load() != 0 {
		t.Fatalf("decision=%#v reviews=%d", decision, checker.metrics.tokenReviews.Load())
	}
}

func TestKubernetesCheckerDeniesFalseAndMissingBackend(t *testing.T) {
	checker := newCheckerFixture(t)
	for name, input := range map[string]CheckInput{
		"false":   {Backend: "goproxy", IdentityToken: "pod-token", Method: "POST", Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.4"},
		"missing": {Backend: "aoai", IdentityToken: "pod-token", Method: "GET", Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.4"},
	} {
		t.Run(name, func(t *testing.T) {
			decision, err := checker.Check(context.Background(), input)
			if err != nil {
				t.Fatal(err)
			}
			if decision.Allow {
				t.Fatalf("decision = %#v", decision)
			}
		})
	}
}

func TestKubernetesCheckerAllowsApprovedExactAccessRequest(t *testing.T) {
	checker := newCheckerFixture(t)
	assignmentObjects, err := checker.assignments.GetIndexer().ByIndex(assignmentPodUIDIndex, "pod-uid")
	if err != nil || len(assignmentObjects) != 1 {
		t.Fatalf("assignment objects = %d, err=%v", len(assignmentObjects), err)
	}
	revision, _, _ := unstructured.NestedString(
		assignmentObjects[0].(*unstructured.Unstructured).Object,
		"status", "resolvedCapabilityBundle", "policyRevision",
	)
	now := time.Now().UTC()
	request := accessRequestObject(t, "access-a", revision, now.Add(time.Hour))
	request.Spec.Method = "POST"
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := checker.dynamic.Resource(checkerAccessRequestsGVR).Namespace("aks-sandbox-system").Create(
		context.Background(), &unstructured.Unstructured{Object: object}, metav1.CreateOptions{},
	); err != nil {
		t.Fatal(err)
	}
	if err := wait.PollUntilContextTimeout(context.Background(), 10*time.Millisecond, 2*time.Second, true, func(context.Context) (bool, error) {
		objects, err := checker.accessRequests.GetIndexer().ByIndex(accessAssignmentUIDIndex, "assignment-uid")
		return len(objects) == 1, err
	}); err != nil {
		t.Fatal(err)
	}

	decision, err := checker.Check(context.Background(), CheckInput{
		Backend: "goproxy", IdentityToken: "pod-token", Method: "POST", Host: "cachew.example.test",
		Path: "/module", Headers: map[string]string{}, SourceAddress: "10.2.3.4",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allow || decision.Source != assignmentv1alpha1.DecisionSourceAccessRequest || decision.AccessRequestName != "access-a" {
		t.Fatalf("decision = %#v", decision)
	}
}

func TestMatchAccessGrantExactStaleExpiredAndAmbiguous(t *testing.T) {
	now := time.Now().UTC()
	decision := Decision{
		AssignmentName: "assignment-a", AssignmentUID: "assignment-uid",
		CapabilityBundleRevision: "sha256:0123456789",
		Backend:                  "goproxy", Method: "GET", Host: "cachew.example.test", Path: "/module",
	}
	exact := accessRequestUnstructured(t, accessRequestObject(t, "access-a", decision.CapabilityBundleRevision, now.Add(time.Hour)))

	name, _, granted, err := matchAccessGrantObjects([]any{exact}, decision, now)
	if err != nil || !granted || name != "access-a" {
		t.Fatalf("exact match = name=%q granted=%v err=%v", name, granted, err)
	}

	stale := exact.DeepCopy()
	_ = unstructured.SetNestedField(stale.Object, "sha256:stale", "spec", "basePolicyRevision")
	if _, _, granted, err := matchAccessGrantObjects([]any{stale}, decision, now); err != nil || granted {
		t.Fatalf("stale grant = granted=%v err=%v", granted, err)
	}

	expired := accessRequestUnstructured(t, accessRequestObject(t, "access-expired", decision.CapabilityBundleRevision, now.Add(-time.Minute)))
	if _, reason, granted, err := matchAccessGrantObjects([]any{expired}, decision, now); err != nil || granted || !strings.Contains(reason, "expired") {
		t.Fatalf("expired grant = granted=%v reason=%q err=%v", granted, reason, err)
	}

	second := accessRequestUnstructured(t, accessRequestObject(t, "access-b", decision.CapabilityBundleRevision, now.Add(time.Hour)))
	if _, reason, granted, err := matchAccessGrantObjects([]any{exact, second}, decision, now); err != nil || granted || !strings.Contains(reason, "multiple") {
		t.Fatalf("ambiguous grant = granted=%v reason=%q err=%v", granted, reason, err)
	}
}

func TestKubernetesCheckerDeniesUnboundToken(t *testing.T) {
	checker := newCheckerFixture(t)
	checker.kube.(*kubernetesfake.Clientset).PrependReactor("create", "tokenreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: true, Audiences: []string{"aks-sandbox-capability-gateway"},
			User: authenticationv1.UserInfo{Username: "system:serviceaccount:opensandbox:opensandbox-workload"},
		}}, nil
	})
	decision, err := checker.Check(context.Background(), CheckInput{Backend: "goproxy", IdentityToken: "token", Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allow || decision.Reason != "token is not Pod-bound" {
		t.Fatalf("decision = %#v", decision)
	}
}

func accessRequestObject(t *testing.T, name, revision string, expiresAt time.Time) *assignmentv1alpha1.SandboxAccessRequest {
	t.Helper()
	approvedAt := metav1.NewTime(expiresAt.Add(-time.Hour))
	expiry := metav1.NewTime(expiresAt)
	return &assignmentv1alpha1.SandboxAccessRequest{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAccessRequest"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxAccessRequestSpec{
			AssignmentRef:            assignmentv1alpha1.AssignmentReference{Name: "assignment-a", UID: types.UID("assignment-uid")},
			BasePolicyRevision:       revision,
			Backend:                  "goproxy",
			Method:                   "GET",
			Host:                     "cachew.example.test",
			Path:                     "/module",
			Reason:                   "Temporary repository refresh.",
			RequestedDurationSeconds: 3600,
			Requester: assignmentv1alpha1.GovernanceIdentity{
				TenantID: "11111111-1111-1111-1111-111111111111", ObjectID: "22222222-2222-2222-2222-222222222222", DisplayName: "Requester",
			},
		},
		Status: assignmentv1alpha1.SandboxAccessRequestStatus{
			State: assignmentv1alpha1.SandboxAccessRequestApproved,
			Approver: &assignmentv1alpha1.GovernanceIdentity{
				TenantID: "11111111-1111-1111-1111-111111111111", ObjectID: "33333333-3333-3333-3333-333333333333", DisplayName: "Approver",
			},
			DecisionReason: "Approved for one repository refresh.",
			ApprovedAt:     &approvedAt,
			ExpiresAt:      &expiry,
		},
	}
}

func accessRequestUnstructured(t *testing.T, request *assignmentv1alpha1.SandboxAccessRequest) *unstructured.Unstructured {
	t.Helper()
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(request)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: object}
}

func newCheckerFixture(t *testing.T) *KubernetesChecker {
	t.Helper()
	bundle := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1", "kind": "CapabilityBundle",
		"metadata": map[string]any{"name": "coding", "namespace": "aks-sandbox-system", "uid": "bundle-uid"},
		"spec": map[string]any{"egress": map[string]any{"agentgateway": map[string]any{
			"goproxy": map[string]any{"allow": `request.method == "GET" && backend.name == "goproxy"`},
		}}},
	}}
	revision, err := checkerPolicyRevision(bundle)
	if err != nil {
		t.Fatal(err)
	}
	assignmentObject := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1", "kind": "SandboxAssignment",
		"metadata": map[string]any{"name": "assignment-a", "namespace": "aks-sandbox-system", "uid": "assignment-uid"},
		"spec":     map[string]any{"capabilityBundleRef": map[string]any{"name": "coding"}},
		"status": map[string]any{
			"podRef":                   map[string]any{"uid": "pod-uid", "name": "sandbox-pod", "namespace": "opensandbox"},
			"resolvedCapabilityBundle": map[string]any{"name": "coding", "uid": "bundle-uid", "policyRevision": revision},
			"conditions":               []any{map[string]any{"type": "Ready", "status": "True"}},
		},
	}}
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	dynamicClient := fake.NewSimpleDynamicClient(scheme, bundle, assignmentObject)
	automount := false
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "sandbox-pod", Namespace: "opensandbox", UID: types.UID("pod-uid")},
		Spec:       corev1.PodSpec{ServiceAccountName: "opensandbox-workload", AutomountServiceAccountToken: &automount},
		Status:     corev1.PodStatus{PodIP: "10.2.3.4", PodIPs: []corev1.PodIP{{IP: "10.2.3.4"}}},
	}
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "opensandbox-workload", Namespace: "opensandbox", Labels: map[string]string{assignment.EligibleServiceAccountLabel: "true"}}, AutomountServiceAccountToken: &automount}
	kube := kubernetesfake.NewSimpleClientset(pod, serviceAccount)
	kube.PrependReactor("create", "tokenreviews", func(ktesting.Action) (bool, runtime.Object, error) {
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: true, Audiences: []string{"aks-sandbox-capability-gateway"},
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:opensandbox:opensandbox-workload",
				Extra: map[string]authenticationv1.ExtraValue{
					podNameExtra: {"sandbox-pod"}, podUIDExtra: {"pod-uid"},
				},
			},
		}}, nil
	})
	checker, err := NewKubernetesChecker(dynamicClient, kube, "aks-sandbox-system", "opensandbox", "aks-sandbox-capability-gateway")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	if err := checker.Start(ctx); err != nil {
		t.Fatal(err)
	}
	return checker
}
