package callerauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

func TestAuthenticatorRequiresBoundServiceAccountAndScopesTenant(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	binding := &assignmentv1alpha1.SandboxPrincipalBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxPrincipalBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: "harness", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxPrincipalBindingSpec{
			ServiceAccountNamespace: "aks-sandbox-system",
			ServiceAccountName:      "assignmentd-harness",
			RequesterTenants:        []string{"tenant-a"},
		},
	}
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, binding)
	kube := kubernetesfake.NewSimpleClientset()
	kube.PrependReactor("create", "tokenreviews", func(action k8stesting.Action) (bool, runtime.Object, error) {
		review := action.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		if review.Spec.Token != "valid-token" || len(review.Spec.Audiences) != 1 || review.Spec.Audiences[0] != "lifecycle" {
			t.Fatalf("token review = %+v", review.Spec)
		}
		return true, &authenticationv1.TokenReview{Status: authenticationv1.TokenReviewStatus{
			Authenticated: true,
			Audiences:     []string{"lifecycle"},
			User: authenticationv1.UserInfo{
				Username: "system:serviceaccount:aks-sandbox-system:assignmentd-harness",
			},
		}}, nil
	})
	authenticator, err := New(kube, dynamicClient, "aks-sandbox-system", "lifecycle")
	if err != nil {
		t.Fatal(err)
	}
	handler := authenticator.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := authenticator.AuthorizeTenant(r.Context(), "tenant-a"); err != nil {
			t.Fatal(err)
		}
		if err := authenticator.AuthorizeTenant(r.Context(), "tenant-b"); err == nil {
			t.Fatal("tenant-b authorization succeeded")
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("caller token was not stripped before forwarding")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	request := httptest.NewRequest(http.MethodPost, "https://assignmentd/opensandbox/sandboxes", nil)
	request.Header.Set("Authorization", "Bearer valid-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("response = %d body=%s", response.Code, response.Body.String())
	}
}

func TestAuthenticatorRejectsMissingBearerToken(t *testing.T) {
	authenticator, err := New(
		kubernetesfake.NewSimpleClientset(),
		dynamicfake.NewSimpleDynamicClient(runtime.NewScheme()),
		"aks-sandbox-system",
		"lifecycle",
	)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	handler := authenticator.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://assignmentd/opensandbox/sandboxes", nil))
	if response.Code != http.StatusUnauthorized || called {
		t.Fatalf("response = %d called=%t", response.Code, called)
	}
	if err := authenticator.AuthorizeTenant(context.Background(), "tenant-a"); err == nil {
		t.Fatal("tenant authorization succeeded without middleware identity")
	}
}
