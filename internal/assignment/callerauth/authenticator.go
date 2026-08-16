// Package callerauth authenticates trusted assignmentd lifecycle callers.
package callerauth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var principalBindingsGVR = schema.GroupVersionResource{
	Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxprincipalbindings",
}

type tenantScopesContextKey struct{}

// Authenticator validates a dedicated-audience ServiceAccount token and loads
// the caller's administrator-defined logical tenant scopes.
type Authenticator struct {
	kube      kubernetes.Interface
	dynamic   dynamic.Interface
	namespace string
	audience  string
}

func New(kube kubernetes.Interface, dynamicClient dynamic.Interface, namespace, audience string) (*Authenticator, error) {
	if kube == nil || dynamicClient == nil || namespace == "" || audience == "" {
		return nil, errors.New("caller authenticator requires Kubernetes clients, namespace, and audience")
	}
	return &Authenticator{kube: kube, dynamic: dynamicClient, namespace: namespace, audience: audience}, nil
}

// Middleware rejects unauthenticated and unbound lifecycle callers.
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		review, err := a.kube.AuthenticationV1().TokenReviews().Create(r.Context(), &authenticationv1.TokenReview{
			Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{a.audience}},
		}, metav1.CreateOptions{})
		if err != nil {
			http.Error(w, "Caller authentication is unavailable", http.StatusServiceUnavailable)
			return
		}
		if !review.Status.Authenticated || len(review.Status.Audiences) == 0 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		namespace, name, ok := serviceAccountIdentity(review.Status.User.Username)
		if !ok {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		tenants, err := a.serviceAccountTenants(r.Context(), namespace, name)
		if err != nil {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		r.Header.Del("Authorization")
		ctx := context.WithValue(r.Context(), tenantScopesContextKey{}, tenants)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// AuthorizeTenant verifies that middleware authenticated this request and that
// its binding includes the selected logical tenant.
func (a *Authenticator) AuthorizeTenant(ctx context.Context, logicalTenant string) error {
	tenants, ok := ctx.Value(tenantScopesContextKey{}).(map[string]struct{})
	if !ok {
		return errors.New("caller identity is unavailable")
	}
	if _, ok := tenants[logicalTenant]; !ok {
		return errors.New("caller is not authorized for the logical tenant")
	}
	return nil
}

func (a *Authenticator) serviceAccountTenants(ctx context.Context, namespace, name string) (map[string]struct{}, error) {
	list, err := a.dynamic.Resource(principalBindingsGVR).Namespace(a.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var matched map[string]struct{}
	for i := range list.Items {
		item := &list.Items[i]
		if item.GetDeletionTimestamp() != nil {
			continue
		}
		bindingNamespace, _, _ := unstructured.NestedString(item.Object, "spec", "serviceAccountNamespace")
		bindingName, _, _ := unstructured.NestedString(item.Object, "spec", "serviceAccountName")
		if bindingNamespace != namespace || bindingName != name {
			continue
		}
		if matched != nil {
			return nil, errors.New("service account must have exactly one active principal binding")
		}
		values, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "requesterTenants")
		matched = make(map[string]struct{}, len(values))
		for _, tenant := range values {
			matched[tenant] = struct{}{}
		}
	}
	if len(matched) == 0 {
		return nil, errors.New("service account has no authorized logical tenant")
	}
	return matched, nil
}

func bearerToken(value string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
	return token, ok && strings.EqualFold(scheme, "Bearer") && token != "" && !strings.Contains(token, " ")
}

func serviceAccountIdentity(username string) (string, string, bool) {
	const prefix = "system:serviceaccount:"
	value, ok := strings.CutPrefix(username, prefix)
	if !ok {
		return "", "", false
	}
	namespace, name, ok := strings.Cut(value, ":")
	return namespace, name, ok && namespace != "" && name != "" && !strings.Contains(name, ":")
}
