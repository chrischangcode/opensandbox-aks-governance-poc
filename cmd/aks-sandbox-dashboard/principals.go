package main

import (
	"context"
	"errors"
	"fmt"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

var (
	errPrincipalBindingMissing   = errors.New("authenticated principal has no sandbox tenant binding")
	errPrincipalBindingAmbiguous = errors.New("principal must have exactly one active binding")
)

type principalTenantScopes struct {
	requester map[string]struct{}
	admin     map[string]struct{}
}

func (g *governanceDashboard) principalScopes(ctx context.Context, identity authenticatedIdentity) (principalTenantScopes, error) {
	return loadPrincipalScopes(ctx, g.client, g.namespace, identity)
}

func loadPrincipalScopes(ctx context.Context, client dynamic.Interface, namespace string, identity authenticatedIdentity) (principalTenantScopes, error) {
	list, err := client.Resource(dashboardPrincipalBindingsGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return principalTenantScopes{}, err
	}
	var matched *assignmentv1alpha1.SandboxPrincipalBinding
	for i := range list.Items {
		binding := &assignmentv1alpha1.SandboxPrincipalBinding{}
		if err := fromUnstructured(&list.Items[i], binding); err != nil {
			return principalTenantScopes{}, err
		}
		if binding.DeletionTimestamp != nil ||
			binding.Spec.TenantID != identity.TenantID ||
			binding.Spec.ObjectID != identity.ObjectID {
			continue
		}
		if matched != nil {
			return principalTenantScopes{}, fmt.Errorf("%w", errPrincipalBindingAmbiguous)
		}
		matched = binding
	}
	if matched == nil {
		return principalTenantScopes{}, fmt.Errorf("%w", errPrincipalBindingMissing)
	}
	scopes := principalTenantScopes{
		requester: make(map[string]struct{}, len(matched.Spec.RequesterTenants)),
		admin:     make(map[string]struct{}, len(matched.Spec.AdminTenants)),
	}
	for _, tenant := range matched.Spec.RequesterTenants {
		scopes.requester[tenant] = struct{}{}
	}
	for _, tenant := range matched.Spec.AdminTenants {
		scopes.admin[tenant] = struct{}{}
	}
	return scopes, nil
}

func tenantAllowed(tenants map[string]struct{}, tenant string) bool {
	if tenants == nil {
		return true
	}
	_, allowed := tenants[tenant]
	return allowed
}
