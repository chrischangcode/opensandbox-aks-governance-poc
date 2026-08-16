// Package admission enforces logical-tenant budgets before OpenSandbox creates
// a workload.
package admission

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	bundleGVR     = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "capabilitybundles"}
	assignmentGVR = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxassignments"}
	tenantGVR     = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxtenantpolicies"}
)

type KubernetesAdmission struct {
	dynamic             dynamic.Interface
	assignmentNamespace string
	workloadNamespace   string
}

func NewKubernetesAdmission(dynamicClient dynamic.Interface, assignmentNamespace, workloadNamespace string) *KubernetesAdmission {
	return &KubernetesAdmission{
		dynamic: dynamicClient, assignmentNamespace: assignmentNamespace,
		workloadNamespace: workloadNamespace,
	}
}

func (a *KubernetesAdmission) AuthorizeCreate(ctx context.Context, bundleName string, request *ossandbox.CreateSandboxRequest) error {
	bundleObject, err := a.dynamic.Resource(bundleGVR).Namespace(a.assignmentNamespace).Get(ctx, bundleName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	logicalTenant, _, _ := unstructured.NestedString(bundleObject.Object, "spec", "governance", "logicalTenant")
	if logicalTenant == "" {
		return errors.New("capability bundle has no logical tenant")
	}
	policy, err := a.policyForTenant(ctx, logicalTenant)
	if err != nil {
		return err
	}
	if policy.Spec.WorkloadNamespace != a.workloadNamespace {
		return errors.New("tenant policy targets a different workload namespace")
	}
	if !bundleAllowed(policy.Spec, bundleName) {
		return errors.New("capability bundle is not allowed by the tenant policy")
	}
	if request.Timeout == nil || *request.Timeout < 60 ||
		policy.Spec.MaxLifetimeSeconds < 60 ||
		*request.Timeout > int(policy.Spec.MaxLifetimeSeconds) {
		return errors.New("requested lifetime exceeds the tenant policy")
	}
	if err := validateResourceLimit("cpu", request.ResourceLimits["cpu"], policy.Spec.MaxCPU); err != nil {
		return err
	}
	if err := validateResourceLimit("memory", request.ResourceLimits["memory"], policy.Spec.MaxMemory); err != nil {
		return err
	}
	bundles, err := a.dynamic.Resource(bundleGVR).Namespace(a.assignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	tenantBundles := map[string]struct{}{}
	for i := range bundles.Items {
		tenant, _, _ := unstructured.NestedString(bundles.Items[i].Object, "spec", "governance", "logicalTenant")
		if tenant == logicalTenant {
			tenantBundles[bundles.Items[i].GetName()] = struct{}{}
		}
	}
	assignments, err := a.dynamic.Resource(assignmentGVR).Namespace(a.assignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	active := int32(0)
	for i := range assignments.Items {
		assignment := &assignments.Items[i]
		if assignment.GetDeletionTimestamp() != nil {
			continue
		}
		name, _, _ := unstructured.NestedString(assignment.Object, "spec", "capabilityBundleRef", "name")
		if _, belongsToTenant := tenantBundles[name]; belongsToTenant {
			active++
		}
	}
	if active >= policy.Spec.MaxConcurrentSandboxes {
		return fmt.Errorf("logical tenant %q reached its concurrent sandbox budget", logicalTenant)
	}
	return nil
}

func bundleAllowed(spec assignmentv1alpha1.SandboxTenantPolicySpec, name string) bool {
	if slices.Contains(spec.AllowedCapabilityBundles, name) {
		return true
	}
	for _, prefix := range spec.AllowedCapabilityBundlePrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func (a *KubernetesAdmission) MaxAccessDuration(ctx context.Context, logicalTenant string) (int32, error) {
	policy, err := a.policyForTenant(ctx, logicalTenant)
	if err != nil {
		return 0, err
	}
	return policy.Spec.MaxAccessRequestDurationSeconds, nil
}

func (a *KubernetesAdmission) policyForTenant(ctx context.Context, logicalTenant string) (*assignmentv1alpha1.SandboxTenantPolicy, error) {
	list, err := a.dynamic.Resource(tenantGVR).Namespace(a.assignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var matches []*assignmentv1alpha1.SandboxTenantPolicy
	for i := range list.Items {
		policy := &assignmentv1alpha1.SandboxTenantPolicy{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(list.Items[i].Object, policy); err != nil {
			return nil, err
		}
		if policy.Spec.Enabled && policy.Spec.LogicalTenant == logicalTenant && policy.DeletionTimestamp == nil {
			matches = append(matches, policy)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("logical tenant %q must have exactly one enabled policy", logicalTenant)
	}
	return matches[0], nil
}

func validateResourceLimit(name, requested, maximum string) error {
	if requested == "" {
		return fmt.Errorf("%s limit is required", name)
	}
	requestedQuantity, err := resource.ParseQuantity(requested)
	if err != nil {
		return fmt.Errorf("%s limit is invalid", name)
	}
	maximumQuantity, err := resource.ParseQuantity(maximum)
	if err != nil || maximumQuantity.Sign() <= 0 {
		return fmt.Errorf("tenant %s budget is invalid", name)
	}
	if requestedQuantity.Sign() <= 0 || requestedQuantity.Cmp(maximumQuantity) > 0 {
		return fmt.Errorf("%s limit exceeds the tenant budget", name)
	}
	return nil
}
