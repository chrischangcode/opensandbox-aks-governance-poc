// Package admission enforces logical-tenant budgets before OpenSandbox creates
// a workload.
package admission

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	"github.com/google/uuid"
	coordinationv1 "k8s.io/api/coordination/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	bundleGVR     = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "capabilitybundles"}
	assignmentGVR = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxassignments"}
	tenantGVR     = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxtenantpolicies"}
)

type KubernetesAdmission struct {
	dynamic             dynamic.Interface
	kube                kubernetes.Interface
	assignmentNamespace string
	workloadNamespace   string
}

func NewKubernetesAdmission(dynamicClient dynamic.Interface, kube kubernetes.Interface, assignmentNamespace, workloadNamespace string) *KubernetesAdmission {
	return &KubernetesAdmission{
		dynamic: dynamicClient, kube: kube, assignmentNamespace: assignmentNamespace,
		workloadNamespace: workloadNamespace,
	}
}

func (a *KubernetesAdmission) AuthorizeCreate(ctx context.Context, bundleName string, request *ossandbox.CreateSandboxRequest) (func(), error) {
	bundleObject, err := a.dynamic.Resource(bundleGVR).Namespace(a.assignmentNamespace).Get(ctx, bundleName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	logicalTenant, _, _ := unstructured.NestedString(bundleObject.Object, "spec", "governance", "logicalTenant")
	if logicalTenant == "" {
		return nil, errors.New("capability bundle has no logical tenant")
	}
	policy, err := a.policyForTenant(ctx, logicalTenant)
	if err != nil {
		return nil, err
	}
	if policy.Spec.WorkloadNamespace != a.workloadNamespace {
		return nil, errors.New("tenant policy targets a different workload namespace")
	}
	if !bundleAllowed(policy.Spec, bundleName) {
		return nil, errors.New("capability bundle is not allowed by the tenant policy")
	}
	if request.Timeout == nil || *request.Timeout < 60 ||
		policy.Spec.MaxLifetimeSeconds < 60 ||
		*request.Timeout > int(policy.Spec.MaxLifetimeSeconds) {
		return nil, errors.New("requested lifetime exceeds the tenant policy")
	}
	if err := validateResourceLimit("cpu", request.ResourceLimits["cpu"], policy.Spec.MaxCPU); err != nil {
		return nil, err
	}
	if err := validateResourceLimit("memory", request.ResourceLimits["memory"], policy.Spec.MaxMemory); err != nil {
		return nil, err
	}
	release, err := a.acquireTenantLease(ctx, logicalTenant)
	if err != nil {
		return nil, err
	}
	keepLease := false
	defer func() {
		if !keepLease {
			release()
		}
	}()
	bundles, err := a.dynamic.Resource(bundleGVR).Namespace(a.assignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
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
		return nil, err
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
		return nil, fmt.Errorf("logical tenant %q reached its concurrent sandbox budget", logicalTenant)
	}
	keepLease = true
	return release, nil
}

func (a *KubernetesAdmission) acquireTenantLease(ctx context.Context, logicalTenant string) (func(), error) {
	if a.kube == nil {
		return nil, errors.New("Kubernetes admission Lease client is required")
	}
	sum := sha256.Sum256([]byte(logicalTenant))
	name := fmt.Sprintf("sandbox-admission-%x", sum[:8])
	holder := uuid.NewString()
	duration := int32(15)
	leases := a.kube.CoordinationV1().Leases(a.assignmentNamespace)
	for {
		now := metav1.NewMicroTime(time.Now().UTC())
		lease, err := leases.Get(ctx, name, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			lease, err = leases.Create(ctx, &coordinationv1.Lease{
				ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: a.assignmentNamespace},
				Spec: coordinationv1.LeaseSpec{
					HolderIdentity:       &holder,
					LeaseDurationSeconds: &duration,
					AcquireTime:          &now,
					RenewTime:            &now,
				},
			}, metav1.CreateOptions{})
			if err == nil {
				return func() { _ = leases.Delete(context.Background(), name, metav1.DeleteOptions{}) }, nil
			}
			if !apierrors.IsAlreadyExists(err) {
				return nil, err
			}
		} else if err != nil {
			return nil, err
		} else if leaseAvailable(lease, time.Now()) {
			copy := lease.DeepCopy()
			copy.Spec.HolderIdentity = &holder
			copy.Spec.LeaseDurationSeconds = &duration
			copy.Spec.AcquireTime = &now
			copy.Spec.RenewTime = &now
			updated, updateErr := leases.Update(ctx, copy, metav1.UpdateOptions{})
			if updateErr == nil {
				uid := updated.UID
				return func() {
					_ = leases.Delete(context.Background(), name, metav1.DeleteOptions{
						Preconditions: &metav1.Preconditions{UID: &uid},
					})
				}, nil
			}
			if !apierrors.IsConflict(updateErr) {
				return nil, updateErr
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func leaseAvailable(lease *coordinationv1.Lease, now time.Time) bool {
	if lease.Spec.HolderIdentity == nil || *lease.Spec.HolderIdentity == "" ||
		lease.Spec.RenewTime == nil || lease.Spec.LeaseDurationSeconds == nil {
		return true
	}
	return !lease.Spec.RenewTime.Add(time.Duration(*lease.Spec.LeaseDurationSeconds) * time.Second).After(now)
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
