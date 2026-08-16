package admission

import (
	"context"
	"strings"
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

func TestAdmissionEnforcesTenantBudgets(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bundle := &assignmentv1alpha1.CapabilityBundle{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-reader", Namespace: "aks-sandbox-system"},
		Spec:       assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{LogicalTenant: "tenant-a"}},
	}
	policy := &assignmentv1alpha1.SandboxTenantPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTenantPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a-v1", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxTenantPolicySpec{
			LogicalTenant: "tenant-a", WorkloadNamespace: "opensandbox",
			AllowedCapabilityBundles: []string{"team-a-reader"}, AllowedCapabilityBundlePrefixes: []string{"demo-"},
			MaxConcurrentSandboxes: 1, MaxLifetimeSeconds: 1800,
			MaxAccessRequestDurationSeconds: 900, MaxCPU: "1", MaxMemory: "1Gi", Enabled: true,
		},
	}
	client := fake.NewSimpleDynamicClient(scheme, bundle, policy)
	admission := NewKubernetesAdmission(client, kubernetesfake.NewSimpleClientset(), "aks-sandbox-system", "opensandbox")
	timeout := 900
	request := &ossandbox.CreateSandboxRequest{
		Timeout: &timeout, ResourceLimits: ossandbox.ResourceLimits{"cpu": "500m", "memory": "512Mi"},
	}
	release, err := admission.AuthorizeCreate(context.Background(), "team-a-reader", request)
	if err != nil {
		t.Fatal(err)
	}
	release()

	assignment := &assignmentv1alpha1.SandboxAssignment{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAssignment"},
		ObjectMeta: metav1.ObjectMeta{Name: "assignment-a", Namespace: "aks-sandbox-system", UID: types.UID("uid")},
		Spec:       assignmentv1alpha1.SandboxAssignmentSpec{CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{Name: "team-a-reader"}},
	}
	if _, err := client.Resource(assignmentGVR).Namespace("aks-sandbox-system").Create(context.Background(), toUnstructured(t, assignment), metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := admission.AuthorizeCreate(context.Background(), "team-a-reader", request); err == nil || !strings.Contains(err.Error(), "concurrent") {
		t.Fatalf("quota error = %v", err)
	}
}

func TestAdmissionRejectsExcessResourcesAndLifetime(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bundle := &assignmentv1alpha1.CapabilityBundle{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-reader", Namespace: "aks-sandbox-system"},
		Spec:       assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{LogicalTenant: "tenant-a"}},
	}
	policy := &assignmentv1alpha1.SandboxTenantPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTenantPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a-v1", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxTenantPolicySpec{
			LogicalTenant: "tenant-a", WorkloadNamespace: "opensandbox",
			AllowedCapabilityBundles: []string{"team-a-reader"}, AllowedCapabilityBundlePrefixes: []string{"demo-"},
			MaxConcurrentSandboxes: 1, MaxLifetimeSeconds: 600,
			MaxAccessRequestDurationSeconds: 300, MaxCPU: "500m", MaxMemory: "512Mi", Enabled: true,
		},
	}
	admission := NewKubernetesAdmission(fake.NewSimpleDynamicClient(scheme, bundle, policy), kubernetesfake.NewSimpleClientset(), "aks-sandbox-system", "opensandbox")
	timeout := 1200
	_, err := admission.AuthorizeCreate(context.Background(), "team-a-reader", &ossandbox.CreateSandboxRequest{
		Timeout: &timeout, ResourceLimits: ossandbox.ResourceLimits{"cpu": "1", "memory": "1Gi"},
	})
	if err == nil {
		t.Fatal("excess request was admitted")
	}
}

func TestAdmissionRejectsLifetimeThatWouldOverflowInt32(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bundle := &assignmentv1alpha1.CapabilityBundle{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "CapabilityBundle"},
		ObjectMeta: metav1.ObjectMeta{Name: "team-a-reader", Namespace: "aks-sandbox-system"},
		Spec:       assignmentv1alpha1.CapabilityBundleSpec{Governance: &assignmentv1alpha1.GovernanceBoundary{LogicalTenant: "tenant-a"}},
	}
	policy := &assignmentv1alpha1.SandboxTenantPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTenantPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: "tenant-a-v1", Namespace: "aks-sandbox-system"},
		Spec: assignmentv1alpha1.SandboxTenantPolicySpec{
			LogicalTenant: "tenant-a", WorkloadNamespace: "opensandbox",
			AllowedCapabilityBundles: []string{"team-a-reader"},
			MaxConcurrentSandboxes:   1, MaxLifetimeSeconds: 600,
			MaxAccessRequestDurationSeconds: 300, MaxCPU: "500m", MaxMemory: "512Mi", Enabled: true,
		},
	}
	admission := NewKubernetesAdmission(fake.NewSimpleDynamicClient(scheme, bundle, policy), kubernetesfake.NewSimpleClientset(), "aks-sandbox-system", "opensandbox")
	timeout := int(uint64(1)<<32 + 60)
	_, err := admission.AuthorizeCreate(context.Background(), "team-a-reader", &ossandbox.CreateSandboxRequest{
		Timeout: &timeout, ResourceLimits: ossandbox.ResourceLimits{"cpu": "500m", "memory": "512Mi"},
	})
	if err == nil || !strings.Contains(err.Error(), "lifetime") {
		t.Fatalf("overflowing lifetime error = %v", err)
	}
}

func toUnstructured(t *testing.T, object any) *unstructured.Unstructured {
	t.Helper()
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		t.Fatal(err)
	}
	return &unstructured.Unstructured{Object: value}
}
