package opensandboxapi

import (
	"context"
	"strings"
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
)

func TestKubernetesTemplateResolverReturnsTrustedShape(t *testing.T) {
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	bundle := templateTestBundle(t)
	template := templateTestTemplate(t, bundle)
	resolver := NewKubernetesTemplateResolver(
		fake.NewSimpleDynamicClient(scheme, bundle, template),
		"aks-sandbox-system",
	)
	resolved, err := resolver.Resolve(context.Background(), template.Name)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Name != template.Name || resolved.UID != string(template.UID) ||
		!strings.HasPrefix(resolved.Revision, "sha256:") ||
		resolved.CapabilityBundleName != bundle.Name ||
		resolved.LogicalTenant != "tenant-a" ||
		resolved.Image != template.Spec.Image ||
		resolved.CPU != "500m" || resolved.Memory != "512Mi" ||
		resolved.TimeoutSeconds != 1800 {
		t.Fatalf("resolved template = %#v", resolved)
	}
}

func TestKubernetesTemplateResolverRejectsDisabledAndStaleTemplates(t *testing.T) {
	for name, testCase := range map[string]struct {
		mutate func(*assignmentv1alpha1.SandboxTemplate)
		wanted string
	}{
		"disabled": {
			mutate: func(template *assignmentv1alpha1.SandboxTemplate) { template.Spec.Enabled = false },
			wanted: "disabled",
		},
		"stale bundle": {
			mutate: func(template *assignmentv1alpha1.SandboxTemplate) {
				template.Spec.CapabilityBundleRef.PolicyRevision = "sha256:" + strings.Repeat("0", 64)
			},
			wanted: "stale",
		},
	} {
		t.Run(name, func(t *testing.T) {
			scheme := runtime.NewScheme()
			if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			bundle := templateTestBundle(t)
			template := templateTestTemplate(t, bundle)
			testCase.mutate(template)
			resolver := NewKubernetesTemplateResolver(
				fake.NewSimpleDynamicClient(scheme, bundle, template),
				"aks-sandbox-system",
			)
			if _, err := resolver.Resolve(context.Background(), template.Name); err == nil ||
				!strings.Contains(err.Error(), testCase.wanted) {
				t.Fatalf("resolver error = %v", err)
			}
		})
	}
}

func templateTestBundle(t *testing.T) *assignmentv1alpha1.CapabilityBundle {
	t.Helper()
	return &assignmentv1alpha1.CapabilityBundle{
		TypeMeta: metav1.TypeMeta{
			APIVersion: assignmentv1alpha1.GroupVersion.String(),
			Kind:       "CapabilityBundle",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "team-a-reader",
			Namespace: "aks-sandbox-system",
			UID:       types.UID("bundle-uid"),
		},
		Spec: assignmentv1alpha1.CapabilityBundleSpec{
			Governance: &assignmentv1alpha1.GovernanceBoundary{
				LogicalTenant: "tenant-a",
				Team:          "readers",
			},
		},
	}
}

func templateTestTemplate(t *testing.T, bundle *assignmentv1alpha1.CapabilityBundle) *assignmentv1alpha1.SandboxTemplate {
	t.Helper()
	bundleMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(bundle)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := governance.PolicyRevision(bundleMap["spec"].(map[string]any))
	if err != nil {
		t.Fatal(err)
	}
	return &assignmentv1alpha1.SandboxTemplate{
		TypeMeta: metav1.TypeMeta{
			APIVersion: assignmentv1alpha1.GroupVersion.String(),
			Kind:       "SandboxTemplate",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name:      "python-kata-reader-v2",
			Namespace: "aks-sandbox-system",
			UID:       types.UID("template-uid"),
		},
		Spec: assignmentv1alpha1.SandboxTemplateSpec{
			DisplayName: "Python Kata reader",
			Image:       "python@sha256:" + strings.Repeat("a", 64),
			Entrypoint:  []string{"tail", "-f", "/dev/null"},
			CapabilityBundleRef: assignmentv1alpha1.CapabilityBundleReference{
				Name: bundle.Name, PolicyRevision: revision,
			},
			Resources: assignmentv1alpha1.SandboxTemplateResources{
				CPU: "500m", Memory: "512Mi",
			},
			TimeoutSeconds: 1800,
			Enabled:        true,
		},
	}
}
