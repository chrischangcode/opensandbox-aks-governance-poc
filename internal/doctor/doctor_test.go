package doctor

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	nodev1 "k8s.io/api/node/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic/fake"
	kubernetesfake "k8s.io/client-go/kubernetes/fake"
)

func TestRunnerReportsReadyContract(t *testing.T) {
	automount := false
	ready := int32(1)
	kube := kubernetesfake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-optimized"},
			Handler:    "kata-handler",
			Scheduling: &nodev1.Scheduling{NodeSelector: map[string]string{"sandbox": "kata"}},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-node", Labels: map[string]string{"sandbox": "kata"}},
			Status: corev1.NodeStatus{
				Conditions:  []corev1.NodeCondition{{Type: corev1.NodeReady, Status: corev1.ConditionTrue}},
				Allocatable: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("4"), corev1.ResourceMemory: resource.MustParse("8Gi")},
			},
		},
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "assignmentd", Namespace: "aks-sandbox-system"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &ready,
				Strategy: appsv1.DeploymentStrategy{Type: appsv1.RecreateDeploymentStrategyType},
				Template: corev1.PodTemplateSpec{Spec: corev1.PodSpec{Containers: []corev1.Container{{
					Name: "assignmentd", Env: []corev1.EnvVar{{Name: "ASSIGNMENTD_EGRESS_IDENTITY_MODE", Value: "external-mediator"}},
				}}}},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "assignmentd", Namespace: "aks-sandbox-system"}},
		&corev1.Service{ObjectMeta: metav1.ObjectMeta{Name: "opensandbox-server", Namespace: "opensandbox"}},
		&corev1.ServiceAccount{
			ObjectMeta:                   metav1.ObjectMeta{Name: "opensandbox-workload", Namespace: "opensandbox", UID: types.UID("sa"), Labels: map[string]string{"aks-sandbox.azure.com/eligible": "true"}},
			AutomountServiceAccountToken: &automount,
		},
		&corev1.ResourceQuota{ObjectMeta: metav1.ObjectMeta{Name: "sandbox-budget", Namespace: "opensandbox"}},
	)
	scheme := runtime.NewScheme()
	objects := []runtime.Object{}
	for _, name := range []string{
		"capabilitybundles.aks-sandbox.azure.com",
		"sandboxaccessrequests.aks-sandbox.azure.com",
		"sandboxassignments.aks-sandbox.azure.com",
		"sandboxcredentialevents.aks-sandbox.azure.com",
		"sandboxegressevents.aks-sandbox.azure.com",
		"sandboxtemplates.aks-sandbox.azure.com",
		"sandboxtenantpolicies.aks-sandbox.azure.com",
		"sandboxvalidationruns.aks-sandbox.azure.com",
	} {
		objects = append(objects, &unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
			"metadata": map[string]any{"name": name},
		}})
	}
	objects = append(objects,
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aks-sandbox.azure.com/v1alpha1", "kind": "SandboxTemplate",
			"metadata": map[string]any{"name": "python", "namespace": "aks-sandbox-system"},
			"spec":     map[string]any{"enabled": true},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aks-sandbox.azure.com/v1alpha1", "kind": "CapabilityBundle",
			"metadata": map[string]any{"name": "reader", "namespace": "aks-sandbox-system"},
			"spec":     map[string]any{},
		}},
		&unstructured.Unstructured{Object: map[string]any{
			"apiVersion": "aks-sandbox.azure.com/v1alpha1", "kind": "SandboxTenantPolicy",
			"metadata": map[string]any{"name": "tenant-a-v1", "namespace": "aks-sandbox-system"},
			"spec":     map[string]any{"enabled": true},
		}},
	)
	dynamicClient := fake.NewSimpleDynamicClient(scheme, objects...)
	report := New(kube, dynamicClient, Config{}).Run(context.Background())
	if !report.Ready {
		t.Fatalf("report = %#v", report)
	}
	for _, check := range report.Checks {
		if check.Status == StatusFail {
			t.Fatalf("failed check = %#v", check)
		}
	}
}

func TestRunnerFailsClosedWithoutKataRuntime(t *testing.T) {
	kube := kubernetesfake.NewSimpleClientset()
	dynamicClient := fake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(), map[schema.GroupVersionResource]string{
		templateGVR: "SandboxTemplateList",
		bundleGVR:   "CapabilityBundleList",
		tenantGVR:   "SandboxTenantPolicyList",
	})
	report := New(kube, dynamicClient, Config{}).Run(context.Background())
	if report.Ready {
		t.Fatalf("report unexpectedly ready: %#v", report)
	}
	if report.Checks[0].Status != StatusFail {
		t.Fatalf("runtime check = %#v", report.Checks[0])
	}
}
