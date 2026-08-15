package kubernetes

import (
	"testing"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
)

func TestConvertReadsReadyBinding(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1",
		"kind":       "SandboxAssignment",
		"metadata": map[string]any{
			"namespace":       "aks-sandbox-system",
			"name":            "assignment-a981",
			"resourceVersion": "42",
		},
		"spec": map[string]any{
			"capabilityBundleRef": map[string]any{"name": "coding-default"},
		},
		"status": map[string]any{
			"podRef": map[string]any{
				"namespace": "opensandbox", "name": "sandbox-123-0", "uid": "pod-uid",
			},
			"conditions": []any{
				map[string]any{"type": "Ready", "status": "True", "reason": "AssignmentReady"},
			},
		},
	}}
	object.SetUID(types.UID("assignment-uid"))

	value, err := convert(object)
	if err != nil {
		t.Fatal(err)
	}
	if !value.Ready || value.PodRef == nil || value.PodRef.UID != "pod-uid" {
		t.Fatalf("converted = %#v", value)
	}
}

func TestSandboxIDsForObjectIndexesMappingAndWorkload(t *testing.T) {
	object := &unstructured.Unstructured{Object: map[string]any{
		"metadata": map[string]any{
			"annotations": map[string]any{assignment.SandboxIDAnnotation: "sandbox-id"},
		},
		"status": map[string]any{
			"workloadRef": map[string]any{"name": "workload-id"},
		},
	}}
	ids, err := sandboxIDsForObject(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 2 || ids[0] != "sandbox-id" || ids[1] != "workload-id" {
		t.Fatalf("ids = %v", ids)
	}

	_ = unstructured.SetNestedField(object.Object, "sandbox-id", "status", "workloadRef", "name")
	ids, err = sandboxIDsForObject(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0] != "sandbox-id" {
		t.Fatalf("deduplicated ids = %v", ids)
	}
}

func TestConvertReportsDeletion(t *testing.T) {
	now := metav1.Now()
	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1",
		"kind":       "SandboxAssignment",
		"metadata": map[string]any{
			"namespace": "aks-sandbox-system",
			"name":      "assignment-a981",
		},
		"spec": map[string]any{
			"capabilityBundleRef": map[string]any{"name": "coding-default"},
		},
	}}
	object.SetDeletionTimestamp(&now)

	value, err := convert(object)
	if err != nil {
		t.Fatal(err)
	}
	if !value.Deleting {
		t.Fatal("deleting = false, want true")
	}
}
