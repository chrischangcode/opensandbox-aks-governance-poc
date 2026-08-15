package controller

import (
	"testing"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateIdentity(t *testing.T) {
	automount := false
	expiration := int64(600)
	pod := &corev1.Pod{Spec: corev1.PodSpec{
		AutomountServiceAccountToken: &automount,
		Volumes: []corev1.Volume{{
			Name: identityVolume,
			VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
					Audience: identityAudience, ExpirationSeconds: &expiration, Path: "token",
				}}},
			}},
		}},
		Containers: []corev1.Container{
			{Name: "main"},
			{Name: identityContainer, VolumeMounts: []corev1.VolumeMount{{Name: identityVolume, MountPath: identityMountPath, ReadOnly: true}}},
		},
	}}
	if err := validateIdentity(pod); err != nil {
		t.Fatalf("validateIdentity() error = %v", err)
	}

	pod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{{Name: identityVolume, MountPath: identityMountPath, ReadOnly: true}}
	if err := validateIdentity(pod); err == nil {
		t.Fatal("validateIdentity() accepted identity mount in main container")
	}
}

func TestValidateExternalMediatorIdentity(t *testing.T) {
	automount := false
	pod := &corev1.Pod{Spec: corev1.PodSpec{AutomountServiceAccountToken: &automount}}
	if err := validateExternalMediatorIdentity(pod); err != nil {
		t.Fatalf("validateExternalMediatorIdentity() error = %v", err)
	}
	automount = true
	if err := validatePodServiceAccountIsolation(pod); err == nil {
		t.Fatal("automounted service account token was accepted")
	}
	automount = false
	pod.Spec.Volumes = []corev1.Volume{{
		Name: "unexpected-token",
		VolumeSource: corev1.VolumeSource{Projected: &corev1.ProjectedVolumeSource{
			Sources: []corev1.VolumeProjection{{ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
				Audience: "other", Path: "token",
			}}},
		}},
	}}
	if err := validateExternalMediatorIdentity(pod); err == nil {
		t.Fatal("projected service account token was accepted")
	}
}

func TestValidateBundlePolicy(t *testing.T) {
	valid := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{"egress": map[string]any{"agentgateway": map[string]any{
		"goproxy": map[string]any{"allow": `request.method == "GET"`},
	}}}}}
	typedValid, err := bundleFromUnstructured(valid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBundlePolicy(typedValid); err != nil {
		t.Fatalf("valid policy rejected: %v", err)
	}
	invalid := valid.DeepCopy()
	_ = unstructured.SetNestedField(invalid.Object, `request.missing(`, "spec", "egress", "agentgateway", "goproxy", "allow")
	typedInvalid, err := bundleFromUnstructured(invalid)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBundlePolicy(typedInvalid); err == nil {
		t.Fatal("invalid CEL policy accepted")
	}
	nonBoolean := valid.DeepCopy()
	_ = unstructured.SetNestedField(nonBoolean.Object, `request.method`, "spec", "egress", "agentgateway", "goproxy", "allow")
	typedNonBoolean, err := bundleFromUnstructured(nonBoolean)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateBundlePolicy(typedNonBoolean); err == nil {
		t.Fatal("non-boolean CEL policy accepted")
	}
}

func TestPolicyRevisionIsStableForMapOrder(t *testing.T) {
	first := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"egress":  map[string]any{"agentgateway": map[string]any{"goproxy": map[string]any{"allow": "true"}}},
		"harness": map[string]any{"commandPolicy": []any{}},
	}}}
	second := &unstructured.Unstructured{Object: map[string]any{"spec": map[string]any{
		"harness": map[string]any{"commandPolicy": []any{}},
		"egress":  map[string]any{"agentgateway": map[string]any{"goproxy": map[string]any{"allow": "true"}}},
	}}}
	a, err := policyRevision(first)
	if err != nil {
		t.Fatal(err)
	}
	b, err := policyRevision(second)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("policy revisions differ: %s != %s", a, b)
	}
}

func TestValidateServiceAccountEligibility(t *testing.T) {
	pod := &corev1.Pod{}
	if err := validateServiceAccountReference(pod); err == nil {
		t.Fatal("missing ServiceAccount reference was accepted")
	}
	pod.Spec.ServiceAccountName = "coding-sandbox"
	if err := validateServiceAccountReference(pod); err != nil {
		t.Fatalf("named ServiceAccount rejected: %v", err)
	}

	automount := false
	serviceAccount := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "coding-sandbox"}, AutomountServiceAccountToken: &automount}
	if err := validateEligibleServiceAccount(serviceAccount); err == nil {
		t.Fatal("unlabelled ServiceAccount was accepted")
	}
	serviceAccount.Labels = map[string]string{assignment.EligibleServiceAccountLabel: "true"}
	if err := validateEligibleServiceAccount(serviceAccount); err != nil {
		t.Fatalf("eligible ServiceAccount rejected: %v", err)
	}
	automount = true
	if err := validateEligibleServiceAccount(serviceAccount); err == nil {
		t.Fatal("auto-mounted ServiceAccount was accepted")
	}
}

func TestAssignmentUIDPrefersOpenSandboxAnnotation(t *testing.T) {
	annotations := map[string]string{
		assignment.AssignmentUIDAnnotation:            "forged-direct-value",
		assignment.OpenSandboxAssignmentUIDAnnotation: "trusted-opensandbox-value",
	}
	if got := assignmentUID(annotations); got != "trusted-opensandbox-value" {
		t.Fatalf("assignmentUID() = %q", got)
	}
}

func TestReadyConditionsDescribeIdentityRequirement(t *testing.T) {
	object := &unstructured.Unstructured{}
	withoutIdentity := readyConditions(object, false, ProjectedSidecarIdentity)
	withIdentity := readyConditions(object, true, ProjectedSidecarIdentity)
	withExternalMediator := readyConditions(object, true, ExternalMediatorIdentity)
	without := withoutIdentity[2].(map[string]any)
	with := withIdentity[2].(map[string]any)
	external := withExternalMediator[2].(map[string]any)
	if without["reason"] != "IdentityNotRequired" ||
		with["reason"] != "EgressIdentityConfigured" ||
		external["reason"] != "ExternalMediatorConfigured" {
		t.Fatalf("identity conditions without=%#v with=%#v external=%#v", without, with, external)
	}
}

func TestStatusEquivalentIgnoresOnlyTransitionTime(t *testing.T) {
	left := map[string]any{"conditions": []any{map[string]any{
		"type": "Ready", "status": "False", "reason": "Pending", "lastTransitionTime": "first",
	}}}
	right := map[string]any{"conditions": []any{map[string]any{
		"type": "Ready", "status": "False", "reason": "Pending", "lastTransitionTime": "second",
	}}}
	if !statusEquivalent(left, right) {
		t.Fatal("transition time changed status equivalence")
	}
	right["conditions"].([]any)[0].(map[string]any)["reason"] = "Failed"
	if statusEquivalent(left, right) {
		t.Fatal("reason change was treated as equivalent")
	}
}

func TestOwnedByPoolRequiresControllerUID(t *testing.T) {
	controller := true
	pool := &unstructured.Unstructured{}
	pool.SetUID("pool-uid")
	refs := []metav1.OwnerReference{{Kind: "Pool", UID: "pool-uid", Controller: &controller}}
	if !ownedByPool(refs, pool) {
		t.Fatal("ownedByPool() = false")
	}
	refs[0].UID = "other"
	if ownedByPool(refs, pool) {
		t.Fatal("ownedByPool accepted wrong UID")
	}
}

func TestOwnedByRequiresControllerUID(t *testing.T) {
	controller := true
	workload := &unstructured.Unstructured{}
	workload.SetUID("workload-uid")
	refs := []metav1.OwnerReference{{Kind: "BatchSandbox", UID: "workload-uid", Controller: &controller}}
	if !ownedBy(refs, workload) {
		t.Fatal("ownedBy() = false")
	}
}
