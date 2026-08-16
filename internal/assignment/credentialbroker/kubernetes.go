package credentialbroker

import (
	"context"
	"errors"
	"fmt"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	assignmentGVR      = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxassignments"}
	credentialEventGVR = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxcredentialevents"}
)

type KubernetesGrantValidator struct {
	dynamic             dynamic.Interface
	kube                kubernetes.Interface
	assignmentNamespace string
	workloadNamespace   string
}

func NewKubernetesGrantValidator(dynamicClient dynamic.Interface, kube kubernetes.Interface, assignmentNamespace, workloadNamespace string) *KubernetesGrantValidator {
	return &KubernetesGrantValidator{
		dynamic: dynamicClient, kube: kube,
		assignmentNamespace: assignmentNamespace, workloadNamespace: workloadNamespace,
	}
}

func (v *KubernetesGrantValidator) ValidateGrant(ctx context.Context, claims GrantClaims) error {
	object, err := v.dynamic.Resource(assignmentGVR).Namespace(v.assignmentNamespace).Get(ctx, claims.AssignmentName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if object.GetDeletionTimestamp() != nil || string(object.GetUID()) != claims.AssignmentUID ||
		object.GetAnnotations()[assignment.PausedAnnotation] == "true" ||
		object.GetAnnotations()[assignment.SandboxIDAnnotation] != claims.SandboxID ||
		!conditionTrue(object, "Ready") {
		return errors.New("assignment binding is stale")
	}
	podName, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "name")
	podNamespace, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "namespace")
	podUID, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "uid")
	bundleName, _, _ := unstructured.NestedString(object.Object, "status", "resolvedCapabilityBundle", "name")
	bundleRevision, _, _ := unstructured.NestedString(object.Object, "status", "resolvedCapabilityBundle", "policyRevision")
	if podNamespace == "" {
		podNamespace = v.workloadNamespace
	}
	if podUID != claims.PodUID || bundleName != claims.CapabilityBundleName ||
		bundleRevision != claims.CapabilityBundleRevision {
		return errors.New("assignment policy or Pod incarnation changed")
	}
	pod, err := v.kube.CoreV1().Pods(podNamespace).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return err
	}
	if pod.DeletionTimestamp != nil || string(pod.UID) != claims.PodUID || pod.Status.Phase == corev1.PodFailed {
		return errors.New("sandbox Pod binding is stale")
	}
	return nil
}

type KubernetesAuditSink struct {
	dynamic   dynamic.Interface
	namespace string
}

func NewKubernetesAuditSink(dynamicClient dynamic.Interface, namespace string) *KubernetesAuditSink {
	return &KubernetesAuditSink{dynamic: dynamicClient, namespace: namespace}
}

func (s *KubernetesAuditSink) Record(ctx context.Context, event AuditEvent) error {
	claims := event.Grant
	value := &assignmentv1alpha1.SandboxCredentialEvent{
		TypeMeta: metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxCredentialEvent"},
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "credential-", Namespace: s.namespace,
			Labels: map[string]string{"aks-sandbox.azure.com/assignment": claims.AssignmentName},
		},
		Spec: assignmentv1alpha1.SandboxCredentialEventSpec{
			Timestamp: metav1.NewTime(event.Timestamp), GrantID: claims.ID, Action: event.Action,
			TaskID:        claims.TaskID,
			AssignmentRef: assignmentv1alpha1.AssignmentReference{Name: claims.AssignmentName, UID: types.UID(claims.AssignmentUID)},
			PodUID:        types.UID(claims.PodUID), SandboxID: claims.SandboxID,
			CapabilityBundleName:     claims.CapabilityBundleName,
			CapabilityBundleRevision: claims.CapabilityBundleRevision,
			Backend:                  claims.Backend, Method: claims.Method, Host: claims.Host, Path: claims.Path,
			ExpiresAt: metav1.NewTime(claims.ExpiresAt.Time),
		},
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(value)
	if err != nil {
		return err
	}
	_, err = s.dynamic.Resource(credentialEventGVR).Namespace(s.namespace).Create(
		ctx, &unstructured.Unstructured{Object: object}, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	)
	if apierrors.IsNotFound(err) {
		return fmt.Errorf("credential audit CRD is not installed: %w", err)
	}
	return err
}

func conditionTrue(object *unstructured.Unstructured, conditionType string) bool {
	conditions, _, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if ok && condition["type"] == conditionType && condition["status"] == "True" {
			return true
		}
	}
	return false
}
