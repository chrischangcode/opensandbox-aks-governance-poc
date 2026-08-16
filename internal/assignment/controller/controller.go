// Package controller binds SandboxAssignments to fresh OpenSandbox workloads and Pods.
package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"
	assignmentauthz "github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/authz"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	assignmentFinalizer = "aks-sandbox.azure.com/revoke-assignment"
	bundleFinalizer     = "aks-sandbox.azure.com/in-use-protection"
	identityAudience    = "aks-sandbox-capability-gateway"
	identityVolume      = "assignment-identity"
	identityContainer   = "egress"
	identityMountPath   = "/var/run/aks-sandbox-identity"
)

// EgressIdentityMode controls where the audience-restricted Pod identity is held.
type EgressIdentityMode string

const (
	// ProjectedSidecarIdentity requires a projected token mounted only by an egress sidecar.
	ProjectedSidecarIdentity EgressIdentityMode = "projected-sidecar"
	// ExternalMediatorIdentity allows a trusted external mediator to request a Pod-bound token.
	ExternalMediatorIdentity EgressIdentityMode = "external-mediator"
)

var (
	assignmentsGVR = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxassignments"}
	bundlesGVR     = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "capabilitybundles"}
	templatesGVR   = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxtemplates"}
	workloadsGVR   = schema.GroupVersionResource{Group: "sandbox.opensandbox.io", Version: "v1alpha1", Resource: "batchsandboxes"}
	poolsGVR       = schema.GroupVersionResource{Group: "sandbox.opensandbox.io", Version: "v1alpha1", Resource: "pools"}
)

// Config configures assignment reconciliation.
type Config struct {
	AssignmentNamespace   string
	WorkloadNamespace     string
	AllowedRuntimeClasses []string
	EgressIdentityMode    EgressIdentityMode
	Interval              time.Duration
}

// Controller reconciles assignments using Kubernetes API state.
type Controller struct {
	dynamic dynamic.Interface
	core    kubernetes.Interface
	config  Config
	logger  *slog.Logger
}

// New creates an assignment controller.
func New(dynamicClient dynamic.Interface, coreClient kubernetes.Interface, config Config, logger *slog.Logger) *Controller {
	if dynamicClient == nil || coreClient == nil {
		panic("assignment controller: nil Kubernetes client")
	}
	if config.AssignmentNamespace == "" || config.WorkloadNamespace == "" {
		panic("assignment controller: namespaces are required")
	}
	if len(config.AllowedRuntimeClasses) == 0 {
		config.AllowedRuntimeClasses = []string{"kata-vm-isolation", "kata-optimized", "self-kata-clh", "kata-clh"}
	}
	if config.EgressIdentityMode == "" {
		config.EgressIdentityMode = ProjectedSidecarIdentity
	}
	if config.EgressIdentityMode != ProjectedSidecarIdentity &&
		config.EgressIdentityMode != ExternalMediatorIdentity {
		panic("assignment controller: invalid egress identity mode")
	}
	if config.Interval <= 0 {
		config.Interval = 2 * time.Second
	}
	return &Controller{dynamic: dynamicClient, core: coreClient, config: config, logger: logger}
}

// Run reconciles all assignments immediately and on a bounded polling interval.
// Reconciliation is level-triggered, so missed events and restarts are safe.
func (c *Controller) Run(ctx context.Context) error {
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	for {
		if err := c.reconcileAll(ctx); err != nil && !errors.Is(err, context.Canceled) {
			c.logger.ErrorContext(ctx, "reconcile assignments", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (c *Controller) reconcileAll(ctx context.Context) error {
	list, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	var joined error
	for i := range list.Items {
		if err := c.reconcile(ctx, &list.Items[i]); err != nil {
			joined = errors.Join(joined, fmt.Errorf("%s: %w", list.Items[i].GetName(), err))
		}
	}
	return joined
}

func (c *Controller) reconcile(ctx context.Context, object *unstructured.Unstructured) error {
	if object.GetDeletionTimestamp() != nil {
		return c.finalize(ctx, object)
	}
	if !slices.Contains(object.GetFinalizers(), assignmentFinalizer) {
		copy := object.DeepCopy()
		copy.SetFinalizers(append(copy.GetFinalizers(), assignmentFinalizer))
		if _, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
			return err
		}
		return nil
	}

	typedAssignment, err := assignmentFromUnstructured(object)
	if err != nil {
		return err
	}
	bundleName := typedAssignment.Spec.CapabilityBundleRef.Name
	var resolvedTemplate *assignmentv1alpha1.SandboxTemplate
	if typedAssignment.Spec.TemplateRef.Name != "" {
		templateObject, err := c.dynamic.Resource(templatesGVR).Namespace(c.config.AssignmentNamespace).Get(
			ctx, typedAssignment.Spec.TemplateRef.Name, metav1.GetOptions{},
		)
		if err != nil || templateObject.GetDeletionTimestamp() != nil {
			return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "TemplateNotFound", "sandbox template is unavailable"))
		}
		if string(templateObject.GetUID()) != string(typedAssignment.Spec.TemplateRef.UID) {
			return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "TemplateReplaced", "sandbox template incarnation changed"))
		}
		templateRevision, err := policyRevision(templateObject)
		if err != nil || templateRevision != typedAssignment.Spec.TemplateRef.SpecRevision {
			return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "TemplateRevisionMismatch", "sandbox template revision changed"))
		}
		resolvedTemplate = &assignmentv1alpha1.SandboxTemplate{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(templateObject.Object, resolvedTemplate); err != nil {
			return err
		}
		if !resolvedTemplate.Spec.Enabled ||
			resolvedTemplate.Spec.CapabilityBundleRef.Name != bundleName {
			return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "TemplateInvalid", "sandbox template is disabled or selects a different capability bundle"))
		}
	}
	bundle, err := c.dynamic.Resource(bundlesGVR).Namespace(c.config.AssignmentNamespace).Get(ctx, bundleName, metav1.GetOptions{})
	if err != nil || bundle.GetDeletionTimestamp() != nil {
		return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "BundleNotFound", "capability bundle is unavailable"))
	}
	typedBundle, err := bundleFromUnstructured(bundle)
	if err != nil {
		return err
	}
	if err := validateBundlePolicy(typedBundle); err != nil {
		return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "BundleInvalid", err.Error()))
	}
	if !slices.Contains(bundle.GetFinalizers(), bundleFinalizer) {
		copy := bundle.DeepCopy()
		copy.SetFinalizers(append(copy.GetFinalizers(), bundleFinalizer))
		if _, err := c.dynamic.Resource(bundlesGVR).Namespace(c.config.AssignmentNamespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
			return err
		}
		return nil
	}
	revision, err := policyRevision(bundle)
	if err != nil {
		return err
	}
	if resolvedTemplate != nil &&
		(resolvedTemplate.Spec.CapabilityBundleRef.PolicyRevision != revision ||
			typedAssignment.Spec.LogicalTenant == "" ||
			typedBundle.Spec.Governance == nil ||
			typedAssignment.Spec.LogicalTenant != typedBundle.Spec.Governance.LogicalTenant) {
		return c.updateStatus(ctx, object, nil, nil, nil, progressConditions(object, false, false, false, "TemplateBoundaryMismatch", "sandbox template, assignment tenant, and capability revision do not match"))
	}
	resolved := map[string]any{"name": bundle.GetName(), "uid": string(bundle.GetUID()), "policyRevision": revision}
	identityRequired := typedBundle.Spec.Egress != nil && len(typedBundle.Spec.Egress.Agentgateway) > 0
	if object.GetAnnotations()[assignment.PausedAnnotation] == "true" {
		workloadRef, _, _ := unstructured.NestedMap(object.Object, "status", "workloadRef")
		podRef, podBound, _ := unstructured.NestedMap(object.Object, "status", "podRef")
		return c.updateStatus(ctx, object, resolved, workloadRef, podRef, progressConditions(object, true, podBound, false, "Paused", "sandbox capability is paused"))
	}

	workloads, err := c.matchingWorkloads(ctx, object)
	if err != nil {
		return err
	}
	if len(workloads) != 1 {
		reason := "WorkloadPending"
		message := "waiting for exactly one fresh BatchSandbox"
		if len(workloads) > 1 {
			reason, message = "MultipleWorkloads", "more than one BatchSandbox claims the assignment"
		}
		return c.updateStatus(ctx, object, resolved, nil, nil, progressConditions(object, true, false, false, reason, message))
	}
	workload := &workloads[0]
	if object.GetAnnotations()[assignment.SandboxIDAnnotation] == "" {
		copy := object.DeepCopy()
		annotations := copy.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[assignment.SandboxIDAnnotation] = workload.GetName()
		copy.SetAnnotations(annotations)
		labels := copy.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[assignment.SandboxIDLabel] = workload.GetName()
		copy.SetLabels(labels)
		_, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).Update(
			ctx, copy, metav1.UpdateOptions{},
		)
		return err
	}
	replicas, found, _ := unstructured.NestedInt64(workload.Object, "spec", "replicas")
	if !found || replicas != 1 {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), nil, progressConditions(object, true, false, false, "InvalidReplicaCount", "BatchSandbox must request exactly one Pod"))
	}
	if workload.GetCreationTimestamp().Time.Before(object.GetCreationTimestamp().Time) {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), nil, progressConditions(object, true, false, false, "StaleWorkload", "BatchSandbox predates assignment"))
	}

	poolRef, _, _ := unstructured.NestedString(workload.Object, "spec", "poolRef")
	pods, err := c.matchingPods(ctx, object, workload, poolRef)
	if err != nil {
		return err
	}
	if len(pods) != 1 {
		reason := "PodPending"
		message := "waiting for exactly one owned Pod"
		if len(pods) > 1 {
			reason, message = "MultiplePods", "more than one live Pod is owned by the BatchSandbox"
		}
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), nil, progressConditions(object, true, false, false, reason, message))
	}
	pod := &pods[0]
	if err := validateServiceAccountReference(pod); err != nil {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "ServiceAccountNotReady", err.Error()))
	}
	serviceAccount, err := c.core.CoreV1().ServiceAccounts(c.config.WorkloadNamespace).Get(ctx, pod.Spec.ServiceAccountName, metav1.GetOptions{})
	if err != nil {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "ServiceAccountNotReady", "sandbox ServiceAccount is unavailable"))
	}
	if err := validateEligibleServiceAccount(serviceAccount); err != nil {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "ServiceAccountNotReady", err.Error()))
	}
	if err := validatePodServiceAccountIsolation(pod); err != nil {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "ServiceAccountNotReady", err.Error()))
	}
	if fencedUID := object.GetAnnotations()[assignment.ResumeAfterPodUIDAnnotation]; fencedUID != "" && fencedUID == string(pod.UID) {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, false, false, "ResumePending", "waiting for a fresh Pod incarnation"))
	}
	if poolRef == "" && pod.CreationTimestamp.Time.Before(object.GetCreationTimestamp().Time) {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, false, false, "StalePod", "owned Pod predates assignment"))
	}
	if !slices.Contains(c.config.AllowedRuntimeClasses, runtimeClassName(pod)) {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "RuntimeNotAllowed", "bound Pod does not use an approved runtime class"))
	}
	if !podReady(pod) {
		return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "PodNotReady", "bound Pod is not ready"))
	}
	if identityRequired {
		var err error
		switch c.config.EgressIdentityMode {
		case ExternalMediatorIdentity:
			err = validateExternalMediatorIdentity(pod)
		default:
			err = validateIdentity(pod)
		}
		if err != nil {
			return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), progressConditions(object, true, true, false, "IdentityNotReady", err.Error()))
		}
	}
	return c.updateStatus(ctx, object, resolved, workloadReference(workload), podReference(pod), readyConditions(object, identityRequired, c.config.EgressIdentityMode))
}

func (c *Controller) matchingWorkloads(ctx context.Context, object *unstructured.Unstructured) ([]unstructured.Unstructured, error) {
	selector := fmt.Sprintf("%s=%s", assignment.AssignmentLabel, object.GetName())
	list, err := c.dynamic.Resource(workloadsGVR).Namespace(c.config.WorkloadNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	result := make([]unstructured.Unstructured, 0, len(list.Items))
	for i := range list.Items {
		item := &list.Items[i]
		if assignmentUID(item.GetAnnotations()) == string(object.GetUID()) {
			result = append(result, *item)
		}
	}
	return result, nil
}

func (c *Controller) matchingPods(ctx context.Context, object *unstructured.Unstructured, workload *unstructured.Unstructured, poolRef string) ([]corev1.Pod, error) {
	if poolRef != "" {
		return c.allocatedPoolPods(ctx, workload, poolRef)
	}
	selector := fmt.Sprintf("%s=%s", assignment.AssignmentLabel, object.GetName())
	list, err := c.core.CoreV1().Pods(c.config.WorkloadNamespace).List(ctx, metav1.ListOptions{LabelSelector: selector})
	if err != nil {
		return nil, err
	}
	result := make([]corev1.Pod, 0, len(list.Items))
	for i := range list.Items {
		pod := &list.Items[i]
		if assignmentUID(pod.Annotations) != string(object.GetUID()) || !ownedBy(pod.OwnerReferences, workload) {
			continue
		}
		if pod.DeletionTimestamp == nil {
			result = append(result, *pod)
		}
	}
	return result, nil
}

func (c *Controller) allocatedPoolPods(ctx context.Context, workload *unstructured.Unstructured, poolRef string) ([]corev1.Pod, error) {
	pool, err := c.dynamic.Resource(poolsGVR).Namespace(c.config.WorkloadNamespace).Get(ctx, poolRef, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	recycleType, _, _ := unstructured.NestedString(pool.Object, "spec", "recycleStrategy", "type")
	if recycleType != "Delete" && recycleType != "Replace" {
		return nil, fmt.Errorf("pool %q must use Delete/Replace recycle strategy", poolRef)
	}
	var allocation struct {
		Pods []string `json:"pods"`
	}
	raw := workload.GetAnnotations()["sandbox.opensandbox.io/alloc-status"]
	if raw == "" {
		return nil, nil
	}
	if err := json.Unmarshal([]byte(raw), &allocation); err != nil {
		return nil, fmt.Errorf("parse Pool allocation: %w", err)
	}
	if len(allocation.Pods) != 1 {
		if len(allocation.Pods) == 0 {
			return nil, nil
		}
		return nil, fmt.Errorf("Pool allocation contains %d Pods", len(allocation.Pods))
	}
	pod, err := c.core.CoreV1().Pods(c.config.WorkloadNamespace).Get(ctx, allocation.Pods[0], metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if pod.DeletionTimestamp != nil || !ownedByPool(pod.OwnerReferences, pool) {
		return nil, fmt.Errorf("allocated Pod is not owned by replacement Pool %q", poolRef)
	}
	return []corev1.Pod{*pod}, nil
}

func (c *Controller) finalize(ctx context.Context, object *unstructured.Unstructured) error {
	if !slices.Contains(object.GetFinalizers(), assignmentFinalizer) {
		return nil
	}
	workloadName, _, _ := unstructured.NestedString(object.Object, "status", "workloadRef", "name")
	workloadNamespace, _, _ := unstructured.NestedString(object.Object, "status", "workloadRef", "namespace")
	if workloadNamespace == "" {
		workloadNamespace = c.config.WorkloadNamespace
	}
	workloadNames := []string{}
	if workloadName != "" {
		workloadNames = append(workloadNames, workloadName)
	} else {
		workloads, err := c.matchingWorkloads(ctx, object)
		if err != nil {
			return err
		}
		for i := range workloads {
			workloadNames = append(workloadNames, workloads[i].GetName())
		}
	}
	for _, name := range workloadNames {
		err := c.dynamic.Resource(workloadsGVR).Namespace(workloadNamespace).Delete(ctx, name, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
		if _, err := c.dynamic.Resource(workloadsGVR).Namespace(workloadNamespace).Get(ctx, name, metav1.GetOptions{}); err == nil {
			return nil
		} else if !apierrors.IsNotFound(err) {
			return err
		}
	}
	statusPodName, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "name")
	statusPodUID, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "uid")
	if statusPodName != "" {
		pod, err := c.core.CoreV1().Pods(c.config.WorkloadNamespace).Get(ctx, statusPodName, metav1.GetOptions{})
		if err == nil && string(pod.UID) == statusPodUID {
			return nil
		}
		if err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	pods, err := c.core.CoreV1().Pods(c.config.WorkloadNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=%s", assignment.AssignmentLabel, object.GetName()),
	})
	if err != nil {
		return err
	}
	for i := range pods.Items {
		if assignmentUID(pods.Items[i].Annotations) == string(object.GetUID()) {
			return nil
		}
	}

	copy := object.DeepCopy()
	copy.SetFinalizers(slices.DeleteFunc(copy.GetFinalizers(), func(value string) bool { return value == assignmentFinalizer }))
	if _, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).Update(ctx, copy, metav1.UpdateOptions{}); err != nil {
		return err
	}
	return c.releaseBundleIfUnused(ctx, object)
}

func (c *Controller) releaseBundleIfUnused(ctx context.Context, object *unstructured.Unstructured) error {
	typedAssignment, err := assignmentFromUnstructured(object)
	if err != nil {
		return err
	}
	bundleName := typedAssignment.Spec.CapabilityBundleRef.Name
	assignments, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	for i := range assignments.Items {
		item := &assignments.Items[i]
		typedItem, err := assignmentFromUnstructured(item)
		if err != nil {
			return err
		}
		if item.GetUID() != object.GetUID() && typedItem.Spec.CapabilityBundleRef.Name == bundleName {
			return nil
		}
	}
	bundle, err := c.dynamic.Resource(bundlesGVR).Namespace(c.config.AssignmentNamespace).Get(ctx, bundleName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return err
	}
	copy := bundle.DeepCopy()
	copy.SetFinalizers(slices.DeleteFunc(copy.GetFinalizers(), func(value string) bool { return value == bundleFinalizer }))
	_, err = c.dynamic.Resource(bundlesGVR).Namespace(c.config.AssignmentNamespace).Update(ctx, copy, metav1.UpdateOptions{})
	return err
}

func (c *Controller) updateStatus(ctx context.Context, object *unstructured.Unstructured, resolved, workloadRef, podRef map[string]any, conditionValues []any) error {
	copy := object.DeepCopy()
	status := map[string]any{"conditions": conditionValues}
	if resolved != nil {
		status["resolvedCapabilityBundle"] = resolved
	}
	if workloadRef != nil {
		status["workloadRef"] = workloadRef
	}
	if podRef != nil {
		status["podRef"] = podRef
	}
	oldStatus, _, _ := unstructured.NestedMap(object.Object, "status")
	if statusEquivalent(oldStatus, status) {
		return nil
	}
	copy.Object["status"] = status
	_, err := c.dynamic.Resource(assignmentsGVR).Namespace(c.config.AssignmentNamespace).UpdateStatus(ctx, copy, metav1.UpdateOptions{})
	return err
}

func statusEquivalent(left, right map[string]any) bool {
	stripTransitionTimes := func(input map[string]any) map[string]any {
		copy := deepCopyMap(input)
		conditions, _, _ := unstructured.NestedSlice(copy, "conditions")
		for _, raw := range conditions {
			if condition, ok := raw.(map[string]any); ok {
				delete(condition, "lastTransitionTime")
			}
		}
		_ = unstructured.SetNestedSlice(copy, conditions, "conditions")
		return copy
	}
	return reflect.DeepEqual(stripTransitionTimes(left), stripTransitionTimes(right))
}

func deepCopyMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	return runtime.DeepCopyJSON(input)
}

func assignmentFromUnstructured(object *unstructured.Unstructured) (*assignmentv1alpha1.SandboxAssignment, error) {
	result := &assignmentv1alpha1.SandboxAssignment{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, result); err != nil {
		return nil, fmt.Errorf("convert SandboxAssignment %q: %w", object.GetName(), err)
	}
	return result, nil
}

func bundleFromUnstructured(object *unstructured.Unstructured) (*assignmentv1alpha1.CapabilityBundle, error) {
	result := &assignmentv1alpha1.CapabilityBundle{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, result); err != nil {
		return nil, fmt.Errorf("convert CapabilityBundle %q: %w", object.GetName(), err)
	}
	return result, nil
}

func validateBundlePolicy(bundle *assignmentv1alpha1.CapabilityBundle) error {
	if bundle.Spec.Egress == nil {
		return nil
	}
	for backend, policy := range bundle.Spec.Egress.Agentgateway {
		if policy.Allow == "" {
			return fmt.Errorf("backend %q allow expression is missing", backend)
		}
		if err := assignmentauthz.ValidateAllowExpression(policy.Allow); err != nil {
			return fmt.Errorf("backend %q allow expression: %w", backend, err)
		}
	}
	return nil
}

func policyRevision(bundle *unstructured.Unstructured) (string, error) {
	spec, _, _ := unstructured.NestedMap(bundle.Object, "spec")
	return governance.PolicyRevision(spec)
}

func workloadReference(workload *unstructured.Unstructured) map[string]any {
	return map[string]any{"apiVersion": workload.GetAPIVersion(), "kind": workload.GetKind(), "namespace": workload.GetNamespace(), "name": workload.GetName(), "uid": string(workload.GetUID())}
}

func podReference(pod *corev1.Pod) map[string]any {
	return map[string]any{"apiVersion": "v1", "kind": "Pod", "namespace": pod.Namespace, "name": pod.Name, "uid": string(pod.UID)}
}

func ownedBy(references []metav1.OwnerReference, workload *unstructured.Unstructured) bool {
	for _, reference := range references {
		if reference.Controller != nil && *reference.Controller && reference.Kind == "BatchSandbox" && reference.UID == workload.GetUID() {
			return true
		}
	}
	return false
}

func validateServiceAccountReference(pod *corev1.Pod) error {
	if pod.Spec.ServiceAccountName == "" {
		return errors.New("bound Pod does not declare a ServiceAccount")
	}
	return nil
}

func validateEligibleServiceAccount(serviceAccount *corev1.ServiceAccount) error {
	if serviceAccount.Labels[assignment.EligibleServiceAccountLabel] != "true" {
		return fmt.Errorf("ServiceAccount %q is not platform-eligible", serviceAccount.Name)
	}
	if serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken {
		return fmt.Errorf("ServiceAccount %q must disable token automount", serviceAccount.Name)
	}
	return nil
}

func assignmentUID(annotations map[string]string) string {
	if value := annotations[assignment.OpenSandboxAssignmentUIDAnnotation]; value != "" {
		return value
	}
	return annotations[assignment.AssignmentUIDAnnotation]
}

func runtimeClassName(pod *corev1.Pod) string {
	if pod.Spec.RuntimeClassName == nil {
		return ""
	}
	return *pod.Spec.RuntimeClassName
}

func ownedByPool(references []metav1.OwnerReference, pool *unstructured.Unstructured) bool {
	for _, reference := range references {
		if reference.Controller != nil && *reference.Controller && reference.Kind == "Pool" && reference.UID == pool.GetUID() {
			return true
		}
	}
	return false
}

func podReady(pod *corev1.Pod) bool {
	for _, condition := range pod.Status.Conditions {
		if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
			return true
		}
	}
	return false
}

func validateIdentity(pod *corev1.Pod) error {
	if err := validatePodServiceAccountIsolation(pod); err != nil {
		return err
	}
	foundProjection := false
	for _, volume := range pod.Spec.Volumes {
		if volume.Name != identityVolume || volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			token := source.ServiceAccountToken
			if token != nil && token.Path == "token" && token.Audience == identityAudience && token.ExpirationSeconds != nil && *token.ExpirationSeconds > 0 && *token.ExpirationSeconds <= 600 {
				foundProjection = true
			}
		}
	}
	if !foundProjection {
		return errors.New("required Pod-bound identity projection is missing")
	}
	mountedByEgress := false
	for _, container := range pod.Spec.Containers {
		for _, mount := range container.VolumeMounts {
			if mount.Name != identityVolume {
				continue
			}
			if container.Name != identityContainer || !mount.ReadOnly || mount.MountPath != identityMountPath || mount.SubPath != "" || mount.SubPathExpr != "" {
				return fmt.Errorf("identity volume has an invalid mount in container %q", container.Name)
			}
			mountedByEgress = true
		}
	}
	if !mountedByEgress {
		return errors.New("identity volume is not mounted by egress")
	}
	return nil
}

func validatePodServiceAccountIsolation(pod *corev1.Pod) error {
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return errors.New("automountServiceAccountToken must be false")
	}
	return nil
}

func validateExternalMediatorIdentity(pod *corev1.Pod) error {
	for _, volume := range pod.Spec.Volumes {
		if volume.Projected == nil {
			continue
		}
		for _, source := range volume.Projected.Sources {
			if source.ServiceAccountToken != nil {
				return errors.New("external mediator mode forbids projected service account tokens")
			}
		}
	}
	return nil
}

func readyConditions(object *unstructured.Unstructured, identityRequired bool, mode EgressIdentityMode) []any {
	identityReason, identityMessage := "IdentityNotRequired", "bundle has no mediated egress policy"
	if identityRequired {
		switch mode {
		case ExternalMediatorIdentity:
			identityReason, identityMessage = "ExternalMediatorConfigured", "trusted mediator issues an audience-restricted token bound to the sandbox Pod"
		default:
			identityReason, identityMessage = "EgressIdentityConfigured", "identity projection is isolated to egress"
		}
	}
	return []any{
		condition(object, "BundleResolved", true, "BundleValid", "immutable bundle resolved"),
		condition(object, "PodBound", true, "FreshPodObserved", "fresh owned Pod bound"),
		condition(object, "IdentityReady", true, identityReason, identityMessage),
		condition(object, "Ready", true, "AssignmentReady", "assignment enforcement is ready"),
	}
}

func progressConditions(object *unstructured.Unstructured, bundleResolved, podBound, identityReady bool, reason, message string) []any {
	bundleReason, bundleMessage := reason, message
	if bundleResolved {
		bundleReason, bundleMessage = "BundleValid", "immutable bundle resolved"
	}
	podReason, podMessage := reason, message
	if podBound {
		podReason, podMessage = "FreshPodObserved", "fresh owned Pod bound"
	}
	identityReason, identityMessage := reason, message
	if identityReady {
		identityReason, identityMessage = "EgressIdentityConfigured", "identity projection is isolated to egress"
	}
	return []any{
		condition(object, "BundleResolved", bundleResolved, bundleReason, bundleMessage),
		condition(object, "PodBound", podBound, podReason, podMessage),
		condition(object, "IdentityReady", identityReady, identityReason, identityMessage),
		condition(object, "Ready", false, reason, message),
	}
}

func condition(object *unstructured.Unstructured, kind string, value bool, reason, message string) map[string]any {
	status := "False"
	if value {
		status = "True"
	}
	return map[string]any{
		"type": kind, "status": status, "reason": reason, "message": message,
		"observedGeneration": object.GetGeneration(), "lastTransitionTime": time.Now().UTC().Format(time.RFC3339),
	}
}
