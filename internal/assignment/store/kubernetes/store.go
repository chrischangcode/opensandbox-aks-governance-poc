// Package kubernetes implements assignment storage using Kubernetes CRDs.
package kubernetes

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicinformer "k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
)

var (
	assignmentsGVR = schema.GroupVersionResource{
		Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxassignments",
	}
	bundlesGVR = schema.GroupVersionResource{
		Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "capabilitybundles",
	}
)

const sandboxIDIndex = "sandboxID"

// Store persists assignments through a dynamic Kubernetes client and indexes
// watched assignment state by OpenSandbox ID.
type Store struct {
	client   dynamic.Interface
	informer cache.SharedIndexInformer
}

// NewStore creates a Kubernetes-backed assignment store.
func NewStore(client dynamic.Interface, namespace string) *Store {
	if client == nil {
		panic("assignment kubernetes store: nil client")
	}
	informer := dynamicinformer.NewFilteredDynamicSharedInformerFactory(client, 0, namespace, nil).
		ForResource(assignmentsGVR).Informer()
	if err := informer.AddIndexers(cache.Indexers{sandboxIDIndex: sandboxIDsForObject}); err != nil {
		panic(err)
	}
	return &Store{client: client, informer: informer}
}

// Start runs the assignment watch and waits for its initial list to synchronize.
func (s *Store) Start(ctx context.Context) error {
	go s.informer.Run(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), s.informer.HasSynced) {
		return errors.New("synchronize assignment cache")
	}
	return nil
}

// Create verifies the referenced bundle and creates a pending assignment.
func (s *Store) Create(ctx context.Context, request assignment.CreateRequest) (*assignment.Assignment, error) {
	bundle, err := s.client.Resource(bundlesGVR).Namespace(request.Namespace).Get(
		ctx, request.CapabilityBundleName, metav1.GetOptions{},
	)
	if err != nil {
		return nil, fmt.Errorf("get capability bundle: %w", err)
	}
	if bundle.GetDeletionTimestamp() != nil {
		return nil, errors.New("capability bundle is deleting")
	}

	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1",
		"kind":       "SandboxAssignment",
		"metadata": map[string]any{
			"namespace":    request.Namespace,
			"name":         request.Name,
			"generateName": request.GenerateName,
			"annotations": map[string]any{
				assignment.IdempotencyKeyAnnotation: request.IdempotencyKey,
				assignment.RequestHashAnnotation:    request.RequestHash,
			},
		},
		"spec": map[string]any{
			"templateRef": map[string]any{
				"name":         request.TemplateName,
				"uid":          request.TemplateUID,
				"specRevision": request.TemplateRevision,
			},
			"logicalTenant":       request.LogicalTenant,
			"capabilityBundleRef": map[string]any{"name": request.CapabilityBundleName},
		},
	}}
	removeEmptyMetadata(object)

	created, err := s.client.Resource(assignmentsGVR).Namespace(request.Namespace).Create(
		ctx, object, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	)
	if apierrors.IsAlreadyExists(err) && request.Name != "" {
		existing, getErr := s.client.Resource(assignmentsGVR).Namespace(request.Namespace).Get(
			ctx, request.Name, metav1.GetOptions{},
		)
		if getErr != nil {
			return nil, getErr
		}
		annotations := existing.GetAnnotations()
		logicalTenant, _, _ := unstructured.NestedString(existing.Object, "spec", "logicalTenant")
		if annotations[assignment.IdempotencyKeyAnnotation] != request.IdempotencyKey ||
			annotations[assignment.RequestHashAnnotation] != request.RequestHash ||
			logicalTenant != request.LogicalTenant {
			return nil, assignment.ErrIdempotencyConflict
		}
		result, convertErr := convert(existing)
		if convertErr != nil {
			return nil, convertErr
		}
		result.Existing = true
		return result, nil
	}
	if err != nil {
		return nil, fmt.Errorf("create sandbox assignment: %w", err)
	}
	return convert(created)
}

// Get returns one assignment.
func (s *Store) Get(ctx context.Context, namespace, name string) (*assignment.Assignment, error) {
	object, err := s.client.Resource(assignmentsGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return convert(object)
}

// GetBySandboxID resolves an assignment by the trusted OpenSandbox mapping or
// by its reconciled workload reference.
func (s *Store) GetBySandboxID(ctx context.Context, namespace, sandboxID string) (*assignment.Assignment, error) {
	objects, err := s.informer.GetIndexer().ByIndex(sandboxIDIndex, sandboxID)
	if err != nil {
		return nil, err
	}
	if len(objects) == 1 {
		return convert(objects[0].(*unstructured.Unstructured).DeepCopy())
	}
	if len(objects) > 1 {
		return nil, fmt.Errorf("multiple assignments map to OpenSandbox ID %q", sandboxID)
	}

	// Close the small watch-propagation window immediately after create without
	// falling back to an unfiltered namespace-wide list.
	list, err := s.client.Resource(assignmentsGVR).Namespace(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.Set{assignment.SandboxIDLabel: sandboxID}.AsSelector().String(),
		Limit:         2,
	})
	if err != nil {
		return nil, err
	}
	if len(list.Items) == 1 {
		return convert(&list.Items[0])
	}
	if len(list.Items) > 1 {
		return nil, fmt.Errorf("multiple assignments map to OpenSandbox ID %q", sandboxID)
	}
	return nil, apierrors.NewNotFound(assignmentsGVR.GroupResource(), sandboxID)
}

// SetSandboxID records the OpenSandbox ID returned by lifecycle creation.
func (s *Store) SetSandboxID(ctx context.Context, namespace, name, sandboxID string) error {
	return s.updateObjectMetadata(ctx, namespace, name, func(annotations, objectLabels map[string]string) {
		annotations[assignment.SandboxIDAnnotation] = sandboxID
		objectLabels[assignment.SandboxIDLabel] = sandboxID
	})
}

// SetLifecycleFence records pause intent and the Pod UID that resume must replace.
func (s *Store) SetLifecycleFence(ctx context.Context, namespace, name string, paused bool, resumeAfterPodUID string) error {
	return s.updateObjectMetadata(ctx, namespace, name, func(values, _ map[string]string) {
		if paused {
			values[assignment.PausedAnnotation] = "true"
		} else {
			delete(values, assignment.PausedAnnotation)
		}
		if resumeAfterPodUID != "" {
			values[assignment.ResumeAfterPodUIDAnnotation] = resumeAfterPodUID
		} else {
			delete(values, assignment.ResumeAfterPodUIDAnnotation)
		}
	})
}

func (s *Store) updateObjectMetadata(ctx context.Context, namespace, name string, mutate func(map[string]string, map[string]string)) error {
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		object, err := s.client.Resource(assignmentsGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return err
		}
		values := object.GetAnnotations()
		if values == nil {
			values = map[string]string{}
		}
		objectLabels := object.GetLabels()
		if objectLabels == nil {
			objectLabels = map[string]string{}
		}
		mutate(values, objectLabels)
		object.SetAnnotations(values)
		object.SetLabels(objectLabels)
		_, err = s.client.Resource(assignmentsGVR).Namespace(namespace).Update(ctx, object, metav1.UpdateOptions{})
		return err
	})
}

// Delete begins assignment revocation and deletion.
func (s *Store) Delete(ctx context.Context, namespace, name string) error {
	return s.client.Resource(assignmentsGVR).Namespace(namespace).Delete(ctx, name, metav1.DeleteOptions{})
}

func convert(object *unstructured.Unstructured) (*assignment.Assignment, error) {
	bundleName, _, err := unstructured.NestedString(object.Object, "spec", "capabilityBundleRef", "name")
	if err != nil {
		return nil, fmt.Errorf("read capability bundle reference: %w", err)
	}
	templateName, _, err := unstructured.NestedString(object.Object, "spec", "templateRef", "name")
	if err != nil {
		return nil, fmt.Errorf("read sandbox template reference: %w", err)
	}
	templateUID, _, _ := unstructured.NestedString(object.Object, "spec", "templateRef", "uid")
	templateRevision, _, _ := unstructured.NestedString(object.Object, "spec", "templateRef", "specRevision")
	logicalTenant, _, _ := unstructured.NestedString(object.Object, "spec", "logicalTenant")
	result := &assignment.Assignment{
		Namespace:            object.GetNamespace(),
		Name:                 object.GetName(),
		UID:                  string(object.GetUID()),
		ResourceVersion:      object.GetResourceVersion(),
		TemplateName:         templateName,
		TemplateUID:          templateUID,
		TemplateRevision:     templateRevision,
		LogicalTenant:        logicalTenant,
		CapabilityBundleName: bundleName,
		SandboxID:            object.GetAnnotations()[assignment.SandboxIDAnnotation],
		IdempotencyKey:       object.GetAnnotations()[assignment.IdempotencyKeyAnnotation],
		RequestHash:          object.GetAnnotations()[assignment.RequestHashAnnotation],
		CreatedAt:            object.GetCreationTimestamp().Time,
		Deleting:             object.GetDeletionTimestamp() != nil,
	}

	conditions, _, err := unstructured.NestedSlice(object.Object, "status", "conditions")
	if err != nil {
		return nil, fmt.Errorf("read conditions: %w", err)
	}
	for _, raw := range conditions {
		conditionMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		condition := assignment.Condition{
			Type:    stringField(conditionMap, "type"),
			Status:  stringField(conditionMap, "status"),
			Reason:  stringField(conditionMap, "reason"),
			Message: stringField(conditionMap, "message"),
		}
		result.Conditions = append(result.Conditions, condition)
		if condition.Type == "Ready" && condition.Status == "True" {
			result.Ready = true
		}
	}
	result.WorkloadRef = objectReference(object.Object, "workloadRef")
	if result.SandboxID == "" && result.WorkloadRef != nil {
		result.SandboxID = result.WorkloadRef.Name
	}
	result.PodRef = objectReference(object.Object, "podRef")
	return result, nil
}

func objectReference(object map[string]any, field string) *assignment.ObjectReference {
	value, found, _ := unstructured.NestedMap(object, "status", field)
	if !found {
		return nil
	}
	return &assignment.ObjectReference{
		APIVersion: stringField(value, "apiVersion"),
		Kind:       stringField(value, "kind"),
		Namespace:  stringField(value, "namespace"),
		Name:       stringField(value, "name"),
		UID:        stringField(value, "uid"),
	}
}

func stringField(object map[string]any, name string) string {
	value, _ := object[name].(string)
	return value
}

func sandboxIDsForObject(raw any) ([]string, error) {
	object, ok := raw.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected assignment cache object %T", raw)
	}
	ids := []string{}
	if mapped := object.GetAnnotations()[assignment.SandboxIDAnnotation]; mapped != "" {
		ids = append(ids, mapped)
	}
	if workloadName, _, _ := unstructured.NestedString(object.Object, "status", "workloadRef", "name"); workloadName != "" && !slices.Contains(ids, workloadName) {
		ids = append(ids, workloadName)
	}
	return ids, nil
}

func removeEmptyMetadata(object *unstructured.Unstructured) {
	metadata, _, _ := unstructured.NestedMap(object.Object, "metadata")
	for _, field := range []string{"name", "generateName"} {
		if metadata[field] == "" {
			delete(metadata, field)
		}
	}
	_ = unstructured.SetNestedMap(object.Object, metadata, "metadata")
}
