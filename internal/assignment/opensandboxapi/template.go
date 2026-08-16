package opensandboxapi

import (
	"context"
	"errors"
	"fmt"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	templateGVR = schema.GroupVersionResource{
		Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxtemplates",
	}
	templateBundleGVR = schema.GroupVersionResource{
		Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "capabilitybundles",
	}
)

// ResolvedTemplate is the complete immutable sandbox shape selected by the
// trusted lifecycle service.
type ResolvedTemplate struct {
	Name                     string
	UID                      string
	Revision                 string
	Image                    string
	Entrypoint               []string
	CPU                      string
	Memory                   string
	TimeoutSeconds           int
	CapabilityBundleName     string
	CapabilityBundleRevision string
	LogicalTenant            string
}

// TemplateResolver resolves an administrator-owned sandbox shape.
type TemplateResolver interface {
	Resolve(context.Context, string) (ResolvedTemplate, error)
}

// KubernetesTemplateResolver resolves immutable templates and verifies their
// capability bundle revision directly against Kubernetes.
type KubernetesTemplateResolver struct {
	client    dynamic.Interface
	namespace string
}

func NewKubernetesTemplateResolver(client dynamic.Interface, namespace string) *KubernetesTemplateResolver {
	if client == nil || namespace == "" {
		panic("OpenSandbox template resolver requires a Kubernetes client and namespace")
	}
	return &KubernetesTemplateResolver{client: client, namespace: namespace}
}

func (r *KubernetesTemplateResolver) Resolve(ctx context.Context, name string) (ResolvedTemplate, error) {
	object, err := r.client.Resource(templateGVR).Namespace(r.namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return ResolvedTemplate{}, err
	}
	if object.GetDeletionTimestamp() != nil {
		return ResolvedTemplate{}, errors.New("sandbox template is deleting")
	}
	template := &assignmentv1alpha1.SandboxTemplate{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, template); err != nil {
		return ResolvedTemplate{}, fmt.Errorf("decode sandbox template: %w", err)
	}
	if !template.Spec.Enabled {
		return ResolvedTemplate{}, errors.New("sandbox template is disabled")
	}
	if template.Spec.TimeoutSeconds > int64(^uint(0)>>1) {
		return ResolvedTemplate{}, errors.New("sandbox template timeout exceeds platform integer range")
	}

	bundleObject, err := r.client.Resource(templateBundleGVR).Namespace(r.namespace).Get(
		ctx, template.Spec.CapabilityBundleRef.Name, metav1.GetOptions{},
	)
	if err != nil {
		return ResolvedTemplate{}, fmt.Errorf("get sandbox template capability bundle: %w", err)
	}
	if bundleObject.GetDeletionTimestamp() != nil {
		return ResolvedTemplate{}, errors.New("sandbox template capability bundle is deleting")
	}
	bundleSpec, found, err := unstructured.NestedMap(bundleObject.Object, "spec")
	if err != nil || !found {
		return ResolvedTemplate{}, errors.New("sandbox template capability bundle has no spec")
	}
	bundleRevision, err := governance.PolicyRevision(bundleSpec)
	if err != nil {
		return ResolvedTemplate{}, fmt.Errorf("hash sandbox template capability bundle: %w", err)
	}
	if bundleRevision != template.Spec.CapabilityBundleRef.PolicyRevision {
		return ResolvedTemplate{}, errors.New("sandbox template capability bundle revision is stale")
	}
	templateSpec, found, err := unstructured.NestedMap(object.Object, "spec")
	if err != nil || !found {
		return ResolvedTemplate{}, errors.New("sandbox template has no spec")
	}
	templateRevision, err := governance.PolicyRevision(templateSpec)
	if err != nil {
		return ResolvedTemplate{}, fmt.Errorf("hash sandbox template: %w", err)
	}

	logicalTenant, _, _ := unstructured.NestedString(bundleObject.Object, "spec", "governance", "logicalTenant")
	if logicalTenant == "" {
		return ResolvedTemplate{}, errors.New("sandbox template capability bundle has no logical tenant")
	}
	return ResolvedTemplate{
		Name:                     object.GetName(),
		UID:                      string(object.GetUID()),
		Revision:                 templateRevision,
		Image:                    template.Spec.Image,
		Entrypoint:               append([]string(nil), template.Spec.Entrypoint...),
		CPU:                      template.Spec.Resources.CPU,
		Memory:                   template.Spec.Resources.Memory,
		TimeoutSeconds:           int(template.Spec.TimeoutSeconds),
		CapabilityBundleName:     template.Spec.CapabilityBundleRef.Name,
		CapabilityBundleRevision: bundleRevision,
		LogicalTenant:            logicalTenant,
	}, nil
}
