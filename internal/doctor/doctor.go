// Package doctor evaluates whether a cluster satisfies the governed sandbox
// runtime contract before a workload is admitted.
package doctor

import (
	"context"
	"fmt"
	"sort"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/selection"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

const (
	StatusPass    = "pass"
	StatusWarning = "warning"
	StatusFail    = "fail"
)

var (
	crdGVR      = schema.GroupVersionResource{Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions"}
	templateGVR = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxtemplates"}
	bundleGVR   = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "capabilitybundles"}
	tenantGVR   = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxtenantpolicies"}
)

type Config struct {
	AssignmentNamespace string
	WorkloadNamespace   string
	RuntimeClass        string
}

type Check struct {
	Name        string `json:"name"`
	Status      string `json:"status"`
	Summary     string `json:"summary"`
	Remediation string `json:"remediation,omitempty"`
}

type Report struct {
	Ready  bool    `json:"ready"`
	Checks []Check `json:"checks"`
}

type Runner struct {
	kube    kubernetes.Interface
	dynamic dynamic.Interface
	config  Config
}

func New(kube kubernetes.Interface, dynamicClient dynamic.Interface, config Config) *Runner {
	if config.AssignmentNamespace == "" {
		config.AssignmentNamespace = "aks-sandbox-system"
	}
	if config.WorkloadNamespace == "" {
		config.WorkloadNamespace = "opensandbox"
	}
	if config.RuntimeClass == "" {
		config.RuntimeClass = "kata-optimized"
	}
	return &Runner{kube: kube, dynamic: dynamicClient, config: config}
}

func (r *Runner) Run(ctx context.Context) Report {
	checks := []Check{
		r.runtimeClass(ctx),
		r.kataCapacity(ctx),
		r.governanceCRDs(ctx),
		r.assignmentService(ctx),
		r.openSandboxService(ctx),
		r.sandboxServiceAccount(ctx),
		r.governanceInventory(ctx),
		r.resourceQuota(ctx),
		r.networkPolicy(ctx),
	}
	ready := true
	for _, check := range checks {
		if check.Status == StatusFail {
			ready = false
			break
		}
	}
	return Report{Ready: ready, Checks: checks}
}

func (r *Runner) runtimeClass(ctx context.Context) Check {
	runtimeClass, err := r.kube.NodeV1().RuntimeClasses().Get(ctx, r.config.RuntimeClass, metav1.GetOptions{})
	if err != nil {
		return fail("kata-runtime", fmt.Sprintf("RuntimeClass %q is unavailable", r.config.RuntimeClass), "Install the AKS Kata runtime and verify the RuntimeClass name.")
	}
	return pass("kata-runtime", fmt.Sprintf("RuntimeClass %q uses handler %q", runtimeClass.Name, runtimeClass.Handler))
}

func (r *Runner) kataCapacity(ctx context.Context) Check {
	runtimeClass, err := r.kube.NodeV1().RuntimeClasses().Get(ctx, r.config.RuntimeClass, metav1.GetOptions{})
	if err != nil {
		return fail("kata-capacity", "Kata capacity cannot be evaluated without its RuntimeClass", "Install the RuntimeClass first.")
	}
	nodes, err := r.kube.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return fail("kata-capacity", "Nodes could not be listed", "Grant the doctor identity permission to list nodes.")
	}
	selector := labels.Everything()
	if runtimeClass.Scheduling != nil && len(runtimeClass.Scheduling.NodeSelector) != 0 {
		requirements := make([]labels.Requirement, 0, len(runtimeClass.Scheduling.NodeSelector))
		for key, value := range runtimeClass.Scheduling.NodeSelector {
			requirement, requirementErr := labels.NewRequirement(key, selection.Equals, []string{value})
			if requirementErr != nil {
				return fail("kata-capacity", "RuntimeClass contains an invalid node selector", "Repair the RuntimeClass scheduling selector.")
			}
			requirements = append(requirements, *requirement)
		}
		selector = labels.NewSelector().Add(requirements...)
	}
	eligible := 0
	for i := range nodes.Items {
		node := &nodes.Items[i]
		if node.Spec.Unschedulable || !nodeReady(node) || !selector.Matches(labels.Set(node.Labels)) {
			continue
		}
		if node.Status.Allocatable.Cpu().IsZero() || node.Status.Allocatable.Memory().IsZero() {
			continue
		}
		eligible++
	}
	if eligible == 0 {
		return fail("kata-capacity", "No ready schedulable node satisfies the Kata RuntimeClass selector", "Scale or repair the Kata node pool.")
	}
	return pass("kata-capacity", fmt.Sprintf("%d ready schedulable node(s) satisfy the Kata runtime contract", eligible))
}

func (r *Runner) governanceCRDs(ctx context.Context) Check {
	required := []string{
		"capabilitybundles.aks-sandbox.azure.com",
		"sandboxaccessrequests.aks-sandbox.azure.com",
		"sandboxassignments.aks-sandbox.azure.com",
		"sandboxcredentialevents.aks-sandbox.azure.com",
		"sandboxegressevents.aks-sandbox.azure.com",
		"sandboxtemplates.aks-sandbox.azure.com",
		"sandboxtenantpolicies.aks-sandbox.azure.com",
		"sandboxvalidationruns.aks-sandbox.azure.com",
	}
	var missing []string
	for _, name := range required {
		if _, err := r.dynamic.Resource(crdGVR).Get(ctx, name, metav1.GetOptions{}); err != nil {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		return fail("governance-crds", "Missing CRDs: "+strings.Join(missing, ", "), "Apply deploy/governance/k8s/crds.yaml.")
	}
	return pass("governance-crds", fmt.Sprintf("All %d required governance CRDs are installed", len(required)))
}

func (r *Runner) assignmentService(ctx context.Context) Check {
	deployment, err := r.kube.AppsV1().Deployments(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{})
	if err != nil {
		return fail("assignmentd", "assignmentd Deployment is unavailable", "Deploy the governance assignment service.")
	}
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas != 1 ||
		deployment.Spec.Strategy.Type != appsv1.RecreateDeploymentStrategyType {
		return fail("assignmentd", "assignmentd must run as a singleton with Recreate rollout strategy", "Keep one assignmentd replica so tenant admission and assignment creation remain serialized.")
	}
	if deployment.Status.ReadyReplicas != 1 {
		return fail("assignmentd", "assignmentd does not have exactly one ready replica", "Inspect the Deployment rollout, image pull, Secret, and scheduling events.")
	}
	mode := deploymentEnv(deployment, "ASSIGNMENTD_EGRESS_IDENTITY_MODE")
	if mode != "projected-sidecar" && mode != "external-mediator" {
		return fail("assignmentd", "assignmentd has an invalid egress identity mode", "Set ASSIGNMENTD_EGRESS_IDENTITY_MODE to projected-sidecar or external-mediator.")
	}
	if _, err := r.kube.CoreV1().Services(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{}); err != nil {
		return fail("assignmentd", "assignmentd Service is unavailable", "Apply the assignmentd Service manifest.")
	}
	return pass("assignmentd", fmt.Sprintf("assignmentd is ready in %s identity mode", mode))
}

func (r *Runner) openSandboxService(ctx context.Context) Check {
	if _, err := r.kube.CoreV1().Services(r.config.WorkloadNamespace).Get(ctx, "opensandbox-server", metav1.GetOptions{}); err != nil {
		return fail("opensandbox-service", "OpenSandbox lifecycle Service is unavailable", "Deploy OpenSandbox before governance components.")
	}
	return pass("opensandbox-service", "OpenSandbox lifecycle Service is discoverable")
}

func (r *Runner) sandboxServiceAccount(ctx context.Context) Check {
	serviceAccount, err := r.kube.CoreV1().ServiceAccounts(r.config.WorkloadNamespace).Get(ctx, "opensandbox-workload", metav1.GetOptions{})
	if err != nil {
		return fail("sandbox-identity", "Sandbox ServiceAccount is unavailable", "Apply deploy/governance/k8s/sandbox-serviceaccount.yaml.")
	}
	if serviceAccount.Labels["aks-sandbox.azure.com/eligible"] != "true" ||
		serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken {
		return fail("sandbox-identity", "Sandbox ServiceAccount permits unsafe token behavior", "Mark it eligible and set automountServiceAccountToken: false.")
	}
	return pass("sandbox-identity", "Sandbox ServiceAccount is eligible and disables token automount")
}

func (r *Runner) governanceInventory(ctx context.Context) Check {
	templates, templateErr := r.dynamic.Resource(templateGVR).Namespace(r.config.AssignmentNamespace).List(ctx, metav1.ListOptions{})
	bundles, bundleErr := r.dynamic.Resource(bundleGVR).Namespace(r.config.AssignmentNamespace).List(ctx, metav1.ListOptions{})
	tenants, tenantErr := r.dynamic.Resource(tenantGVR).Namespace(r.config.AssignmentNamespace).List(ctx, metav1.ListOptions{})
	if templateErr != nil || bundleErr != nil || tenantErr != nil {
		return fail("governance-inventory", "Templates, capability bundles, or tenant policies could not be listed", "Apply the sample resources and verify RBAC.")
	}
	enabled := 0
	for i := range templates.Items {
		value, _, _ := unstructured.NestedBool(templates.Items[i].Object, "spec", "enabled")
		if value {
			enabled++
		}
	}
	enabledTenants := 0
	for i := range tenants.Items {
		value, _, _ := unstructured.NestedBool(tenants.Items[i].Object, "spec", "enabled")
		if value {
			enabledTenants++
		}
	}
	if enabled == 0 || len(bundles.Items) == 0 || enabledTenants == 0 {
		return fail("governance-inventory", "No enabled template, capability bundle, and tenant policy set is available", "Create at least one enabled immutable template, capability bundle, and tenant policy.")
	}
	return pass("governance-inventory", fmt.Sprintf("%d enabled template(s), %d capability bundle(s), and %d enabled tenant policy revision(s) are available", enabled, len(bundles.Items), enabledTenants))
}

func (r *Runner) resourceQuota(ctx context.Context) Check {
	quotas, err := r.kube.CoreV1().ResourceQuotas(r.config.WorkloadNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fail("resource-quota", "ResourceQuotas could not be listed", "Grant permission to list ResourceQuotas.")
	}
	if len(quotas.Items) == 0 {
		return warning("resource-quota", "No workload namespace ResourceQuota is installed", "Install tenant or workload budgets before shared use.")
	}
	return pass("resource-quota", fmt.Sprintf("%d ResourceQuota object(s) protect the workload namespace", len(quotas.Items)))
}

func (r *Runner) networkPolicy(ctx context.Context) Check {
	policies, err := r.kube.NetworkingV1().NetworkPolicies(r.config.WorkloadNamespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fail("network-policy", "NetworkPolicies could not be listed", "Grant permission to list NetworkPolicies.")
	}
	if len(policies.Items) == 0 {
		return warning("network-policy", "No workload namespace NetworkPolicy is installed", "Install fail-closed ingress and mediated-egress policies.")
	}
	names := make([]string, 0, len(policies.Items))
	for i := range policies.Items {
		names = append(names, policies.Items[i].Name)
	}
	sort.Strings(names)
	return pass("network-policy", "NetworkPolicies installed: "+strings.Join(names, ", "))
}

func nodeReady(node *corev1.Node) bool {
	for _, condition := range node.Status.Conditions {
		if condition.Type == corev1.NodeReady {
			return condition.Status == corev1.ConditionTrue
		}
	}
	return false
}

func deploymentEnv(deployment *appsv1.Deployment, name string) string {
	for _, container := range deployment.Spec.Template.Spec.Containers {
		for _, variable := range container.Env {
			if variable.Name == name {
				return variable.Value
			}
		}
	}
	return ""
}

func pass(name, summary string) Check {
	return Check{Name: name, Status: StatusPass, Summary: summary}
}

func warning(name, summary, remediation string) Check {
	return Check{Name: name, Status: StatusWarning, Summary: summary, Remediation: remediation}
}

func fail(name, summary, remediation string) Check {
	return Check{Name: name, Status: StatusFail, Summary: summary, Remediation: remediation}
}
