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
	rbacv1 "k8s.io/api/rbac/v1"
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
		"sandboxcredentialrevocations.aks-sandbox.azure.com",
		"sandboxegressevents.aks-sandbox.azure.com",
		"sandboxprincipalbindings.aks-sandbox.azure.com",
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
	if deployment.Spec.Replicas == nil || *deployment.Spec.Replicas < 2 ||
		deployment.Spec.Strategy.Type != appsv1.RollingUpdateDeploymentStrategyType {
		return fail("assignmentd", "assignmentd must run with at least two replicas and RollingUpdate", "Deploy multiple replicas; Kubernetes Leases serialize tenant admission and elect one assignment controller.")
	}
	if deployment.Status.ReadyReplicas < 2 {
		return fail("assignmentd", "assignmentd does not have at least two ready replicas", "Inspect the Deployment rollout, image pull, Secret, and scheduling events.")
	}
	pdb, err := r.kube.PolicyV1().PodDisruptionBudgets(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{})
	if err != nil || pdb.Spec.MinAvailable == nil || pdb.Spec.MinAvailable.IntValue() < 1 {
		return fail("assignmentd", "assignmentd PodDisruptionBudget is missing or ineffective", "Apply a PodDisruptionBudget with minAvailable of at least one.")
	}
	role, err := r.kube.RbacV1().Roles(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{})
	if err != nil || !roleAllows(role.Rules, "coordination.k8s.io", "leases", "create", "get", "update", "patch", "delete") {
		return fail("assignmentd", "assignmentd cannot manage admission and leader-election Leases", "Grant the assignmentd Role create, get, update, patch, and delete on coordination.k8s.io Leases.")
	}
	binding, err := r.kube.RbacV1().RoleBindings(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{})
	if err != nil || binding.RoleRef.Kind != "Role" || binding.RoleRef.Name != "assignmentd" ||
		!hasServiceAccountSubject(binding.Subjects, r.config.AssignmentNamespace, "assignmentd") {
		return fail("assignmentd", "assignmentd Lease permissions are not bound to its ServiceAccount", "Bind the assignmentd Role to the assignmentd ServiceAccount.")
	}
	tokenReviewRole, err := r.kube.RbacV1().ClusterRoles().Get(ctx, "assignmentd-tokenreview", metav1.GetOptions{})
	if err != nil || !roleAllows(tokenReviewRole.Rules, "authentication.k8s.io", "tokenreviews", "create") {
		return fail("assignmentd", "assignmentd cannot authenticate caller or Pod tokens", "Grant create on authentication.k8s.io TokenReviews.")
	}
	tokenReviewBinding, err := r.kube.RbacV1().ClusterRoleBindings().Get(ctx, "assignmentd-tokenreview", metav1.GetOptions{})
	if err != nil || tokenReviewBinding.RoleRef.Kind != "ClusterRole" ||
		tokenReviewBinding.RoleRef.Name != "assignmentd-tokenreview" ||
		!hasServiceAccountSubject(tokenReviewBinding.Subjects, r.config.AssignmentNamespace, "assignmentd") {
		return fail("assignmentd", "TokenReview permission is not bound to assignmentd", "Bind assignmentd-tokenreview to the assignmentd ServiceAccount.")
	}
	workloadRole, err := r.kube.RbacV1().Roles(r.config.WorkloadNamespace).Get(ctx, "assignmentd-workloads", metav1.GetOptions{})
	if err != nil ||
		!roleAllows(workloadRole.Rules, "sandbox.opensandbox.io", "batchsandboxes", "get", "list", "watch", "delete") ||
		!roleAllows(workloadRole.Rules, "", "pods", "get", "list", "watch") ||
		!roleAllows(workloadRole.Rules, "", "serviceaccounts", "get", "list", "watch") {
		return fail("assignmentd", "assignmentd cannot reconcile workload identities", "Grant the assignmentd-workloads Role access to BatchSandboxes, Pods, and ServiceAccounts.")
	}
	workloadBinding, err := r.kube.RbacV1().RoleBindings(r.config.WorkloadNamespace).Get(ctx, "assignmentd-workloads", metav1.GetOptions{})
	if err != nil || workloadBinding.RoleRef.Kind != "Role" ||
		workloadBinding.RoleRef.Name != "assignmentd-workloads" ||
		!hasServiceAccountSubject(workloadBinding.Subjects, r.config.AssignmentNamespace, "assignmentd") {
		return fail("assignmentd", "workload reconciliation permission is not bound to assignmentd", "Bind assignmentd-workloads to the assignmentd ServiceAccount.")
	}
	mode := deploymentEnv(deployment, "ASSIGNMENTD_EGRESS_IDENTITY_MODE")
	if mode != "projected-sidecar" && mode != "external-mediator" {
		return fail("assignmentd", "assignmentd has an invalid egress identity mode", "Set ASSIGNMENTD_EGRESS_IDENTITY_MODE to projected-sidecar or external-mediator.")
	}
	if _, err := r.kube.CoreV1().Services(r.config.AssignmentNamespace).Get(ctx, "assignmentd", metav1.GetOptions{}); err != nil {
		return fail("assignmentd", "assignmentd Service is unavailable", "Apply the assignmentd Service manifest.")
	}
	return pass("assignmentd", fmt.Sprintf("%d assignmentd replicas are ready in %s identity mode", deployment.Status.ReadyReplicas, mode))
}

func roleAllows(rules []rbacv1.PolicyRule, apiGroup, resource string, verbs ...string) bool {
	for _, rule := range rules {
		if !contains(rule.APIGroups, apiGroup) || !contains(rule.Resources, resource) {
			continue
		}
		for _, verb := range verbs {
			if !contains(rule.Verbs, verb) {
				return false
			}
		}
		return true
	}
	return false
}

func hasServiceAccountSubject(subjects []rbacv1.Subject, namespace, name string) bool {
	for _, subject := range subjects {
		if subject.Kind == "ServiceAccount" && subject.Namespace == namespace && subject.Name == name {
			return true
		}
	}
	return false
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted || value == "*" {
			return true
		}
	}
	return false
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
	required := map[string]bool{
		"sandbox-default-deny-egress": false,
		"sandbox-allow-assignmentd":   false,
	}
	for i := range policies.Items {
		names = append(names, policies.Items[i].Name)
		if _, ok := required[policies.Items[i].Name]; ok {
			required[policies.Items[i].Name] = true
		}
	}
	sort.Strings(names)
	var missing []string
	for name, found := range required {
		if !found {
			missing = append(missing, name)
		}
	}
	if len(missing) != 0 {
		sort.Strings(missing)
		return warning("network-policy", "Forced-egress policies are missing: "+strings.Join(missing, ", "), "Apply deploy/governance/k8s/forced-egress-networkpolicy.yaml.")
	}
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
