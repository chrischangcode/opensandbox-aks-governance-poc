package main

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

func (g *governanceDashboard) createTenantPolicy(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.requireAdmin(w, r); !ok {
		return
	}
	form, ok := g.parseMutation(
		w, r, "csrf", "name", "logicalTenant", "workloadNamespace",
		"allowedCapabilityBundles", "allowedCapabilityBundlePrefixes",
		"maxConcurrentSandboxes", "maxLifetimeSeconds",
		"maxAccessMinutes", "maxCpu", "maxMemory", "enabled",
	)
	if !ok {
		return
	}
	name := strings.TrimSpace(form.Get("name"))
	logicalTenant := strings.TrimSpace(form.Get("logicalTenant"))
	workloadNamespace := strings.TrimSpace(form.Get("workloadNamespace"))
	if len(validation.IsDNS1123Subdomain(name)) != 0 ||
		len(validation.IsDNS1123Label(logicalTenant)) != 0 ||
		len(validation.IsDNS1123Label(workloadNamespace)) != 0 {
		http.Error(w, "Tenant policy identity fields are invalid", http.StatusBadRequest)
		return
	}
	bundles := uniqueLines(form.Get("allowedCapabilityBundles"))
	prefixes := uniqueLines(form.Get("allowedCapabilityBundlePrefixes"))
	if len(bundles)+len(prefixes) == 0 || len(bundles) > 128 || len(prefixes) > 128 {
		http.Error(w, "At least one allowed capability bundle or prefix is required", http.StatusBadRequest)
		return
	}
	for _, bundle := range bundles {
		if len(validation.IsDNS1123Subdomain(bundle)) != 0 {
			http.Error(w, "Allowed capability bundle name is invalid", http.StatusBadRequest)
			return
		}
	}
	for _, prefix := range prefixes {
		if !strings.HasSuffix(prefix, "-") ||
			len(validation.IsDNS1123Label(strings.TrimSuffix(prefix, "-"))) != 0 {
			http.Error(w, "Allowed capability bundle prefix is invalid", http.StatusBadRequest)
			return
		}
	}
	maxConcurrent, err := boundedInt32(form.Get("maxConcurrentSandboxes"), 1, 1000)
	if err != nil {
		http.Error(w, "Concurrent sandbox budget is invalid", http.StatusBadRequest)
		return
	}
	maxLifetime, err := boundedInt32(form.Get("maxLifetimeSeconds"), 60, 86400)
	if err != nil {
		http.Error(w, "Lifetime budget is invalid", http.StatusBadRequest)
		return
	}
	maxAccessMinutes, err := boundedInt32(form.Get("maxAccessMinutes"), 1, 480)
	if err != nil {
		http.Error(w, "Access duration budget is invalid", http.StatusBadRequest)
		return
	}
	maxCPU := strings.TrimSpace(form.Get("maxCpu"))
	maxMemory := strings.TrimSpace(form.Get("maxMemory"))
	if quantity, err := resource.ParseQuantity(maxCPU); err != nil || quantity.Sign() <= 0 {
		http.Error(w, "CPU budget is invalid", http.StatusBadRequest)
		return
	}
	if quantity, err := resource.ParseQuantity(maxMemory); err != nil || quantity.Sign() <= 0 {
		http.Error(w, "Memory budget is invalid", http.StatusBadRequest)
		return
	}
	policy := &assignmentv1alpha1.SandboxTenantPolicy{
		TypeMeta:   metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxTenantPolicy"},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: g.namespace},
		Spec: assignmentv1alpha1.SandboxTenantPolicySpec{
			LogicalTenant: logicalTenant, WorkloadNamespace: workloadNamespace,
			AllowedCapabilityBundles: bundles, AllowedCapabilityBundlePrefixes: prefixes,
			MaxConcurrentSandboxes: maxConcurrent,
			MaxLifetimeSeconds:     maxLifetime, MaxAccessRequestDurationSeconds: maxAccessMinutes * 60,
			MaxCPU: maxCPU, MaxMemory: maxMemory, Enabled: form.Get("enabled") == "true",
		},
	}
	object, err := toUnstructured(policy)
	if err != nil {
		g.internalError(w, r, "encode tenant policy", err)
		return
	}
	if _, err := g.client.Resource(dashboardTenantPoliciesGVR).Namespace(g.namespace).Create(
		r.Context(), object, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	); err != nil {
		g.resourceError(w, "create tenant policy", err)
		return
	}
	g.redirectWithMessage(w, r, "/admin", fmt.Sprintf("Tenant policy %s created", name))
}

func (g *governanceDashboard) tenantPolicyRows(ctx context.Context) ([]tenantPolicyPageRow, error) {
	list, err := g.client.Resource(dashboardTenantPoliciesGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rows := make([]tenantPolicyPageRow, 0, len(list.Items))
	for i := range list.Items {
		policy := &assignmentv1alpha1.SandboxTenantPolicy{}
		if err := fromUnstructured(&list.Items[i], policy); err != nil {
			return nil, err
		}
		rows = append(rows, tenantPolicyPageRow{
			Name: policy.Name, LogicalTenant: policy.Spec.LogicalTenant,
			WorkloadNamespace: policy.Spec.WorkloadNamespace,
			Bundles: strings.Join(
				append(append([]string{}, policy.Spec.AllowedCapabilityBundles...), policy.Spec.AllowedCapabilityBundlePrefixes...),
				", ",
			),
			Concurrent: strconv.FormatInt(int64(policy.Spec.MaxConcurrentSandboxes), 10),
			Lifetime:   (strconv.FormatInt(int64(policy.Spec.MaxLifetimeSeconds), 10) + "s"),
			Access:     (strconv.FormatInt(int64(policy.Spec.MaxAccessRequestDurationSeconds/60), 10) + "m"),
			CPU:        policy.Spec.MaxCPU, Memory: policy.Spec.MaxMemory,
			Enabled: strconv.FormatBool(policy.Spec.Enabled),
		})
	}
	slices.SortFunc(rows, func(a, b tenantPolicyPageRow) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func (g *governanceDashboard) maxAccessDurationSeconds(ctx context.Context, logicalTenant string) (int32, error) {
	list, err := g.client.Resource(dashboardTenantPoliciesGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return 0, err
	}
	var matches []assignmentv1alpha1.SandboxTenantPolicy
	for i := range list.Items {
		policy := assignmentv1alpha1.SandboxTenantPolicy{}
		if err := fromUnstructured(&list.Items[i], &policy); err != nil {
			return 0, err
		}
		if policy.Spec.Enabled && policy.Spec.LogicalTenant == logicalTenant && policy.DeletionTimestamp == nil {
			matches = append(matches, policy)
		}
	}
	if len(matches) != 1 {
		return 0, fmt.Errorf("logical tenant %q must have exactly one enabled tenant policy", logicalTenant)
	}
	return matches[0].Spec.MaxAccessRequestDurationSeconds, nil
}

func uniqueLines(value string) []string {
	var result []string
	for _, line := range strings.Split(value, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !slices.Contains(result, line) {
			result = append(result, line)
		}
	}
	return result
}

func boundedInt32(value string, minimum, maximum int32) (int32, error) {
	parsed, err := strconv.ParseInt(value, 10, 32)
	if err != nil || parsed < int64(minimum) || parsed > int64(maximum) {
		return 0, fmt.Errorf("value must be between %d and %d", minimum, maximum)
	}
	return int32(parsed), nil
}
