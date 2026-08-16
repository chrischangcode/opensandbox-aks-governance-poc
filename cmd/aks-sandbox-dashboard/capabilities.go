package main

import (
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation"
)

const maximumPreauthorizedRules = 32

func (g *governanceDashboard) createCapabilityBundle(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.requireAdmin(w, r); !ok {
		return
	}
	form, ok := g.parseMutation(
		w, r, "csrf", "name", "displayName", "logicalTenant", "team",
		"permissionLevel", "egressRules", "allowedCommands", "validationRules",
	)
	if !ok {
		return
	}
	name := strings.TrimSpace(form.Get("name"))
	displayName := strings.TrimSpace(form.Get("displayName"))
	logicalTenant := strings.TrimSpace(form.Get("logicalTenant"))
	team := strings.TrimSpace(form.Get("team"))
	permissionLevel := strings.TrimSpace(form.Get("permissionLevel"))
	if errors := validation.IsDNS1123Subdomain(name); len(errors) != 0 ||
		len(displayName) < 3 || len(displayName) > 128 ||
		strings.IndexFunc(displayName, unicode.IsControl) >= 0 ||
		len(validation.IsDNS1123Label(logicalTenant)) != 0 ||
		len(validation.IsDNS1123Label(team)) != 0 ||
		len(validation.IsDNS1123Label(permissionLevel)) != 0 {
		http.Error(w, "Capability boundary fields are invalid", http.StatusBadRequest)
		return
	}
	if _, ok := g.requireAdminTenant(w, r, logicalTenant); !ok {
		return
	}

	egress, err := parseExactEgressRules(form.Get("egressRules"))
	if err != nil {
		http.Error(w, "Invalid pre-authorized egress: "+err.Error(), http.StatusBadRequest)
		return
	}
	commandPolicy, err := parseAllowedCommands(form.Get("allowedCommands"))
	if err != nil {
		http.Error(w, "Invalid allowed commands: "+err.Error(), http.StatusBadRequest)
		return
	}
	validationRules, err := parseValidationRules(form.Get("validationRules"), commandPolicy)
	if err != nil {
		http.Error(w, "Invalid validation rules: "+err.Error(), http.StatusBadRequest)
		return
	}
	spec := assignmentv1alpha1.CapabilityBundleSpec{
		Governance: &assignmentv1alpha1.GovernanceBoundary{
			LogicalTenant: logicalTenant, Team: team,
			PermissionLevel: permissionLevel, DisplayName: displayName,
		},
	}
	if len(egress) != 0 {
		spec.Egress = &assignmentv1alpha1.EgressPolicy{Agentgateway: egress}
	}
	if len(commandPolicy) != 0 || len(validationRules) != 0 {
		spec.Harness = &assignmentv1alpha1.HarnessPolicy{
			CommandPolicy: commandPolicy, ValidationRules: validationRules,
		}
	}
	bundle := &assignmentv1alpha1.CapabilityBundle{
		TypeMeta: metav1.TypeMeta{
			APIVersion: assignmentv1alpha1.GroupVersion.String(),
			Kind:       "CapabilityBundle",
		},
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: g.namespace},
		Spec:       spec,
	}
	object, err := toUnstructured(bundle)
	if err != nil {
		g.internalError(w, r, "encode capability bundle", err)
		return
	}
	if _, err := g.client.Resource(dashboardBundlesGVR).Namespace(g.namespace).Create(
		r.Context(), object, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	); err != nil {
		g.resourceError(w, "create capability bundle", err)
		return
	}
	g.redirectWithMessage(w, r, "/admin", fmt.Sprintf("Capability bundle %s created", name))
}

func parseExactEgressRules(value string) (map[string]assignmentv1alpha1.AgentgatewayBackendPolicy, error) {
	byBackend := map[string][]string{}
	targets, err := parseExactEgressTargets(value)
	if err != nil {
		return nil, err
	}
	for _, target := range targets {
		expression := fmt.Sprintf(
			"request.method == %q && request.host == %q && request.path == %q",
			target.Method, target.Host, target.Path,
		)
		byBackend[target.Backend] = append(byBackend[target.Backend], expression)
	}
	result := make(map[string]assignmentv1alpha1.AgentgatewayBackendPolicy, len(byBackend))
	for backend, expressions := range byBackend {
		slices.Sort(expressions)
		for i := range expressions {
			expressions[i] = "(" + expressions[i] + ")"
		}
		result[backend] = assignmentv1alpha1.AgentgatewayBackendPolicy{
			Allow: strings.Join(expressions, " || "),
		}
	}
	return result, nil
}

func parseExactEgressTargets(value string) ([]governance.Target, error) {
	var targets []governance.Target
	ruleCount := 0
	for lineNumber, raw := range strings.Split(value, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		ruleCount++
		if ruleCount > maximumPreauthorizedRules || len(line) > 2048 {
			return nil, fmt.Errorf("at most %d bounded rules are allowed", maximumPreauthorizedRules)
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("line %d must be: backend METHOD https://host/path", lineNumber+1)
		}
		targetURL, err := url.ParseRequestURI(fields[2])
		if err != nil || !strings.EqualFold(targetURL.Scheme, "https") || targetURL.Host == "" || targetURL.Port() != "" ||
			targetURL.User != nil || targetURL.RawQuery != "" || targetURL.Fragment != "" {
			return nil, fmt.Errorf("line %d must contain an exact HTTPS URL without port, query, or fragment", lineNumber+1)
		}
		target, err := governance.NormalizeTarget(
			fields[0], fields[1], targetURL.Host, targetURL.EscapedPath(),
		)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNumber+1, err)
		}
		if !slices.Contains(targets, target) {
			targets = append(targets, target)
		}
	}
	return targets, nil
}

func parseAllowedCommands(value string) ([]assignmentv1alpha1.CommandPolicyRule, error) {
	var result []assignmentv1alpha1.CommandPolicyRule
	for _, raw := range strings.Split(value, "\n") {
		command := strings.TrimSpace(raw)
		if command == "" {
			continue
		}
		if len(result) >= maximumPreauthorizedRules || len(command) > 2048 ||
			strings.IndexFunc(command, unicode.IsControl) >= 0 {
			return nil, fmt.Errorf("at most %d bounded commands are allowed", maximumPreauthorizedRules)
		}
		pattern := "^" + regexp.QuoteMeta(command) + "$"
		if slices.ContainsFunc(result, func(rule assignmentv1alpha1.CommandPolicyRule) bool {
			return rule.Pattern == pattern
		}) {
			continue
		}
		result = append(result, assignmentv1alpha1.CommandPolicyRule{
			Pattern: pattern, Decision: "allow",
			Reason: "Pre-authorized by the capability bundle administrator.",
		})
	}
	return result, nil
}

func parseValidationRules(value string, commandPolicy []assignmentv1alpha1.CommandPolicyRule) ([]assignmentv1alpha1.ValidationRule, error) {
	allowedPatterns := make(map[string]struct{}, len(commandPolicy))
	for _, rule := range commandPolicy {
		if rule.Decision == "allow" {
			allowedPatterns[rule.Pattern] = struct{}{}
		}
	}
	var result []assignmentv1alpha1.ValidationRule
	for lineNumber, raw := range strings.Split(value, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if len(result) >= maximumPreauthorizedRules || len(line) > 2560 {
			return nil, fmt.Errorf("at most %d bounded rules are allowed", maximumPreauthorizedRules)
		}
		prefix, command, found := strings.Cut(line, "=>")
		prefix = strings.TrimSpace(prefix)
		command = strings.TrimSpace(command)
		if !found || prefix == "" || command == "" {
			return nil, fmt.Errorf("line %d must be: path-prefix => exact command", lineNumber+1)
		}
		if prefix != "*" && (strings.HasPrefix(prefix, "/") || strings.Contains(prefix, `\`) ||
			strings.Contains(prefix, "..") || strings.IndexFunc(prefix, unicode.IsControl) >= 0 ||
			len(prefix) > 512) {
			return nil, fmt.Errorf("line %d has an invalid repository-relative path prefix", lineNumber+1)
		}
		if _, ok := allowedPatterns["^"+regexp.QuoteMeta(command)+"$"]; !ok {
			return nil, fmt.Errorf("line %d command must also appear in allowed exact commands", lineNumber+1)
		}
		rule := assignmentv1alpha1.ValidationRule{PathPrefix: prefix, Command: command}
		if !slices.Contains(result, rule) {
			result = append(result, rule)
		}
	}
	return result, nil
}
