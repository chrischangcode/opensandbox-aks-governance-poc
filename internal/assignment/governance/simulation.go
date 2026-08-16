package governance

import (
	"slices"
	"sort"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
)

type PolicyImpactMatch struct {
	EventName     string
	Assignment    string
	SandboxID     string
	LogicalTenant string
	Team          string
	Target        Target
}

type PolicyImpact struct {
	DeniedEvents    int
	NewlyAllowed    int
	AffectedTenants []string
	AffectedTeams   []string
	Matches         []PolicyImpactMatch
}

// SimulatePolicyImpact applies exact candidate targets to historical denied
// events without mutating a capability bundle.
func SimulatePolicyImpact(events []assignmentv1alpha1.SandboxEgressEvent, targets []Target) PolicyImpact {
	impact := PolicyImpact{}
	tenants := map[string]struct{}{}
	teams := map[string]struct{}{}
	for _, event := range events {
		if event.Spec.Allowed || event.Spec.DecisionSource != assignmentv1alpha1.DecisionSourceDeny {
			continue
		}
		impact.DeniedEvents++
		target := Target{
			Backend: event.Spec.Backend,
			Method:  event.Spec.Method,
			Host:    event.Spec.Host,
			Path:    event.Spec.Path,
		}
		if !slices.Contains(targets, target) {
			continue
		}
		impact.NewlyAllowed++
		impact.Matches = append(impact.Matches, PolicyImpactMatch{
			EventName:     event.Name,
			Assignment:    event.Spec.AssignmentRef.Name,
			SandboxID:     event.Spec.SandboxID,
			LogicalTenant: event.Spec.LogicalTenant,
			Team:          event.Spec.Team,
			Target:        target,
		})
		if event.Spec.LogicalTenant != "" {
			tenants[event.Spec.LogicalTenant] = struct{}{}
		}
		if event.Spec.Team != "" {
			teams[event.Spec.Team] = struct{}{}
		}
	}
	for tenant := range tenants {
		impact.AffectedTenants = append(impact.AffectedTenants, tenant)
	}
	for team := range teams {
		impact.AffectedTeams = append(impact.AffectedTeams, team)
	}
	sort.Strings(impact.AffectedTenants)
	sort.Strings(impact.AffectedTeams)
	sort.Slice(impact.Matches, func(i, j int) bool {
		return impact.Matches[i].EventName < impact.Matches[j].EventName
	})
	return impact
}
