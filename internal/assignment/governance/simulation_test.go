package governance

import (
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSimulatePolicyImpactMatchesOnlyExactDeniedTargets(t *testing.T) {
	events := []assignmentv1alpha1.SandboxEgressEvent{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "denied-a"},
			Spec: assignmentv1alpha1.SandboxEgressEventSpec{
				AssignmentRef: assignmentv1alpha1.AssignmentReference{Name: "assignment-a"},
				SandboxID:     "sandbox-a", LogicalTenant: "tenant-a", Team: "readers",
				Backend: "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
				DecisionSource: assignmentv1alpha1.DecisionSourceDeny,
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "allowed-a"},
			Spec: assignmentv1alpha1.SandboxEgressEventSpec{
				Backend: "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
				Allowed: true, DecisionSource: assignmentv1alpha1.DecisionSourceBundle,
			},
		},
	}
	impact := SimulatePolicyImpact(events, []Target{{
		Backend: "source-control", Method: "GET", Host: "github.com", Path: "/org/repo",
	}})
	if impact.DeniedEvents != 1 || impact.NewlyAllowed != 1 ||
		len(impact.Matches) != 1 || impact.Matches[0].EventName != "denied-a" ||
		len(impact.AffectedTenants) != 1 || impact.AffectedTenants[0] != "tenant-a" {
		t.Fatalf("impact = %#v", impact)
	}
}
