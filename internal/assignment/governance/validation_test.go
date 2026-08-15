package governance

import (
	"testing"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	"k8s.io/apimachinery/pkg/types"
)

func TestNormalizeTarget(t *testing.T) {
	target, err := NormalizeTarget("cachew", "get", "Example.COM:8443", "/repo/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	if target.Method != "GET" || target.Host != "example.com" || target.Path != "/repo/info/refs" {
		t.Fatalf("target = %#v", target)
	}
	for _, host := range []string{"https://example.com", "example.com:bad", "bad host"} {
		if _, err := NormalizeHost(host); err == nil {
			t.Fatalf("NormalizeHost(%q) succeeded", host)
		}
	}
}

func TestValidateAccessRequestSpec(t *testing.T) {
	spec := validAccessRequestSpec()
	if err := ValidateAccessRequestSpec(spec); err != nil {
		t.Fatal(err)
	}

	spec.Host = "Example.COM"
	if err := ValidateAccessRequestSpec(spec); err == nil {
		t.Fatal("non-canonical host was accepted")
	}
	spec = validAccessRequestSpec()
	spec.RequestedDurationSeconds = int32(MaximumRequestedDuration.Seconds()) + 1
	if err := ValidateAccessRequestSpec(spec); err == nil {
		t.Fatal("duration over maximum was accepted")
	}
	spec = validAccessRequestSpec()
	spec.Requester.ObjectID = "not-an-object-id"
	if err := ValidateAccessRequestSpec(spec); err == nil {
		t.Fatal("invalid Entra object ID was accepted")
	}
}

func validAccessRequestSpec() assignmentv1alpha1.SandboxAccessRequestSpec {
	return assignmentv1alpha1.SandboxAccessRequestSpec{
		AssignmentRef:            assignmentv1alpha1.AssignmentReference{Name: "assignment-a", UID: types.UID("assignment-uid")},
		BasePolicyRevision:       "sha256:0123456789",
		Backend:                  "cachew",
		Method:                   "GET",
		Host:                     "cachew.example.test",
		Path:                     "/repo/info/refs",
		Reason:                   "Need to refresh the repository.",
		RequestedDurationSeconds: 3600,
		Requester: assignmentv1alpha1.GovernanceIdentity{
			TenantID:    "11111111-1111-1111-1111-111111111111",
			ObjectID:    "22222222-2222-2222-2222-222222222222",
			DisplayName: "Requester",
		},
	}
}
