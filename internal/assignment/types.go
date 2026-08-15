// Package assignment defines storage-neutral sandbox assignment types.
package assignment

import "context"

const (
	// EligibleServiceAccountLabel marks a platform-owned ServiceAccount as safe
	// for assignment-bound sandbox Pods.
	EligibleServiceAccountLabel = "aks-sandbox.azure.com/eligible"
	// AssignmentLabel is placed on the fresh sandbox workload and Pod.
	AssignmentLabel = "aks-sandbox.azure.com/assignment"
	// AssignmentUIDAnnotation fences direct workload metadata to one assignment incarnation.
	AssignmentUIDAnnotation = "aks-sandbox.azure.com/assignment-uid"
	// OpenSandboxAssignmentUIDAnnotation is produced when the trusted facade
	// injects an opensandbox.extensions assignment UID into a create request.
	OpenSandboxAssignmentUIDAnnotation = "opensandbox.io/extensions.aks-sandbox-assignment-uid"
	// SandboxIDAnnotation maps an internal assignment to its OpenSandbox ID.
	SandboxIDAnnotation = "aks-sandbox.azure.com/opensandbox-id"
	// SandboxIDLabel supports exact API-server lookup and informer indexing.
	SandboxIDLabel = "aks-sandbox.azure.com/opensandbox-id"
	// PausedAnnotation fences authorization before forwarding an OpenSandbox pause.
	PausedAnnotation = "aks-sandbox.azure.com/paused"
	// ResumeAfterPodUIDAnnotation prevents readiness until resume creates a new Pod.
	ResumeAfterPodUIDAnnotation = "aks-sandbox.azure.com/resume-after-pod-uid"
)

// Assignment is the allocator-facing view of a SandboxAssignment.
type Assignment struct {
	Namespace            string
	Name                 string
	UID                  string
	ResourceVersion      string
	CapabilityBundleName string
	Deleting             bool
	Ready                bool
	WorkloadRef          *ObjectReference
	PodRef               *ObjectReference
	Conditions           []Condition
}

// ObjectReference identifies a Kubernetes object incarnation.
type ObjectReference struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	Namespace  string `json:"namespace"`
	Name       string `json:"name"`
	UID        string `json:"uid"`
}

// Condition reports assignment reconciliation state.
type Condition struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// CreateRequest selects the immutable capability bundle for a new assignment.
type CreateRequest struct {
	Namespace            string
	Name                 string
	GenerateName         string
	CapabilityBundleName string
}

// Store persists assignments and verifies referenced capability bundles.
type Store interface {
	Create(context.Context, CreateRequest) (*Assignment, error)
	Get(context.Context, string, string) (*Assignment, error)
	GetBySandboxID(context.Context, string, string) (*Assignment, error)
	SetSandboxID(context.Context, string, string, string) error
	SetLifecycleFence(context.Context, string, string, bool, string) error
	Delete(context.Context, string, string) error
}
