package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	// GroupName is the Kubernetes API group for assignment resources.
	GroupName = "aks-sandbox.azure.com"
	// Version is the served alpha API version.
	Version = "v1alpha1"

	// SandboxAccessRequestPending is awaiting an administrator decision.
	SandboxAccessRequestPending SandboxAccessRequestState = "Pending"
	// SandboxAccessRequestApproved is an active or scheduled temporary overlay grant.
	SandboxAccessRequestApproved SandboxAccessRequestState = "Approved"
	// SandboxAccessRequestDenied was rejected by an administrator.
	SandboxAccessRequestDenied SandboxAccessRequestState = "Denied"
	// SandboxAccessRequestExpired is no longer eligible to authorize requests.
	SandboxAccessRequestExpired SandboxAccessRequestState = "Expired"

	// DecisionSourceBundle means the immutable capability bundle allowed the request.
	DecisionSourceBundle SandboxEgressDecisionSource = "bundle"
	// DecisionSourceAccessRequest means a temporary approved access request allowed the request.
	DecisionSourceAccessRequest SandboxEgressDecisionSource = "access-request"
	// DecisionSourceDeny means no immutable or temporary authority allowed the request.
	DecisionSourceDeny SandboxEgressDecisionSource = "deny"
)

// GroupVersion identifies this API package.
var GroupVersion = schema.GroupVersion{Group: GroupName, Version: Version}

// CapabilityBundle declares immutable egress and harness authority.
// +kubebuilder:object:root=true
type CapabilityBundle struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              CapabilityBundleSpec `json:"spec"`
}

// CapabilityBundleList is a list of CapabilityBundle resources.
// +kubebuilder:object:root=true
type CapabilityBundleList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CapabilityBundle `json:"items"`
}

// CapabilityBundleSpec is the immutable capability declaration.
type CapabilityBundleSpec struct {
	Egress     *EgressPolicy       `json:"egress,omitempty"`
	Harness    *HarnessPolicy      `json:"harness,omitempty"`
	Governance *GovernanceBoundary `json:"governance,omitempty"`
}

// GovernanceBoundary describes a display-only logical boundary within one Azure tenant.
type GovernanceBoundary struct {
	LogicalTenant   string `json:"logicalTenant,omitempty"`
	Team            string `json:"team,omitempty"`
	PermissionLevel string `json:"permissionLevel,omitempty"`
	DisplayName     string `json:"displayName,omitempty"`
}

// EgressPolicy contains provider-specific mediated egress rules.
type EgressPolicy struct {
	Agentgateway map[string]AgentgatewayBackendPolicy `json:"agentgateway,omitempty"`
}

// AgentgatewayBackendPolicy is the complete allow predicate for one backend.
type AgentgatewayBackendPolicy struct {
	Allow string `json:"allow"`
}

// HarnessPolicy contains command rules enforced by an external Tool Bridge.
type HarnessPolicy struct {
	CommandPolicy []CommandPolicyRule `json:"commandPolicy,omitempty"`
}

// CommandPolicyRule classifies a canonical command string.
type CommandPolicyRule struct {
	Pattern  string `json:"pattern"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// SandboxAssignment binds one capability bundle to one sandbox Pod incarnation.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type SandboxAssignment struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxAssignmentSpec   `json:"spec"`
	Status            SandboxAssignmentStatus `json:"status,omitempty"`
}

// SandboxAssignmentList is a list of SandboxAssignment resources.
// +kubebuilder:object:root=true
type SandboxAssignmentList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxAssignment `json:"items"`
}

// SandboxAssignmentSpec contains only the selected immutable bundle reference.
type SandboxAssignmentSpec struct {
	CapabilityBundleRef CapabilityBundleReference `json:"capabilityBundleRef"`
}

// CapabilityBundleReference names a bundle in the assignment namespace.
type CapabilityBundleReference struct {
	Name string `json:"name"`
}

// SandboxAssignmentStatus contains controller-verified runtime binding state.
type SandboxAssignmentStatus struct {
	WorkloadRef              *ObjectReference          `json:"workloadRef,omitempty"`
	PodRef                   *ObjectReference          `json:"podRef,omitempty"`
	ResolvedCapabilityBundle *ResolvedCapabilityBundle `json:"resolvedCapabilityBundle,omitempty"`
	Conditions               []metav1.Condition        `json:"conditions,omitempty"`
}

// ObjectReference identifies one Kubernetes object incarnation.
type ObjectReference struct {
	APIVersion string    `json:"apiVersion,omitempty"`
	Kind       string    `json:"kind,omitempty"`
	Namespace  string    `json:"namespace,omitempty"`
	Name       string    `json:"name,omitempty"`
	UID        types.UID `json:"uid,omitempty"`
}

// ResolvedCapabilityBundle fences authorization to an exact bundle incarnation and policy.
type ResolvedCapabilityBundle struct {
	Name           string    `json:"name"`
	UID            types.UID `json:"uid"`
	PolicyRevision string    `json:"policyRevision"`
}

// SandboxAccessRequest requests one exact temporary egress overlay grant.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type SandboxAccessRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxAccessRequestSpec   `json:"spec"`
	Status            SandboxAccessRequestStatus `json:"status,omitempty"`
}

// SandboxAccessRequestList is a list of SandboxAccessRequest resources.
// +kubebuilder:object:root=true
type SandboxAccessRequestList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxAccessRequest `json:"items"`
}

// SandboxAccessRequestSpec binds a request to one assignment and exact egress target.
type SandboxAccessRequestSpec struct {
	AssignmentRef            AssignmentReference `json:"assignmentRef"`
	BasePolicyRevision       string              `json:"basePolicyRevision"`
	Backend                  string              `json:"backend"`
	Method                   string              `json:"method"`
	Host                     string              `json:"host"`
	Path                     string              `json:"path"`
	Reason                   string              `json:"reason"`
	Requester                GovernanceIdentity  `json:"requester"`
	RequestedDurationSeconds int32               `json:"requestedDurationSeconds"`
}

// AssignmentReference identifies one immutable SandboxAssignment incarnation.
type AssignmentReference struct {
	Name string    `json:"name"`
	UID  types.UID `json:"uid"`
}

// GovernanceIdentity is an authenticated Entra identity with optional logical tenancy context.
type GovernanceIdentity struct {
	TenantID      string `json:"tenantId"`
	ObjectID      string `json:"objectId"`
	DisplayName   string `json:"displayName"`
	LogicalTenant string `json:"logicalTenant,omitempty"`
	Team          string `json:"team,omitempty"`
}

// SandboxAccessRequestState is the administrator-controlled request lifecycle state.
type SandboxAccessRequestState string

// SandboxAccessRequestStatus contains the administrator decision and bounded lifetime.
type SandboxAccessRequestStatus struct {
	State          SandboxAccessRequestState `json:"state,omitempty"`
	Approver       *GovernanceIdentity       `json:"approver,omitempty"`
	DecisionReason string                    `json:"decisionReason,omitempty"`
	ApprovedAt     *metav1.Time              `json:"approvedAt,omitempty"`
	ExpiresAt      *metav1.Time              `json:"expiresAt,omitempty"`
}

// SandboxEgressEvent is an immutable sanitized authorization audit record.
// +kubebuilder:object:root=true
type SandboxEgressEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxEgressEventSpec `json:"spec"`
}

// SandboxEgressEventList is a list of SandboxEgressEvent resources.
// +kubebuilder:object:root=true
type SandboxEgressEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxEgressEvent `json:"items"`
}

// SandboxEgressDecisionSource identifies the authority source for one decision.
type SandboxEgressDecisionSource string

// SandboxEgressEventSpec contains only normalized, credential-free audit fields.
type SandboxEgressEventSpec struct {
	Timestamp                metav1.Time                 `json:"timestamp"`
	AssignmentRef            AssignmentReference         `json:"assignmentRef"`
	SandboxID                string                      `json:"sandboxId,omitempty"`
	PodUID                   types.UID                   `json:"podUid"`
	CapabilityBundleName     string                      `json:"capabilityBundleName"`
	CapabilityBundleRevision string                      `json:"capabilityBundleRevision"`
	LogicalTenant            string                      `json:"logicalTenant,omitempty"`
	Team                     string                      `json:"team,omitempty"`
	PermissionLevel          string                      `json:"permissionLevel,omitempty"`
	BoundaryDisplayName      string                      `json:"boundaryDisplayName,omitempty"`
	Backend                  string                      `json:"backend"`
	Method                   string                      `json:"method"`
	Host                     string                      `json:"host"`
	Path                     string                      `json:"path"`
	Allowed                  bool                        `json:"allowed"`
	Reason                   string                      `json:"reason"`
	DecisionSource           SandboxEgressDecisionSource `json:"decisionSource"`
	AccessRequestName        string                      `json:"accessRequestName,omitempty"`
}

// AddToScheme registers assignment resources in a runtime Scheme.
func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&CapabilityBundle{}, &CapabilityBundleList{},
		&SandboxAssignment{}, &SandboxAssignmentList{},
		&SandboxAccessRequest{}, &SandboxAccessRequestList{},
		&SandboxEgressEvent{}, &SandboxEgressEventList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
