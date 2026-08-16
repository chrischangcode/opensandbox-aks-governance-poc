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

	ValidationRunRunning   SandboxValidationRunState = "Running"
	ValidationRunSucceeded SandboxValidationRunState = "Succeeded"
	ValidationRunFailed    SandboxValidationRunState = "Failed"
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
	CommandPolicy   []CommandPolicyRule `json:"commandPolicy,omitempty"`
	ValidationRules []ValidationRule    `json:"validationRules,omitempty"`
}

// CommandPolicyRule classifies one anchored exact-literal command string.
type CommandPolicyRule struct {
	Pattern  string `json:"pattern"`
	Decision string `json:"decision"`
	Reason   string `json:"reason,omitempty"`
}

// ValidationRule selects one exact pre-authorized command for changed paths.
type ValidationRule struct {
	PathPrefix string `json:"pathPrefix"`
	Command    string `json:"command"`
}

// SandboxTemplate is an immutable administrator-approved sandbox shape.
// +kubebuilder:object:root=true
type SandboxTemplate struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxTemplateSpec `json:"spec"`
}

// SandboxTemplateList is a list of SandboxTemplate resources.
// +kubebuilder:object:root=true
type SandboxTemplateList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxTemplate `json:"items"`
}

// SandboxTemplateSpec selects the runtime shape and immutable capability boundary.
type SandboxTemplateSpec struct {
	DisplayName         string                    `json:"displayName"`
	Description         string                    `json:"description,omitempty"`
	Image               string                    `json:"image"`
	Entrypoint          []string                  `json:"entrypoint"`
	CapabilityBundleRef CapabilityBundleReference `json:"capabilityBundleRef"`
	Resources           SandboxTemplateResources  `json:"resources"`
	TimeoutSeconds      int64                     `json:"timeoutSeconds"`
	Enabled             bool                      `json:"enabled"`
}

// SandboxTemplateResources contains sandbox CPU and memory limits.
type SandboxTemplateResources struct {
	CPU    string `json:"cpu"`
	Memory string `json:"memory"`
}

// SandboxTenantPolicy defines one immutable logical-tenant admission budget.
// +kubebuilder:object:root=true
type SandboxTenantPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxTenantPolicySpec `json:"spec"`
}

// SandboxTenantPolicyList is a list of SandboxTenantPolicy resources.
// +kubebuilder:object:root=true
type SandboxTenantPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxTenantPolicy `json:"items"`
}

// SandboxTenantPolicySpec limits one logical tenant within the shared AKS tenant.
type SandboxTenantPolicySpec struct {
	LogicalTenant                   string   `json:"logicalTenant"`
	WorkloadNamespace               string   `json:"workloadNamespace"`
	AllowedCapabilityBundles        []string `json:"allowedCapabilityBundles"`
	AllowedCapabilityBundlePrefixes []string `json:"allowedCapabilityBundlePrefixes,omitempty"`
	MaxConcurrentSandboxes          int32    `json:"maxConcurrentSandboxes"`
	MaxLifetimeSeconds              int32    `json:"maxLifetimeSeconds"`
	MaxAccessRequestDurationSeconds int32    `json:"maxAccessRequestDurationSeconds"`
	MaxCPU                          string   `json:"maxCpu"`
	MaxMemory                       string   `json:"maxMemory"`
	Enabled                         bool     `json:"enabled"`
}

// SandboxPrincipalBinding maps one authenticated Entra principal to logical
// tenant scopes used by the requester and administrator workflows.
// +kubebuilder:object:root=true
type SandboxPrincipalBinding struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxPrincipalBindingSpec `json:"spec"`
}

// SandboxPrincipalBindingList is a list of SandboxPrincipalBinding resources.
// +kubebuilder:object:root=true
type SandboxPrincipalBindingList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxPrincipalBinding `json:"items"`
}

// SandboxPrincipalBindingSpec contains immutable principal-to-tenant scopes.
type SandboxPrincipalBindingSpec struct {
	TenantID                string   `json:"tenantId,omitempty"`
	ObjectID                string   `json:"objectId,omitempty"`
	ServiceAccountNamespace string   `json:"serviceAccountNamespace,omitempty"`
	ServiceAccountName      string   `json:"serviceAccountName,omitempty"`
	RequesterTenants        []string `json:"requesterTenants,omitempty"`
	AdminTenants            []string `json:"adminTenants,omitempty"`
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

// SandboxAssignmentSpec records the server-resolved immutable template and
// capability boundary for one sandbox.
type SandboxAssignmentSpec struct {
	TemplateRef         SandboxTemplateReference  `json:"templateRef"`
	LogicalTenant       string                    `json:"logicalTenant"`
	CapabilityBundleRef CapabilityBundleReference `json:"capabilityBundleRef"`
}

// SandboxTemplateReference identifies an immutable template incarnation.
type SandboxTemplateReference struct {
	Name         string    `json:"name"`
	UID          types.UID `json:"uid"`
	SpecRevision string    `json:"specRevision"`
}

// CapabilityBundleReference names a bundle in the assignment namespace.
type CapabilityBundleReference struct {
	Name           string `json:"name"`
	PolicyRevision string `json:"policyRevision,omitempty"`
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
	PodUID                   types.UID           `json:"podUid"`
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

// SandboxValidationRun is durable, credential-free evidence from one
// sandbox-only source validation.
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
type SandboxValidationRun struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxValidationRunSpec   `json:"spec"`
	Status            SandboxValidationRunStatus `json:"status,omitempty"`
}

// SandboxValidationRunList is a list of SandboxValidationRun resources.
// +kubebuilder:object:root=true
type SandboxValidationRunList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxValidationRun `json:"items"`
}

// SandboxValidationRunSpec binds selected tests to one exact sandbox and policy incarnation.
type SandboxValidationRunSpec struct {
	TaskID                   string              `json:"taskId"`
	Repository               string              `json:"repository"`
	SourceRevision           string              `json:"sourceRevision"`
	ChangedPaths             []string            `json:"changedPaths"`
	SelectedCommands         []string            `json:"selectedCommands"`
	TemplateName             string              `json:"templateName"`
	AssignmentRef            AssignmentReference `json:"assignmentRef"`
	PodUID                   types.UID           `json:"podUid"`
	SandboxID                string              `json:"sandboxId"`
	CapabilityBundleName     string              `json:"capabilityBundleName"`
	CapabilityBundleRevision string              `json:"capabilityBundleRevision"`
	StartedAt                metav1.Time         `json:"startedAt"`
}

// SandboxValidationRunState is the terminal state of one validation.
type SandboxValidationRunState string

// SandboxValidationCommandResult stores hashes rather than unrestricted logs.
type SandboxValidationCommandResult struct {
	Command      string `json:"command"`
	ExitCode     int32  `json:"exitCode"`
	StdoutSHA256 string `json:"stdoutSha256"`
	StderrSHA256 string `json:"stderrSha256"`
}

// SandboxValidationRunStatus contains attested validation results and cleanup state.
type SandboxValidationRunStatus struct {
	State       SandboxValidationRunState        `json:"state,omitempty"`
	CompletedAt *metav1.Time                     `json:"completedAt,omitempty"`
	Results     []SandboxValidationCommandResult `json:"results,omitempty"`
	CleanedUp   bool                             `json:"cleanedUp,omitempty"`
	Message     string                           `json:"message,omitempty"`
}

// SandboxCredentialEvent is a credential-free audit event for one broker grant.
// +kubebuilder:object:root=true
type SandboxCredentialEvent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxCredentialEventSpec `json:"spec"`
}

// SandboxCredentialEventList is a list of SandboxCredentialEvent resources.
// +kubebuilder:object:root=true
type SandboxCredentialEventList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxCredentialEvent `json:"items"`
}

// SandboxCredentialEventSpec excludes the credential and request contents.
type SandboxCredentialEventSpec struct {
	Timestamp                metav1.Time         `json:"timestamp"`
	GrantID                  string              `json:"grantId"`
	Action                   string              `json:"action"`
	TaskID                   string              `json:"taskId"`
	AssignmentRef            AssignmentReference `json:"assignmentRef"`
	PodUID                   types.UID           `json:"podUid"`
	SandboxID                string              `json:"sandboxId"`
	CapabilityBundleName     string              `json:"capabilityBundleName"`
	CapabilityBundleRevision string              `json:"capabilityBundleRevision"`
	Backend                  string              `json:"backend"`
	Method                   string              `json:"method"`
	Host                     string              `json:"host"`
	Path                     string              `json:"path"`
	ExpiresAt                metav1.Time         `json:"expiresAt"`
}

// SandboxCredentialRevocation durably revokes one broker grant.
// +kubebuilder:object:root=true
type SandboxCredentialRevocation struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              SandboxCredentialRevocationSpec `json:"spec"`
}

// SandboxCredentialRevocationList is a list of SandboxCredentialRevocation resources.
// +kubebuilder:object:root=true
type SandboxCredentialRevocationList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []SandboxCredentialRevocation `json:"items"`
}

// SandboxCredentialRevocationSpec contains no credential material.
type SandboxCredentialRevocationSpec struct {
	GrantID       string              `json:"grantId"`
	ExpiresAt     metav1.Time         `json:"expiresAt"`
	AssignmentRef AssignmentReference `json:"assignmentRef"`
	PodUID        types.UID           `json:"podUid"`
	SandboxID     string              `json:"sandboxId"`
}

// AddToScheme registers assignment resources in a runtime Scheme.
func AddToScheme(scheme *runtime.Scheme) error {
	scheme.AddKnownTypes(GroupVersion,
		&CapabilityBundle{}, &CapabilityBundleList{},
		&SandboxTemplate{}, &SandboxTemplateList{},
		&SandboxTenantPolicy{}, &SandboxTenantPolicyList{},
		&SandboxPrincipalBinding{}, &SandboxPrincipalBindingList{},
		&SandboxAssignment{}, &SandboxAssignmentList{},
		&SandboxAccessRequest{}, &SandboxAccessRequestList{},
		&SandboxEgressEvent{}, &SandboxEgressEventList{},
		&SandboxValidationRun{}, &SandboxValidationRunList{},
		&SandboxCredentialEvent{}, &SandboxCredentialEventList{},
		&SandboxCredentialRevocation{}, &SandboxCredentialRevocationList{},
	)
	metav1.AddToGroupVersion(scheme, GroupVersion)
	return nil
}
