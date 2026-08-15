package main

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation"
	"k8s.io/client-go/dynamic"
)

const governanceBodyLimit = 16 << 10

var (
	dashboardAssignmentsGVR = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxassignments"}
	dashboardBundlesGVR     = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "capabilitybundles"}
	dashboardRequestsGVR    = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxaccessrequests"}
	dashboardEventsGVR      = schema.GroupVersionResource{Group: assignmentv1alpha1.GroupName, Version: assignmentv1alpha1.Version, Resource: "sandboxegressevents"}
)

type governanceDashboard struct {
	client       dynamic.Interface
	namespace    string
	basePath     string
	publicOrigin string
	adminRole    string
	logger       *slog.Logger
	now          func() time.Time
}

type assignmentPageRow struct {
	Name, UID, SandboxID, Pod, Bundle, Boundary, LogicalTenant, Team, Permission, Ready string
}

type bundlePageRow struct {
	Name, UID, Boundary, LogicalTenant, Team, Permission string
}

type eventPageRow struct {
	Name, Timestamp, Assignment, SandboxID, Bundle, Boundary, Permission string
	Backend, Method, Host, Path, Allowed, Source, AccessRequest, Reason  string
}

type requestPageRow struct {
	Name, State, Assignment, Requester, RequestedDuration, Target, Reason string
	Approver, DecisionReason, ApprovedAt, ExpiresAt, ApproveAction        string
	DenyAction                                                            string
	RequestedMinutes                                                      int32
}

type accessPageData struct {
	BasePath, IdentityName, CSRFToken, Message string
	IsAdmin                                    bool
	Assignments                                []assignmentPageRow
	DeniedEvents                               []eventPageRow
}

type adminPageData struct {
	BasePath, IdentityName, CSRFToken, Message string
	Requests                                   []requestPageRow
	Assignments                                []assignmentPageRow
	Bundles                                    []bundlePageRow
	Events                                     []eventPageRow
}

func newGovernanceDashboard(client dynamic.Interface, cfg config, logger *slog.Logger) (*governanceDashboard, error) {
	if client == nil {
		return nil, errors.New("dashboard governance Kubernetes client is required")
	}
	redirect, err := url.Parse(cfg.redirectURI)
	if err != nil || redirect.Scheme == "" || redirect.Host == "" {
		return nil, errors.New("dashboard redirect URI must have an origin")
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &governanceDashboard{
		client:       client,
		namespace:    cfg.assignmentNamespace,
		basePath:     cfg.basePath,
		publicOrigin: redirect.Scheme + "://" + redirect.Host,
		adminRole:    cfg.adminRole,
		logger:       logger,
		now:          time.Now,
	}, nil
}

func (g *governanceDashboard) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /access", g.accessPage)
	mux.HandleFunc("POST /access/requests", g.createAccessRequest)
	mux.HandleFunc("GET /admin", g.adminPage)
	mux.HandleFunc("POST /admin/requests/{name}/approve", g.approveAccessRequest)
	mux.HandleFunc("POST /admin/requests/{name}/deny", g.denyAccessRequest)
}

func (g *governanceDashboard) accessPage(w http.ResponseWriter, r *http.Request) {
	identity, csrf, ok := governanceRequestContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	assignments, err := g.assignmentRows(r.Context())
	if err != nil {
		g.internalError(w, r, "list assignments", err)
		return
	}
	events, err := g.eventRows(r.Context(), true)
	if err != nil {
		g.internalError(w, r, "list denied egress events", err)
		return
	}
	g.setPageHeaders(w)
	if err := accessPageTemplate.Execute(w, accessPageData{
		BasePath:     g.basePath,
		IdentityName: identity.Name,
		CSRFToken:    csrf,
		Message:      r.URL.Query().Get("message"),
		IsAdmin:      contains(identity.Roles, g.adminRole),
		Assignments:  assignments,
		DeniedEvents: events,
	}); err != nil {
		g.internalError(w, r, "render access page", err)
	}
}

func (g *governanceDashboard) adminPage(w http.ResponseWriter, r *http.Request) {
	identity, csrf, ok := governanceRequestContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if !contains(identity.Roles, g.adminRole) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	requests, err := g.requestRows(r.Context())
	if err != nil {
		g.internalError(w, r, "list access requests", err)
		return
	}
	assignments, err := g.assignmentRows(r.Context())
	if err != nil {
		g.internalError(w, r, "list assignments", err)
		return
	}
	bundles, err := g.bundleRows(r.Context())
	if err != nil {
		g.internalError(w, r, "list capability bundles", err)
		return
	}
	events, err := g.eventRows(r.Context(), false)
	if err != nil {
		g.internalError(w, r, "list egress events", err)
		return
	}
	g.setPageHeaders(w)
	if err := adminPageTemplate.Execute(w, adminPageData{
		BasePath:     g.basePath,
		IdentityName: identity.Name,
		CSRFToken:    csrf,
		Message:      r.URL.Query().Get("message"),
		Requests:     requests,
		Assignments:  assignments,
		Bundles:      bundles,
		Events:       events,
	}); err != nil {
		g.internalError(w, r, "render admin page", err)
	}
}

func (g *governanceDashboard) createAccessRequest(w http.ResponseWriter, r *http.Request) {
	identity, _, ok := governanceRequestContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	form, ok := g.parseMutation(w, r, "csrf", "eventName", "reason", "durationMinutes")
	if !ok {
		return
	}
	eventName := form.Get("eventName")
	if errors := validation.IsDNS1123Subdomain(eventName); len(errors) != 0 {
		http.Error(w, "Invalid event name", http.StatusBadRequest)
		return
	}
	duration, err := parseDurationMinutes(form.Get("durationMinutes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reason := form.Get("reason")

	eventObject, err := g.client.Resource(dashboardEventsGVR).Namespace(g.namespace).Get(r.Context(), eventName, metav1.GetOptions{})
	if err != nil {
		g.resourceError(w, "get denied event", err)
		return
	}
	event := &assignmentv1alpha1.SandboxEgressEvent{}
	if err := fromUnstructured(eventObject, event); err != nil {
		g.internalError(w, r, "decode denied event", err)
		return
	}
	if event.Spec.Allowed || event.Spec.DecisionSource != assignmentv1alpha1.DecisionSourceDeny {
		http.Error(w, "Access can only be requested from a denied event", http.StatusConflict)
		return
	}
	target, err := governance.NormalizeTarget(event.Spec.Backend, event.Spec.Method, event.Spec.Host, event.Spec.Path)
	if err != nil || target.Backend != event.Spec.Backend || target.Method != event.Spec.Method ||
		target.Host != event.Spec.Host || target.Path != event.Spec.Path {
		http.Error(w, "Denied event target is invalid", http.StatusConflict)
		return
	}
	if err := g.validateEventAssignment(r.Context(), event); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	requester := assignmentv1alpha1.GovernanceIdentity{
		TenantID:      identity.TenantID,
		ObjectID:      identity.ObjectID,
		DisplayName:   identity.Name,
		LogicalTenant: event.Spec.LogicalTenant,
		Team:          event.Spec.Team,
	}
	spec := assignmentv1alpha1.SandboxAccessRequestSpec{
		AssignmentRef:            event.Spec.AssignmentRef,
		BasePolicyRevision:       event.Spec.CapabilityBundleRevision,
		Backend:                  target.Backend,
		Method:                   target.Method,
		Host:                     target.Host,
		Path:                     target.Path,
		Reason:                   reason,
		Requester:                requester,
		RequestedDurationSeconds: int32(duration / time.Second),
	}
	if err := governance.ValidateAccessRequestSpec(spec); err != nil {
		http.Error(w, "Invalid access request: "+err.Error(), http.StatusBadRequest)
		return
	}
	if duplicate, err := g.hasActiveDuplicate(r.Context(), spec); err != nil {
		g.internalError(w, r, "check duplicate access request", err)
		return
	} else if duplicate {
		http.Error(w, "An active request already exists for this exact target", http.StatusConflict)
		return
	}

	request := &assignmentv1alpha1.SandboxAccessRequest{
		TypeMeta: metav1.TypeMeta{APIVersion: assignmentv1alpha1.GroupVersion.String(), Kind: "SandboxAccessRequest"},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    g.namespace,
			GenerateName: "access-",
		},
		Spec: spec,
	}
	object, err := toUnstructured(request)
	if err != nil {
		g.internalError(w, r, "encode access request", err)
		return
	}
	created, err := g.client.Resource(dashboardRequestsGVR).Namespace(g.namespace).Create(
		r.Context(), object, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	)
	if err != nil {
		g.resourceError(w, "create access request", err)
		return
	}
	createdRequest := &assignmentv1alpha1.SandboxAccessRequest{}
	if err := fromUnstructured(created, createdRequest); err != nil {
		g.internalError(w, r, "decode created access request", err)
		return
	}
	createdRequest.Status.State = assignmentv1alpha1.SandboxAccessRequestPending
	if err := g.updateRequestStatus(r.Context(), created, createdRequest.Status); err != nil {
		g.internalError(w, r, "initialize access request status", err)
		return
	}
	g.redirectWithMessage(w, r, "/access", "Access request "+created.GetName()+" created")
}

func (g *governanceDashboard) approveAccessRequest(w http.ResponseWriter, r *http.Request) {
	identity, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	form, ok := g.parseMutation(w, r, "csrf", "decisionReason", "durationMinutes")
	if !ok {
		return
	}
	duration, err := parseDurationMinutes(form.Get("durationMinutes"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	reason := form.Get("decisionReason")
	if len(strings.TrimSpace(reason)) < 3 || len(reason) > 512 {
		http.Error(w, "Decision reason must be 3-512 characters", http.StatusBadRequest)
		return
	}
	object, request, ok := g.pendingRequest(w, r, r.PathValue("name"))
	if !ok {
		return
	}
	if err := governance.ValidateAccessRequestSpec(request.Spec); err != nil {
		http.Error(w, "Access request is invalid", http.StatusConflict)
		return
	}
	if duration > time.Duration(request.Spec.RequestedDurationSeconds)*time.Second {
		http.Error(w, "Approved duration exceeds the requested duration", http.StatusBadRequest)
		return
	}
	if err := g.validateRequestAssignment(r.Context(), request); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	approver, err := governanceIdentity(identity, "", "")
	if err != nil {
		http.Error(w, "Authenticated administrator identity is invalid", http.StatusForbidden)
		return
	}
	now := metav1.NewTime(g.now().UTC())
	expiresAt := metav1.NewTime(now.Add(duration))
	status := assignmentv1alpha1.SandboxAccessRequestStatus{
		State:          assignmentv1alpha1.SandboxAccessRequestApproved,
		Approver:       &approver,
		DecisionReason: reason,
		ApprovedAt:     &now,
		ExpiresAt:      &expiresAt,
	}
	if err := g.updateRequestStatus(r.Context(), object, status); err != nil {
		g.resourceError(w, "approve access request", err)
		return
	}
	g.redirectWithMessage(w, r, "/admin", "Access request "+request.Name+" approved")
}

func (g *governanceDashboard) denyAccessRequest(w http.ResponseWriter, r *http.Request) {
	identity, ok := g.requireAdmin(w, r)
	if !ok {
		return
	}
	form, ok := g.parseMutation(w, r, "csrf", "decisionReason")
	if !ok {
		return
	}
	reason := form.Get("decisionReason")
	if len(strings.TrimSpace(reason)) < 3 || len(reason) > 512 {
		http.Error(w, "Decision reason must be 3-512 characters", http.StatusBadRequest)
		return
	}
	object, request, ok := g.pendingRequest(w, r, r.PathValue("name"))
	if !ok {
		return
	}
	approver, err := governanceIdentity(identity, "", "")
	if err != nil {
		http.Error(w, "Authenticated administrator identity is invalid", http.StatusForbidden)
		return
	}
	status := assignmentv1alpha1.SandboxAccessRequestStatus{
		State:          assignmentv1alpha1.SandboxAccessRequestDenied,
		Approver:       &approver,
		DecisionReason: reason,
	}
	if err := g.updateRequestStatus(r.Context(), object, status); err != nil {
		g.resourceError(w, "deny access request", err)
		return
	}
	g.redirectWithMessage(w, r, "/admin", "Access request "+request.Name+" denied")
}

func (g *governanceDashboard) requireAdmin(w http.ResponseWriter, r *http.Request) (authenticatedIdentity, bool) {
	identity, _, ok := governanceRequestContext(r.Context())
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return authenticatedIdentity{}, false
	}
	if !contains(identity.Roles, g.adminRole) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return authenticatedIdentity{}, false
	}
	return identity, true
}

func (g *governanceDashboard) pendingRequest(w http.ResponseWriter, r *http.Request, name string) (*unstructured.Unstructured, *assignmentv1alpha1.SandboxAccessRequest, bool) {
	if errors := validation.IsDNS1123Subdomain(name); len(errors) != 0 {
		http.Error(w, "Invalid access request name", http.StatusBadRequest)
		return nil, nil, false
	}
	object, err := g.client.Resource(dashboardRequestsGVR).Namespace(g.namespace).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		g.resourceError(w, "get access request", err)
		return nil, nil, false
	}
	request := &assignmentv1alpha1.SandboxAccessRequest{}
	if err := fromUnstructured(object, request); err != nil {
		g.internalError(w, r, "decode access request", err)
		return nil, nil, false
	}
	if requestState(request.Status) != assignmentv1alpha1.SandboxAccessRequestPending {
		http.Error(w, "Access request has already been decided", http.StatusConflict)
		return nil, nil, false
	}
	return object, request, true
}

func (g *governanceDashboard) parseMutation(w http.ResponseWriter, r *http.Request, allowed ...string) (url.Values, bool) {
	if r.URL.RawQuery != "" {
		http.Error(w, "Query parameters are not accepted", http.StatusBadRequest)
		return nil, false
	}
	if r.Header.Get("Origin") != g.publicOrigin || strings.EqualFold(r.Header.Get("Sec-Fetch-Site"), "cross-site") {
		http.Error(w, "Cross-site request rejected", http.StatusForbidden)
		return nil, false
	}
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType != "application/x-www-form-urlencoded" {
		http.Error(w, "Unsupported content type", http.StatusUnsupportedMediaType)
		return nil, false
	}
	r.Body = http.MaxBytesReader(w, r.Body, governanceBodyLimit)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form body", http.StatusBadRequest)
		return nil, false
	}
	allowedSet := map[string]bool{}
	for _, name := range allowed {
		allowedSet[name] = true
	}
	for name, values := range r.PostForm {
		if !allowedSet[name] || len(values) != 1 {
			http.Error(w, "Invalid form fields", http.StatusBadRequest)
			return nil, false
		}
	}
	for _, name := range allowed {
		if len(r.PostForm[name]) != 1 {
			http.Error(w, "Missing form field: "+name, http.StatusBadRequest)
			return nil, false
		}
	}
	expected, ok := csrfTokenFromContext(r.Context())
	provided := r.PostForm.Get("csrf")
	if !ok || len(expected) != len(provided) || subtle.ConstantTimeCompare([]byte(expected), []byte(provided)) != 1 {
		http.Error(w, "Invalid CSRF token", http.StatusForbidden)
		return nil, false
	}
	return r.PostForm, true
}

func (g *governanceDashboard) validateEventAssignment(ctx context.Context, event *assignmentv1alpha1.SandboxEgressEvent) error {
	assignmentObject, err := g.client.Resource(dashboardAssignmentsGVR).Namespace(g.namespace).Get(
		ctx, event.Spec.AssignmentRef.Name, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("assignment is no longer available")
	}
	if assignmentObject.GetDeletionTimestamp() != nil || assignmentObject.GetUID() != event.Spec.AssignmentRef.UID {
		return errors.New("denied event belongs to a stale assignment incarnation")
	}
	bundleName, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "name")
	revision, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "policyRevision")
	if bundleName != event.Spec.CapabilityBundleName || revision != event.Spec.CapabilityBundleRevision {
		return errors.New("denied event belongs to a stale capability policy revision")
	}
	return nil
}

func (g *governanceDashboard) validateRequestAssignment(ctx context.Context, request *assignmentv1alpha1.SandboxAccessRequest) error {
	assignmentObject, err := g.client.Resource(dashboardAssignmentsGVR).Namespace(g.namespace).Get(
		ctx, request.Spec.AssignmentRef.Name, metav1.GetOptions{},
	)
	if err != nil {
		return errors.New("assignment is no longer available")
	}
	if assignmentObject.GetDeletionTimestamp() != nil || assignmentObject.GetUID() != request.Spec.AssignmentRef.UID {
		return errors.New("access request belongs to a stale assignment incarnation")
	}
	revision, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "policyRevision")
	if revision != request.Spec.BasePolicyRevision {
		return errors.New("access request belongs to a stale capability policy revision")
	}
	return nil
}

func (g *governanceDashboard) hasActiveDuplicate(ctx context.Context, spec assignmentv1alpha1.SandboxAccessRequestSpec) (bool, error) {
	list, err := g.client.Resource(dashboardRequestsGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return false, err
	}
	for i := range list.Items {
		request := &assignmentv1alpha1.SandboxAccessRequest{}
		if err := fromUnstructured(&list.Items[i], request); err != nil {
			return false, err
		}
		state := requestState(request.Status)
		if state != assignmentv1alpha1.SandboxAccessRequestPending && state != assignmentv1alpha1.SandboxAccessRequestApproved {
			continue
		}
		if state == assignmentv1alpha1.SandboxAccessRequestApproved &&
			(request.Status.ExpiresAt == nil || !request.Status.ExpiresAt.Time.After(g.now())) {
			continue
		}
		if request.Spec.AssignmentRef == spec.AssignmentRef &&
			request.Spec.BasePolicyRevision == spec.BasePolicyRevision &&
			request.Spec.Backend == spec.Backend && request.Spec.Method == spec.Method &&
			request.Spec.Host == spec.Host && request.Spec.Path == spec.Path {
			return true, nil
		}
	}
	return false, nil
}

func (g *governanceDashboard) updateRequestStatus(ctx context.Context, object *unstructured.Unstructured, status assignmentv1alpha1.SandboxAccessRequestStatus) error {
	request := &assignmentv1alpha1.SandboxAccessRequest{}
	if err := fromUnstructured(object, request); err != nil {
		return err
	}
	request.Status = status
	updated, err := toUnstructured(request)
	if err != nil {
		return err
	}
	_, err = g.client.Resource(dashboardRequestsGVR).Namespace(g.namespace).UpdateStatus(
		ctx, updated, metav1.UpdateOptions{FieldValidation: metav1.FieldValidationStrict},
	)
	return err
}

func (g *governanceDashboard) assignmentRows(ctx context.Context) ([]assignmentPageRow, error) {
	assignments, err := g.client.Resource(dashboardAssignmentsGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	bundles, err := g.bundleMap(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]assignmentPageRow, 0, len(assignments.Items))
	for i := range assignments.Items {
		object := &assignments.Items[i]
		assignmentObject := &assignmentv1alpha1.SandboxAssignment{}
		if err := fromUnstructured(object, assignmentObject); err != nil {
			return nil, err
		}
		bundle := bundles[assignmentObject.Spec.CapabilityBundleRef.Name]
		row := assignmentPageRow{
			Name:      assignmentObject.Name,
			UID:       string(assignmentObject.UID),
			SandboxID: assignmentObject.Annotations[assignment.SandboxIDAnnotation],
			Bundle:    assignmentObject.Spec.CapabilityBundleRef.Name,
			Ready:     assignmentReady(assignmentObject),
		}
		if assignmentObject.Status.PodRef != nil {
			row.Pod = assignmentObject.Status.PodRef.Name
		}
		if bundle != nil && bundle.Spec.Governance != nil {
			row.Boundary = bundle.Spec.Governance.DisplayName
			row.LogicalTenant = bundle.Spec.Governance.LogicalTenant
			row.Team = bundle.Spec.Governance.Team
			row.Permission = bundle.Spec.Governance.PermissionLevel
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b assignmentPageRow) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func (g *governanceDashboard) bundleMap(ctx context.Context) (map[string]*assignmentv1alpha1.CapabilityBundle, error) {
	list, err := g.client.Resource(dashboardBundlesGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	result := make(map[string]*assignmentv1alpha1.CapabilityBundle, len(list.Items))
	for i := range list.Items {
		bundle := &assignmentv1alpha1.CapabilityBundle{}
		if err := fromUnstructured(&list.Items[i], bundle); err != nil {
			return nil, err
		}
		result[bundle.Name] = bundle
	}
	return result, nil
}

func (g *governanceDashboard) bundleRows(ctx context.Context) ([]bundlePageRow, error) {
	bundles, err := g.bundleMap(ctx)
	if err != nil {
		return nil, err
	}
	rows := make([]bundlePageRow, 0, len(bundles))
	for _, bundle := range bundles {
		row := bundlePageRow{Name: bundle.Name, UID: string(bundle.UID)}
		if bundle.Spec.Governance != nil {
			row.Boundary = bundle.Spec.Governance.DisplayName
			row.LogicalTenant = bundle.Spec.Governance.LogicalTenant
			row.Team = bundle.Spec.Governance.Team
			row.Permission = bundle.Spec.Governance.PermissionLevel
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b bundlePageRow) int { return strings.Compare(a.Name, b.Name) })
	return rows, nil
}

func (g *governanceDashboard) eventRows(ctx context.Context, deniedOnly bool) ([]eventPageRow, error) {
	list, err := g.client.Resource(dashboardEventsGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	events := make([]assignmentv1alpha1.SandboxEgressEvent, 0, len(list.Items))
	for i := range list.Items {
		event := assignmentv1alpha1.SandboxEgressEvent{}
		if err := fromUnstructured(&list.Items[i], &event); err != nil {
			return nil, err
		}
		if deniedOnly && (event.Spec.Allowed || event.Spec.DecisionSource != assignmentv1alpha1.DecisionSourceDeny) {
			continue
		}
		events = append(events, event)
	}
	slices.SortFunc(events, func(a, b assignmentv1alpha1.SandboxEgressEvent) int {
		return b.Spec.Timestamp.Time.Compare(a.Spec.Timestamp.Time)
	})
	if len(events) > 100 {
		events = events[:100]
	}
	rows := make([]eventPageRow, 0, len(events))
	for _, event := range events {
		rows = append(rows, eventPageRow{
			Name:          event.Name,
			Timestamp:     event.Spec.Timestamp.Time.UTC().Format(time.RFC3339),
			Assignment:    event.Spec.AssignmentRef.Name,
			SandboxID:     event.Spec.SandboxID,
			Bundle:        event.Spec.CapabilityBundleName,
			Boundary:      event.Spec.BoundaryDisplayName,
			Permission:    event.Spec.PermissionLevel,
			Backend:       event.Spec.Backend,
			Method:        event.Spec.Method,
			Host:          event.Spec.Host,
			Path:          event.Spec.Path,
			Allowed:       strconv.FormatBool(event.Spec.Allowed),
			Source:        string(event.Spec.DecisionSource),
			AccessRequest: event.Spec.AccessRequestName,
			Reason:        event.Spec.Reason,
		})
	}
	return rows, nil
}

func (g *governanceDashboard) requestRows(ctx context.Context) ([]requestPageRow, error) {
	list, err := g.client.Resource(dashboardRequestsGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	requests := make([]assignmentv1alpha1.SandboxAccessRequest, 0, len(list.Items))
	for i := range list.Items {
		request := assignmentv1alpha1.SandboxAccessRequest{}
		if err := fromUnstructured(&list.Items[i], &request); err != nil {
			return nil, err
		}
		requests = append(requests, request)
	}
	slices.SortFunc(requests, func(a, b assignmentv1alpha1.SandboxAccessRequest) int {
		return b.CreationTimestamp.Time.Compare(a.CreationTimestamp.Time)
	})
	rows := make([]requestPageRow, 0, len(requests))
	for _, request := range requests {
		row := requestPageRow{
			Name:              request.Name,
			State:             string(requestState(request.Status)),
			Assignment:        request.Spec.AssignmentRef.Name,
			Requester:         identityDisplay(request.Spec.Requester),
			RequestedDuration: (time.Duration(request.Spec.RequestedDurationSeconds) * time.Second).String(),
			RequestedMinutes:  request.Spec.RequestedDurationSeconds / 60,
			Target:            fmt.Sprintf("%s %s://%s%s", request.Spec.Method, request.Spec.Backend, request.Spec.Host, request.Spec.Path),
			Reason:            request.Spec.Reason,
			DecisionReason:    request.Status.DecisionReason,
			ApproveAction:     fmt.Sprintf("%s/admin/requests/%s/approve", g.basePath, request.Name),
			DenyAction:        fmt.Sprintf("%s/admin/requests/%s/deny", g.basePath, request.Name),
		}
		if request.Status.Approver != nil {
			row.Approver = identityDisplay(*request.Status.Approver)
		}
		if request.Status.ApprovedAt != nil {
			row.ApprovedAt = request.Status.ApprovedAt.Time.UTC().Format(time.RFC3339)
		}
		if request.Status.ExpiresAt != nil {
			row.ExpiresAt = request.Status.ExpiresAt.Time.UTC().Format(time.RFC3339)
		}
		rows = append(rows, row)
	}
	return rows, nil
}

func (g *governanceDashboard) setPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'self'; frame-ancestors 'none'")
}

func (g *governanceDashboard) redirectWithMessage(w http.ResponseWriter, r *http.Request, path, message string) {
	http.Redirect(w, r, g.basePath+path+"?message="+url.QueryEscape(message), http.StatusSeeOther)
}

func (g *governanceDashboard) resourceError(w http.ResponseWriter, operation string, err error) {
	switch {
	case apierrors.IsNotFound(err):
		http.Error(w, "Resource not found", http.StatusNotFound)
	case apierrors.IsConflict(err):
		http.Error(w, "Resource changed; reload and retry", http.StatusConflict)
	case apierrors.IsForbidden(err):
		http.Error(w, "Kubernetes authorization denied", http.StatusForbidden)
	default:
		g.logger.Error(operation, "error", err)
		http.Error(w, "Governance operation failed", http.StatusInternalServerError)
	}
}

func (g *governanceDashboard) internalError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	g.logger.ErrorContext(r.Context(), operation, "error", err)
	http.Error(w, "Governance operation failed", http.StatusInternalServerError)
}

func governanceRequestContext(ctx context.Context) (authenticatedIdentity, string, bool) {
	identity, identityOK := authenticatedIdentityFromContext(ctx)
	csrf, csrfOK := csrfTokenFromContext(ctx)
	return identity, csrf, identityOK && csrfOK
}

func governanceIdentity(identity authenticatedIdentity, logicalTenant, team string) (assignmentv1alpha1.GovernanceIdentity, error) {
	result := assignmentv1alpha1.GovernanceIdentity{
		TenantID:      identity.TenantID,
		ObjectID:      identity.ObjectID,
		DisplayName:   identity.Name,
		LogicalTenant: logicalTenant,
		Team:          team,
	}
	return result, governance.ValidateIdentity(result)
}

func parseDurationMinutes(value string) (time.Duration, error) {
	minutes, err := strconv.Atoi(value)
	if err != nil {
		return 0, errors.New("duration must be a whole number of minutes")
	}
	duration := time.Duration(minutes) * time.Minute
	if duration < governance.MinimumRequestedDuration || duration > governance.MaximumRequestedDuration {
		return 0, fmt.Errorf("duration must be between 1 and %d minutes", int(governance.MaximumRequestedDuration/time.Minute))
	}
	return duration, nil
}

func requestState(status assignmentv1alpha1.SandboxAccessRequestStatus) assignmentv1alpha1.SandboxAccessRequestState {
	if status.State == "" {
		return assignmentv1alpha1.SandboxAccessRequestPending
	}
	return status.State
}

func assignmentReady(value *assignmentv1alpha1.SandboxAssignment) string {
	for _, condition := range value.Status.Conditions {
		if condition.Type == "Ready" {
			return string(condition.Status)
		}
	}
	return "Unknown"
}

func identityDisplay(identity assignmentv1alpha1.GovernanceIdentity) string {
	return identity.DisplayName + " (" + identity.TenantID + "/" + identity.ObjectID + ")"
}

func fromUnstructured(object *unstructured.Unstructured, output any) error {
	return runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, output)
}

func toUnstructured(object any) (*unstructured.Unstructured, error) {
	value, err := runtime.DefaultUnstructuredConverter.ToUnstructured(object)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: value}, nil
}

var governanceStyles = `
  :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
  body { margin: 0; background: #0b1020; color: #eef2ff; }
  nav, main { width: min(92rem, calc(100% - 2rem)); margin: auto; }
  nav { display: flex; gap: 1rem; padding: 1rem 0; align-items: center; }
  nav a { color: #93c5fd; } nav span { margin-left: auto; color: #cbd5e1; }
  section { margin: 1rem 0 2rem; padding: 1rem; border: 1px solid #26324d; border-radius: .75rem; background: #111a2e; overflow-x: auto; }
  table { border-collapse: collapse; width: 100%; font-size: .9rem; }
  th, td { text-align: left; vertical-align: top; padding: .55rem; border-bottom: 1px solid #26324d; }
  code { white-space: nowrap; } form { display: grid; gap: .4rem; min-width: 18rem; }
  input, textarea, button { font: inherit; padding: .45rem; } textarea { min-height: 4rem; }
  button { color: white; background: #2563eb; border: 0; border-radius: .35rem; cursor: pointer; }
  .deny { background: #b91c1c; } .message { padding: .75rem; background: #14532d; border-radius: .5rem; }
`

var accessPageTemplate = template.Must(template.New("access").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sandbox access governance</title><style>` + governanceStyles + `</style></head><body>
<nav><a href="{{.BasePath}}/">Sandbox dashboard</a><a href="{{.BasePath}}/access">Access</a>{{if .IsAdmin}}<a href="{{.BasePath}}/admin">Admin</a>{{end}}<span>{{.IdentityName}}</span></nav>
<main><h1>Sandbox access requests <small>POC</small></h1>{{if .Message}}<p class="message">{{.Message}}</p>{{end}}
<section><h2>Current assignments and boundaries</h2><table><thead><tr><th>Assignment / sandbox</th><th>Pod</th><th>Bundle</th><th>Logical boundary</th><th>Permission</th><th>Ready</th></tr></thead><tbody>
{{range .Assignments}}<tr><td><code>{{.Name}}</code><br>{{.SandboxID}}</td><td>{{.Pod}}</td><td>{{.Bundle}}</td><td>{{.Boundary}}<br>{{.LogicalTenant}} / {{.Team}}</td><td>{{.Permission}}</td><td>{{.Ready}}</td></tr>{{else}}<tr><td colspan="6">No assignments found.</td></tr>{{end}}
</tbody></table></section>
<section><h2>Recent denied egress</h2><table><thead><tr><th>Time / sandbox</th><th>Exact target</th><th>Reason</th><th>Request temporary access</th></tr></thead><tbody>
{{range .DeniedEvents}}<tr><td>{{.Timestamp}}<br>{{.SandboxID}}<br><code>{{.Assignment}}</code></td><td><code>{{.Method}} {{.Backend}}://{{.Host}}{{.Path}}</code><br>{{.Boundary}} / {{.Permission}}</td><td>{{.Reason}}</td><td>
<form method="post" action="{{$.BasePath}}/access/requests"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><input type="hidden" name="eventName" value="{{.Name}}">
<label>Reason<textarea name="reason" maxlength="512" required></textarea></label><label>Duration (minutes)<input name="durationMinutes" type="number" min="1" max="480" value="60" required></label><button type="submit">Request exact access</button></form>
</td></tr>{{else}}<tr><td colspan="4">No denied egress events found.</td></tr>{{end}}</tbody></table></section></main></body></html>`))

var adminPageTemplate = template.Must(template.New("admin").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sandbox governance admin</title><style>` + governanceStyles + `</style></head><body>
<nav><a href="{{.BasePath}}/">Sandbox dashboard</a><a href="{{.BasePath}}/access">Access</a><a href="{{.BasePath}}/admin">Admin</a><span>{{.IdentityName}}</span></nav>
<main><h1>Sandbox governance admin <small>POC</small></h1>{{if .Message}}<p class="message">{{.Message}}</p>{{end}}
<section><h2>Access requests</h2><table><thead><tr><th>Request</th><th>Requester / reason</th><th>Exact target</th><th>Decision</th></tr></thead><tbody>
{{range .Requests}}<tr><td><code>{{.Name}}</code><br>{{.State}}<br>{{.Assignment}}<br>requested {{.RequestedDuration}}</td><td>{{.Requester}}<br>{{.Reason}}</td><td><code>{{.Target}}</code></td><td>
{{if eq .State "Pending"}}<form method="post" action="{{.ApproveAction}}"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><label>Decision reason<textarea name="decisionReason" maxlength="512" required></textarea></label><label>Duration (minutes)<input name="durationMinutes" type="number" min="1" max="{{.RequestedMinutes}}" value="{{.RequestedMinutes}}" required></label><button type="submit">Approve</button></form>
<form method="post" action="{{.DenyAction}}"><input type="hidden" name="csrf" value="{{$.CSRFToken}}"><label>Decision reason<textarea name="decisionReason" maxlength="512" required></textarea></label><button class="deny" type="submit">Deny</button></form>
{{else}}{{.Approver}}<br>{{.DecisionReason}}<br>{{.ApprovedAt}} {{.ExpiresAt}}{{end}}</td></tr>{{else}}<tr><td colspan="4">No access requests found.</td></tr>{{end}}</tbody></table></section>
<section><h2>Capability boundaries</h2><table><thead><tr><th>Bundle</th><th>Boundary</th><th>Logical tenant / team</th><th>Permission</th></tr></thead><tbody>
{{range .Bundles}}<tr><td>{{.Name}}</td><td>{{.Boundary}}</td><td>{{.LogicalTenant}} / {{.Team}}</td><td>{{.Permission}}</td></tr>{{else}}<tr><td colspan="4">No bundles found.</td></tr>{{end}}</tbody></table></section>
<section><h2>Current assignments</h2><table><thead><tr><th>Assignment / sandbox</th><th>Bundle</th><th>Boundary</th><th>Permission</th><th>Ready</th></tr></thead><tbody>
{{range .Assignments}}<tr><td>{{.Name}}<br>{{.SandboxID}}</td><td>{{.Bundle}}</td><td>{{.Boundary}}</td><td>{{.Permission}}</td><td>{{.Ready}}</td></tr>{{else}}<tr><td colspan="5">No assignments found.</td></tr>{{end}}</tbody></table></section>
<section><h2>Recent egress events</h2><table><thead><tr><th>Time / sandbox</th><th>Target</th><th>Decision</th><th>Reason</th></tr></thead><tbody>
{{range .Events}}<tr><td>{{.Timestamp}}<br>{{.SandboxID}}</td><td><code>{{.Method}} {{.Backend}}://{{.Host}}{{.Path}}</code></td><td>{{.Allowed}} / {{.Source}}<br>{{.AccessRequest}}</td><td>{{.Reason}}</td></tr>{{else}}<tr><td colspan="4">No egress events found.</td></tr>{{end}}</tbody></table></section>
</main></body></html>`))
