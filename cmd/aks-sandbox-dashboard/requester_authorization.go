package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	osbclient "github.com/bahe-msft/osb-dashboard/opensandbox"
	"github.com/coder/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
)

var (
	errRequesterUnauthorized = errors.New("dashboard requester identity is unavailable")
	errRequesterForbidden    = errors.New("dashboard requester authorization denied")
	errRequesterUnavailable  = errors.New("dashboard requester authorization is unavailable")

	errSandboxAssignmentMissing   = errors.New("sandbox is not bound to a governed assignment")
	errSandboxAssignmentAmbiguous = errors.New("sandbox matches multiple governed assignments")
	errSandboxLogicalTenantEmpty  = errors.New("sandbox assignment has no logical tenant")
	errTemplateLogicalTenantEmpty = errors.New("dashboard sandbox template has no logical tenant")
)

type requesterLifecycleAuthorizer struct {
	client        dynamic.Interface
	sandboxReader osbclient.Reader
	namespace     string
	basePath      string
	templateName  string
}

func newRequesterLifecycleAuthorizer(client dynamic.Interface, sandboxReader osbclient.Reader, cfg config) (*requesterLifecycleAuthorizer, error) {
	if client == nil || sandboxReader == nil {
		return nil, errors.New("requester dashboard authorization requires Kubernetes and sandbox readers")
	}
	if cfg.assignmentNamespace == "" || cfg.basePath == "" || cfg.sandboxTemplate == "" {
		return nil, errors.New("requester dashboard authorization requires assignment namespace, base path, and sandbox template")
	}
	return &requesterLifecycleAuthorizer{
		client:        client,
		sandboxReader: sandboxReader,
		namespace:     cfg.assignmentNamespace,
		basePath:      cfg.basePath,
		templateName:  cfg.sandboxTemplate,
	}, nil
}

func (a *requesterLifecycleAuthorizer) WrapClient(client osbclient.Client) osbclient.Client {
	if client == nil {
		return nil
	}
	return &authorizedDashboardClient{base: client, authorizer: a}
}

func (a *requesterLifecycleAuthorizer) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relativePath, scoped := a.relativePath(r.URL.Path)
		if !scoped {
			next.ServeHTTP(w, r)
			return
		}

		var err error
		switch {
		case r.Method == http.MethodPost && relativePath == "/dashboard/sandboxes":
			err = a.authorizeTemplate(r.Context())
		case isAggregateSandboxPath(relativePath):
			err = a.authorizeAggregateSandboxes(r.Context())
			if err == nil {
				err = a.authorizeAggregateSnapshots(r.Context())
			}
		case r.Method == http.MethodGet && usesSandboxSnapshotTotals(relativePath):
			sandboxID, ok := sandboxPathValue(relativePath)
			if ok {
				err = a.authorizeSandbox(r.Context(), sandboxID)
				if err == nil {
					err = a.authorizeAggregateSnapshots(r.Context())
				}
			}
		case r.Method == http.MethodPost && relativePath == "/dashboard/snapshots":
			if parseErr := r.ParseForm(); parseErr != nil {
				err = fmt.Errorf("%w: parse snapshot form: %v", errRequesterUnavailable, parseErr)
				break
			}
			if sandboxID := strings.TrimSpace(r.FormValue("sandboxID")); sandboxID != "" {
				err = a.authorizeSandbox(r.Context(), sandboxID)
			}
		default:
			if sandboxID, ok := sandboxPathValue(relativePath); ok {
				err = a.authorizeSandbox(r.Context(), sandboxID)
			}
		}
		if err != nil {
			writeRequesterAuthorizationError(w, err)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *requesterLifecycleAuthorizer) relativePath(path string) (string, bool) {
	relativePath, ok := strings.CutPrefix(path, a.basePath)
	if !ok {
		return "", false
	}
	if relativePath == "" {
		return "/", true
	}
	if !strings.HasPrefix(relativePath, "/") {
		return "/" + relativePath, true
	}
	return relativePath, true
}

func isAggregateSandboxPath(relativePath string) bool {
	switch relativePath {
	case "/", "/stats", "/snapshots", "/dashboard/overview", "/dashboard/stats", "/dashboard/snapshots":
		return true
	default:
		return false
	}
}

func usesSandboxSnapshotTotals(relativePath string) bool {
	switch {
	case strings.HasPrefix(relativePath, "/sandboxes/"):
		return !strings.Contains(strings.TrimPrefix(relativePath, "/sandboxes/"), "/")
	case strings.HasPrefix(relativePath, "/dashboard/sandboxes/"):
		rest := strings.TrimPrefix(relativePath, "/dashboard/sandboxes/")
		return rest != "" && (rest == pathHead(rest) || strings.HasSuffix(relativePath, "/fragment"))
	default:
		return false
	}
}

func pathHead(value string) string {
	head, _, _ := strings.Cut(value, "/")
	return head
}

func sandboxPathValue(relativePath string) (string, bool) {
	for _, prefix := range []string{"/sandboxes/", "/dashboard/sandboxes/"} {
		rest, ok := strings.CutPrefix(relativePath, prefix)
		if !ok || rest == "" {
			continue
		}
		sandboxID := pathHead(rest)
		if sandboxID != "" {
			return sandboxID, true
		}
	}
	return "", false
}

func writeRequesterAuthorizationError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errRequesterUnauthorized):
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	case errors.Is(err, errRequesterForbidden):
		http.Error(w, "Forbidden", http.StatusForbidden)
	default:
		http.Error(w, "Requester authorization is unavailable", http.StatusServiceUnavailable)
	}
}

func (a *requesterLifecycleAuthorizer) authorizeTemplate(ctx context.Context) error {
	tenants, err := a.requesterTenants(ctx)
	if err != nil {
		return err
	}
	logicalTenant, err := a.templateLogicalTenant(ctx)
	if err != nil {
		return err
	}
	if !tenantAllowed(tenants, logicalTenant) {
		return fmt.Errorf("%w: requester is not authorized for sandbox template tenant %q", errRequesterForbidden, logicalTenant)
	}
	return nil
}

func (a *requesterLifecycleAuthorizer) authorizeAggregateSandboxes(ctx context.Context) error {
	tenants, err := a.requesterTenants(ctx)
	if err != nil {
		return err
	}
	sandboxes, err := a.sandboxReader.ListSandboxes(ctx)
	if err != nil {
		return fmt.Errorf("%w: list sandboxes: %v", errRequesterUnavailable, err)
	}
	for _, sandbox := range sandboxes {
		allowed, allowErr := a.sandboxAllowedByObject(ctx, sandbox, tenants)
		if allowErr != nil {
			return allowErr
		}
		if !allowed {
			return fmt.Errorf("%w: requester cannot list sandbox %q", errRequesterForbidden, sandbox.ID)
		}
	}
	return nil
}

func (a *requesterLifecycleAuthorizer) authorizeAggregateSnapshots(ctx context.Context) error {
	tenants, err := a.requesterTenants(ctx)
	if err != nil {
		return err
	}
	snapshots, err := a.sandboxReader.ListSnapshots(ctx)
	if err != nil {
		return fmt.Errorf("%w: list snapshots: %v", errRequesterUnavailable, err)
	}
	for _, snapshot := range snapshots {
		allowed, allowErr := a.snapshotAllowed(ctx, snapshot, tenants)
		if allowErr != nil {
			return allowErr
		}
		if !allowed {
			return fmt.Errorf("%w: requester cannot list snapshot %q", errRequesterForbidden, snapshot.ID)
		}
	}
	return nil
}

func (a *requesterLifecycleAuthorizer) authorizeSandbox(ctx context.Context, sandboxID string) error {
	tenants, err := a.requesterTenants(ctx)
	if err != nil {
		return err
	}
	allowed, err := a.sandboxAllowed(ctx, sandboxID, tenants)
	if err != nil {
		return err
	}
	if !allowed {
		return fmt.Errorf("%w: requester is not authorized for sandbox %q", errRequesterForbidden, sandboxID)
	}
	return nil
}

func (a *requesterLifecycleAuthorizer) requesterTenants(ctx context.Context) (map[string]struct{}, error) {
	identity, ok := authenticatedIdentityFromContext(ctx)
	if !ok {
		return nil, fmt.Errorf("%w", errRequesterUnauthorized)
	}
	scopes, err := loadPrincipalScopes(ctx, a.client, a.namespace, identity)
	switch {
	case err == nil:
	case errors.Is(err, errPrincipalBindingMissing), errors.Is(err, errPrincipalBindingAmbiguous):
		return nil, fmt.Errorf("%w: %v", errRequesterForbidden, err)
	default:
		return nil, fmt.Errorf("%w: load principal scopes: %v", errRequesterUnavailable, err)
	}
	if len(scopes.requester) == 0 {
		return nil, fmt.Errorf("%w: principal has no requester tenant scopes", errRequesterForbidden)
	}
	return scopes.requester, nil
}

func (a *requesterLifecycleAuthorizer) templateLogicalTenant(ctx context.Context) (string, error) {
	templateObject, err := a.client.Resource(dashboardTemplatesGVR).Namespace(a.namespace).Get(ctx, a.templateName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("%w: get sandbox template: %v", errRequesterUnavailable, err)
	}
	bundleName, _, _ := nestedString(templateObject.Object, "spec", "capabilityBundleRef", "name")
	if strings.TrimSpace(bundleName) == "" {
		return "", fmt.Errorf("%w", errTemplateLogicalTenantEmpty)
	}
	return a.bundleLogicalTenant(ctx, bundleName)
}

func (a *requesterLifecycleAuthorizer) bundleLogicalTenant(ctx context.Context, bundleName string) (string, error) {
	bundleObject, err := a.client.Resource(dashboardBundlesGVR).Namespace(a.namespace).Get(ctx, bundleName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("%w: get capability bundle %q: %v", errRequesterUnavailable, bundleName, err)
	}
	logicalTenant, _, _ := nestedString(bundleObject.Object, "spec", "governance", "logicalTenant")
	if strings.TrimSpace(logicalTenant) == "" {
		return "", fmt.Errorf("%w", errSandboxLogicalTenantEmpty)
	}
	return logicalTenant, nil
}

func (a *requesterLifecycleAuthorizer) sandboxAllowed(ctx context.Context, sandboxID string, tenants map[string]struct{}) (bool, error) {
	logicalTenant, err := a.sandboxLogicalTenant(ctx, sandboxID)
	switch {
	case err == nil:
		return tenantAllowed(tenants, logicalTenant), nil
	case errors.Is(err, errSandboxAssignmentMissing), errors.Is(err, errSandboxAssignmentAmbiguous), errors.Is(err, errSandboxLogicalTenantEmpty):
		return false, nil
	default:
		return false, fmt.Errorf("%w: resolve sandbox %q: %v", errRequesterUnavailable, sandboxID, err)
	}
}

func (a *requesterLifecycleAuthorizer) sandboxAllowedByObject(ctx context.Context, sandbox osbclient.Sandbox, tenants map[string]struct{}) (bool, error) {
	logicalTenant, err := a.sandboxLogicalTenantForSandbox(ctx, sandbox)
	switch {
	case err == nil:
		return tenantAllowed(tenants, logicalTenant), nil
	case errors.Is(err, errSandboxAssignmentMissing), errors.Is(err, errSandboxAssignmentAmbiguous), errors.Is(err, errSandboxLogicalTenantEmpty):
		return false, nil
	default:
		return false, fmt.Errorf("%w: resolve sandbox %q: %v", errRequesterUnavailable, sandbox.ID, err)
	}
}

func (a *requesterLifecycleAuthorizer) snapshotAllowed(ctx context.Context, snapshot osbclient.Snapshot, tenants map[string]struct{}) (bool, error) {
	if strings.TrimSpace(snapshot.SandboxID) == "" {
		return false, nil
	}
	return a.sandboxAllowed(ctx, snapshot.SandboxID, tenants)
}

func (a *requesterLifecycleAuthorizer) sandboxLogicalTenant(ctx context.Context, sandboxID string) (string, error) {
	assignmentObject, err := a.assignmentForSandboxID(ctx, sandboxID)
	if err != nil {
		return "", err
	}
	if logicalTenant := strings.TrimSpace(assignmentObject.Spec.LogicalTenant); logicalTenant != "" {
		return logicalTenant, nil
	}
	return a.bundleLogicalTenant(ctx, assignmentObject.Spec.CapabilityBundleRef.Name)
}

func (a *requesterLifecycleAuthorizer) sandboxLogicalTenantForSandbox(ctx context.Context, sandbox osbclient.Sandbox) (string, error) {
	assignmentObject, err := a.assignmentForSandbox(ctx, sandbox)
	if err != nil {
		return "", err
	}
	if logicalTenant := strings.TrimSpace(assignmentObject.Spec.LogicalTenant); logicalTenant != "" {
		return logicalTenant, nil
	}
	return a.bundleLogicalTenant(ctx, assignmentObject.Spec.CapabilityBundleRef.Name)
}

func (a *requesterLifecycleAuthorizer) assignmentForSandbox(ctx context.Context, sandbox osbclient.Sandbox) (*assignmentv1alpha1.SandboxAssignment, error) {
	if sandbox.Metadata != nil {
		if assignmentName := strings.TrimSpace(sandbox.Metadata[assignment.AssignmentLabel]); assignmentName != "" {
			return a.assignmentByName(ctx, assignmentName)
		}
	}
	return a.assignmentForSandboxID(ctx, sandbox.ID)
}

func (a *requesterLifecycleAuthorizer) assignmentByName(ctx context.Context, assignmentName string) (*assignmentv1alpha1.SandboxAssignment, error) {
	object, err := a.client.Resource(dashboardAssignmentsGVR).Namespace(a.namespace).Get(ctx, assignmentName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errSandboxAssignmentMissing, err)
	}
	if object.GetDeletionTimestamp() != nil {
		return nil, errSandboxAssignmentMissing
	}
	value := &assignmentv1alpha1.SandboxAssignment{}
	if err := fromUnstructured(object, value); err != nil {
		return nil, err
	}
	return value, nil
}

func (a *requesterLifecycleAuthorizer) assignmentForSandboxID(ctx context.Context, sandboxID string) (*assignmentv1alpha1.SandboxAssignment, error) {
	list, err := a.client.Resource(dashboardAssignmentsGVR).Namespace(a.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	var matched *assignmentv1alpha1.SandboxAssignment
	for i := range list.Items {
		assignmentObject := &assignmentv1alpha1.SandboxAssignment{}
		if err := fromUnstructured(&list.Items[i], assignmentObject); err != nil {
			return nil, err
		}
		if assignmentObject.DeletionTimestamp != nil {
			continue
		}
		if assignmentObject.Annotations[assignment.SandboxIDAnnotation] != sandboxID &&
			assignmentObject.Labels[assignment.SandboxIDLabel] != sandboxID {
			continue
		}
		if matched != nil {
			return nil, errSandboxAssignmentAmbiguous
		}
		matched = assignmentObject
	}
	if matched == nil {
		return nil, errSandboxAssignmentMissing
	}
	return matched, nil
}

type authorizedDashboardClient struct {
	base       osbclient.Client
	authorizer *requesterLifecycleAuthorizer
}

func (c *authorizedDashboardClient) ListSandboxes(ctx context.Context) ([]osbclient.Sandbox, error) {
	sandboxes, err := c.base.ListSandboxes(ctx)
	if err != nil {
		return nil, err
	}
	return c.filterSandboxes(ctx, sandboxes)
}

func (c *authorizedDashboardClient) ListSnapshots(ctx context.Context) ([]osbclient.Snapshot, error) {
	snapshots, err := c.base.ListSnapshots(ctx)
	if err != nil {
		return nil, err
	}
	return c.filterSnapshots(ctx, snapshots)
}

func (c *authorizedDashboardClient) GetSnapshot(ctx context.Context, snapshotID string) (osbclient.Snapshot, error) {
	snapshot, err := c.base.GetSnapshot(ctx, snapshotID)
	if err != nil {
		return osbclient.Snapshot{}, err
	}
	tenants, err := c.authorizer.requesterTenants(ctx)
	if err != nil {
		return osbclient.Snapshot{}, err
	}
	allowed, err := c.authorizer.snapshotAllowed(ctx, snapshot, tenants)
	if err != nil {
		return osbclient.Snapshot{}, err
	}
	if !allowed {
		return osbclient.Snapshot{}, fmt.Errorf("%w: requester is not authorized for snapshot %q", errRequesterForbidden, snapshotID)
	}
	return snapshot, nil
}

func (c *authorizedDashboardClient) ListSandboxNodeLoads(ctx context.Context) ([]osbclient.SandboxNodeLoad, error) {
	return c.base.ListSandboxNodeLoads(ctx)
}

func (c *authorizedDashboardClient) ListPodEvents(ctx context.Context, sandboxID string) ([]osbclient.SandboxEvent, error) {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return nil, err
	}
	return c.base.ListPodEvents(ctx, sandboxID)
}

func (c *authorizedDashboardClient) ListRecentSandboxEvents(ctx context.Context, sandboxes []osbclient.Sandbox) ([]osbclient.SandboxEvent, error) {
	filtered, err := c.filterSandboxes(ctx, sandboxes)
	if err != nil {
		return nil, err
	}
	return c.base.ListRecentSandboxEvents(ctx, filtered)
}

// CreateSandbox relies on the outer HTTP middleware because the embedded
// dashboard performs lifecycle creation on an app-scoped background context
// that does not retain the signed-in principal identity.
func (c *authorizedDashboardClient) CreateSandbox(ctx context.Context, request osbclient.CreateSandboxRequest) (osbclient.Sandbox, error) {
	return c.base.CreateSandbox(ctx, request)
}

func (c *authorizedDashboardClient) DeleteSandbox(ctx context.Context, sandbox osbclient.Sandbox) error {
	if err := c.authorizer.authorizeSandbox(ctx, sandbox.ID); err != nil {
		return err
	}
	return c.base.DeleteSandbox(ctx, sandbox)
}

func (c *authorizedDashboardClient) PauseSandbox(ctx context.Context, sandboxID string) error {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return err
	}
	return c.base.PauseSandbox(ctx, sandboxID)
}

func (c *authorizedDashboardClient) ResumeSandbox(ctx context.Context, sandboxID string) error {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return err
	}
	return c.base.ResumeSandbox(ctx, sandboxID)
}

func (c *authorizedDashboardClient) CreateSnapshot(ctx context.Context, sandboxID, name string) (osbclient.Snapshot, error) {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return osbclient.Snapshot{}, err
	}
	return c.base.CreateSnapshot(ctx, sandboxID, name)
}

func (c *authorizedDashboardClient) DeleteSnapshot(ctx context.Context, snapshotID string) error {
	snapshot, err := c.GetSnapshot(ctx, snapshotID)
	if err != nil {
		return err
	}
	return c.base.DeleteSnapshot(ctx, snapshot.ID)
}

func (c *authorizedDashboardClient) OpenPTY(ctx context.Context, sandboxID string) (*websocket.Conn, error) {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return nil, err
	}
	return c.base.OpenPTY(ctx, sandboxID)
}

func (c *authorizedDashboardClient) RunCommand(ctx context.Context, sandboxID, command string) (osbclient.CommandResult, error) {
	if err := c.authorizer.authorizeSandbox(ctx, sandboxID); err != nil {
		return osbclient.CommandResult{}, err
	}
	return c.base.RunCommand(ctx, sandboxID, command)
}

func (c *authorizedDashboardClient) Close() error {
	return c.base.Close()
}

func (c *authorizedDashboardClient) filterSandboxes(ctx context.Context, sandboxes []osbclient.Sandbox) ([]osbclient.Sandbox, error) {
	tenants, err := c.authorizer.requesterTenants(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]osbclient.Sandbox, 0, len(sandboxes))
	for _, sandbox := range sandboxes {
		allowed, allowErr := c.authorizer.sandboxAllowedByObject(ctx, sandbox, tenants)
		if allowErr != nil {
			return nil, allowErr
		}
		if allowed {
			filtered = append(filtered, sandbox)
		}
	}
	return filtered, nil
}

func (c *authorizedDashboardClient) filterSnapshots(ctx context.Context, snapshots []osbclient.Snapshot) ([]osbclient.Snapshot, error) {
	tenants, err := c.authorizer.requesterTenants(ctx)
	if err != nil {
		return nil, err
	}
	filtered := make([]osbclient.Snapshot, 0, len(snapshots))
	for _, snapshot := range snapshots {
		allowed, allowErr := c.authorizer.snapshotAllowed(ctx, snapshot, tenants)
		if allowErr != nil {
			return nil, allowErr
		}
		if allowed {
			filtered = append(filtered, snapshot)
		}
	}
	return filtered, nil
}

func nestedString(object map[string]any, fields ...string) (string, bool, error) {
	current := any(object)
	for _, field := range fields {
		mapping, ok := current.(map[string]any)
		if !ok {
			return "", false, nil
		}
		current, ok = mapping[field]
		if !ok {
			return "", false, nil
		}
	}
	value, ok := current.(string)
	return value, ok, nil
}
