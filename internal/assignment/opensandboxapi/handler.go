// Package opensandboxapi implements an assignment-aware OpenSandbox lifecycle facade.
package opensandboxapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// CapabilityProfileExtension reports the capability selected by the trusted
	// template resolver. Caller-provided values are ignored.
	CapabilityProfileExtension = "aks-sandbox.azure.com/capabilityProfile"
	// SandboxTemplateExtension selects an administrator-owned immutable sandbox
	// template. The lifecycle service, not the caller, resolves the workload shape.
	SandboxTemplateExtension = "aks-sandbox.azure.com/template"
	// SandboxTemplateRevisionExtension reports the resolved immutable template hash.
	SandboxTemplateRevisionExtension = "aks-sandbox.azure.com/templateRevision"
	// assignmentUIDExtension is injected by the facade and propagated by
	// OpenSandbox to OpenSandboxAssignmentUIDAnnotation.
	assignmentUIDExtension = "opensandbox.extensions.aks-sandbox-assignment-uid"
	defaultPrefix          = "/opensandbox"
	maxCreateBodyBytes     = 4 << 20
)

// Config configures the OpenSandbox facade.
type Config struct {
	Prefix              string
	Upstream            *url.URL
	APIKey              string
	Namespace           string
	TransitionTimeout   time.Duration
	Admission           Admission
	Templates           TemplateResolver
	CallerAuthorizer    CallerAuthorizer
	RequireIdempotency  bool
	PendingOperationTTL time.Duration
}

// Admission enforces tenant budgets before an assignment or upstream sandbox is created.
type Admission interface {
	AuthorizeCreate(context.Context, string, *ossandbox.CreateSandboxRequest) (func(), error)
}

// CallerAuthorizer enforces the authenticated caller's logical tenant scope.
type CallerAuthorizer interface {
	AuthorizeTenant(context.Context, string) error
}

// createSandboxResponse fills the SDK's missing asynchronous create response
// type while reusing its status and platform wire types.
//
// Compatibility note: this shape mirrors the OpenSandbox API used by the pinned
// Go SDK. Update it and the wire-compatibility tests whenever that SDK changes.
type createSandboxResponse struct {
	ID         string                  `json:"id"`
	Status     ossandbox.SandboxStatus `json:"status"`
	Metadata   map[string]string       `json:"metadata,omitempty"`
	Extensions map[string]string       `json:"extensions,omitempty"`
	Platform   *ossandbox.PlatformSpec `json:"platform,omitempty"`
	ExpiresAt  *time.Time              `json:"expiresAt,omitempty"`
	CreatedAt  time.Time               `json:"createdAt"`
	Entrypoint []string                `json:"entrypoint,omitempty"`
}

type sandboxResponse struct {
	ID         string                  `json:"id"`
	Image      *ossandbox.ImageSpec    `json:"image,omitempty"`
	SnapshotID string                  `json:"snapshotId,omitempty"`
	Status     ossandbox.SandboxStatus `json:"status"`
	Metadata   map[string]string       `json:"metadata,omitempty"`
	Extensions map[string]string       `json:"extensions,omitempty"`
	Entrypoint []string                `json:"entrypoint,omitempty"`
	ExpiresAt  *time.Time              `json:"expiresAt,omitempty"`
	CreatedAt  time.Time               `json:"createdAt"`
	Platform   *ossandbox.PlatformSpec `json:"platform,omitempty"`
}

type listSandboxesResponse struct {
	Items      []sandboxResponse        `json:"items"`
	Pagination ossandbox.PaginationInfo `json:"pagination"`
}

// Handler selectively intercepts mutating lifecycle operations and proxies all
// other OpenSandbox operations unchanged.
type Handler struct {
	store      assignment.Store
	config     Config
	proxy      *httputil.ReverseProxy
	httpClient *http.Client
	logger     *slog.Logger
	createMu   sync.Mutex
}

// NewHandler creates an OpenSandbox-compatible facade.
func NewHandler(store assignment.Store, config Config, logger *slog.Logger) http.Handler {
	if store == nil || config.Upstream == nil || config.Templates == nil {
		panic("opensandbox API: store, upstream, and template resolver are required")
	}
	if config.Prefix == "" {
		config.Prefix = defaultPrefix
	}
	config.Prefix = strings.TrimSuffix(config.Prefix, "/")
	if config.Namespace == "" {
		panic("opensandbox API: namespace is required")
	}
	if config.TransitionTimeout <= 0 {
		config.TransitionTimeout = 30 * time.Second
	}
	if config.PendingOperationTTL <= 0 {
		config.PendingOperationTTL = 10 * time.Minute
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			outboundPath := strings.TrimPrefix(proxyRequest.In.URL.Path, config.Prefix)
			if outboundPath == "" {
				outboundPath = "/"
			}
			proxyRequest.SetURL(config.Upstream)
			proxyRequest.Out.URL.Path = joinURLPath(config.Upstream.Path, outboundPath)
			proxyRequest.Out.URL.RawPath = ""
			proxyRequest.Out.Host = config.Upstream.Host
			proxyRequest.SetXForwarded()
			proxyRequest.Out.Header.Del("Authorization")
			setUpstreamAPIKey(proxyRequest.Out.Header, config.APIKey)
		},
		ModifyResponse: sanitizeProxiedResponse,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, err error) {
			logger.Error("proxy OpenSandbox request", "error", err)
			writeError(w, http.StatusBadGateway, "OpenSandbox is unavailable")
		},
	}

	return &Handler{
		store:      store,
		config:     config,
		proxy:      proxy,
		httpClient: &http.Client{Timeout: 11 * time.Minute},
		logger:     logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	path, ok := strings.CutPrefix(request.URL.Path, h.config.Prefix)
	if !ok || (path != "/sandboxes" && !strings.HasPrefix(path, "/sandboxes/")) {
		writeError(w, http.StatusNotFound, "not found")
		return
	}

	if request.Method == http.MethodPost && path == "/sandboxes" {
		h.create(w, request)
		return
	}
	id, action, matched := sandboxOperation(path)
	if matched {
		switch {
		case request.Method == http.MethodDelete && action == "":
			h.delete(w, request, id)
			return
		case request.Method == http.MethodPost && action == "pause":
			h.pause(w, request, id)
			return
		case request.Method == http.MethodPost && action == "resume":
			h.resume(w, request, id)
			return
		case request.Method == http.MethodPatch && action == "metadata":
			h.patchMetadata(w, request, id)
			return
		}
	}
	if h.config.CallerAuthorizer != nil {
		if path == "/sandboxes" {
			writeError(w, http.StatusForbidden, "tenant-scoped sandbox listing is unavailable")
			return
		}
		if matched {
			if _, ok := h.authorizedAssignment(w, request, id); !ok {
				return
			}
		}
	}
	h.proxy.ServeHTTP(w, request)
}

func (h *Handler) create(w http.ResponseWriter, request *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, maxCreateBodyBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid OpenSandbox create request")
		return
	}
	var value ossandbox.CreateSandboxRequest
	if err := json.Unmarshal(body, &value); err != nil {
		writeError(w, http.StatusBadRequest, "invalid OpenSandbox create request")
		return
	}
	if value.Extensions == nil {
		value.Extensions = map[string]string{}
	}
	templateName := strings.TrimSpace(value.Extensions[SandboxTemplateExtension])
	if templateName == "" {
		writeError(w, http.StatusForbidden, "sandbox template is required")
		return
	}
	resolved, err := h.config.Templates.Resolve(request.Context(), templateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, "sandbox template is unavailable")
		} else {
			h.logger.WarnContext(request.Context(), "sandbox template rejected", "template", templateName, "error", err)
			writeError(w, http.StatusForbidden, "sandbox template is unavailable")
		}
		return
	}
	if h.config.CallerAuthorizer != nil {
		if err := h.config.CallerAuthorizer.AuthorizeTenant(request.Context(), resolved.LogicalTenant); err != nil {
			writeError(w, http.StatusForbidden, "caller is not authorized for the sandbox template")
			return
		}
	}
	bundleName := resolved.CapabilityBundleName
	value.Image = &ossandbox.ImageSpec{URI: resolved.Image}
	value.SnapshotID = ""
	value.Timeout = &resolved.TimeoutSeconds
	value.ResourceLimits = ossandbox.ResourceLimits{"cpu": resolved.CPU, "memory": resolved.Memory}
	value.ResourceRequests = nil
	value.Entrypoint = append([]string(nil), resolved.Entrypoint...)
	value.NetworkPolicy = nil
	value.CredentialProxy = nil
	value.Volumes = nil
	value.Platform = nil
	value.Extensions = map[string]string{}
	idempotencyKey := strings.TrimSpace(request.Header.Get("Idempotency-Key"))
	if h.config.RequireIdempotency && !validIdempotencyKey(idempotencyKey) {
		writeError(w, http.StatusBadRequest, "a valid Idempotency-Key header is required")
		return
	}
	requestHash, err := createRequestHash(value, resolved)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash OpenSandbox create request")
		return
	}
	assignmentName := ""
	if idempotencyKey != "" {
		assignmentName = idempotentAssignmentName(resolved.LogicalTenant, idempotencyKey)
	}
	h.createMu.Lock()
	releaseAdmission := func() {}
	if h.config.Admission != nil {
		release, err := h.config.Admission.AuthorizeCreate(request.Context(), bundleName, &value)
		if err != nil {
			h.createMu.Unlock()
			h.logger.WarnContext(request.Context(), "sandbox creation rejected by tenant policy", "bundle", bundleName, "error", err)
			writeError(w, http.StatusForbidden, "sandbox creation does not satisfy the tenant policy")
			return
		}
		releaseAdmission = release
	}

	// The deterministic assignment is the durable operation record. The
	// controller can recover its sandbox mapping from the upstream workload.
	created, err := h.store.Create(request.Context(), assignment.CreateRequest{
		Namespace:            h.config.Namespace,
		Name:                 assignmentName,
		GenerateName:         "assignment-",
		TemplateName:         resolved.Name,
		TemplateUID:          resolved.UID,
		TemplateRevision:     resolved.Revision,
		LogicalTenant:        resolved.LogicalTenant,
		CapabilityBundleName: bundleName,
		IdempotencyKey:       idempotencyKey,
		RequestHash:          requestHash,
	})
	releaseAdmission()
	h.createMu.Unlock()
	if err != nil {
		if errors.Is(err, assignment.ErrIdempotencyConflict) {
			writeError(w, http.StatusConflict, "Idempotency-Key was reused with different sandbox intent")
			return
		}
		h.writeStoreError(w, err)
		return
	}
	if created.Existing {
		if created.SandboxID == "" {
			if time.Since(created.CreatedAt) >= h.config.PendingOperationTTL {
				latest, getErr := h.store.Get(request.Context(), h.config.Namespace, created.Name)
				if getErr != nil {
					h.writeStoreError(w, getErr)
					return
				}
				if latest.SandboxID != "" {
					created = latest
				} else {
					if err := h.store.Delete(request.Context(), h.config.Namespace, created.Name); err != nil {
						h.writeStoreError(w, err)
						return
					}
					w.Header().Set("Retry-After", "1")
					writeError(w, http.StatusServiceUnavailable, "stale sandbox create operation was expired; retry the request")
					return
				}
			}
		}
		if created.SandboxID == "" {
			w.Header().Set("Retry-After", "2")
			writeError(w, http.StatusConflict, "sandbox create operation is still in progress")
			return
		}
		replayBody, err := json.Marshal(createSandboxResponse{
			ID: created.SandboxID, Status: ossandbox.SandboxStatus{State: ossandbox.StatePending},
			CreatedAt: created.CreatedAt,
			Extensions: map[string]string{
				CapabilityProfileExtension:       resolved.CapabilityBundleName,
				SandboxTemplateExtension:         resolved.Name,
				SandboxTemplateRevisionExtension: resolved.Revision,
			},
		})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "encode idempotent sandbox response")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(replayBody)
		return
	}

	if value.Metadata == nil {
		value.Metadata = map[string]string{}
	}
	delete(value.Metadata, assignment.AssignmentLabel)
	value.Metadata[assignment.AssignmentLabel] = created.Name
	value.Metadata[SandboxTemplateExtension] = resolved.Name
	value.Extensions[assignmentUIDExtension] = created.UID
	forwardBody, err := json.Marshal(value)
	if err != nil {
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
		writeError(w, http.StatusInternalServerError, "encode OpenSandbox request")
		return
	}

	response, responseBody, err := h.doUpstream(request.Context(), http.MethodPost, "/sandboxes", request.Header, forwardBody)
	if err != nil {
		writeError(w, http.StatusBadGateway, "OpenSandbox is unavailable")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
		copyResponse(w, response, responseBody)
		return
	}
	var createdSandbox createSandboxResponse
	if err := json.Unmarshal(responseBody, &createdSandbox); err != nil || createdSandbox.ID == "" || createdSandbox.CreatedAt.IsZero() {
		writeError(w, http.StatusBadGateway, "OpenSandbox returned an invalid create response")
		return
	}
	if err := h.store.SetSandboxID(request.Context(), h.config.Namespace, created.Name, createdSandbox.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "record OpenSandbox assignment")
		return
	}
	delete(createdSandbox.Metadata, assignment.AssignmentLabel)
	delete(createdSandbox.Extensions, assignmentUIDExtension)
	if createdSandbox.Extensions == nil {
		createdSandbox.Extensions = map[string]string{}
	}
	createdSandbox.Extensions[CapabilityProfileExtension] = resolved.CapabilityBundleName
	createdSandbox.Extensions[SandboxTemplateExtension] = resolved.Name
	createdSandbox.Extensions[SandboxTemplateRevisionExtension] = resolved.Revision
	responseBody, err = json.Marshal(createdSandbox)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode OpenSandbox response")
		return
	}
	copyResponse(w, response, responseBody)
}

func validIdempotencyKey(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func createRequestHash(value ossandbox.CreateSandboxRequest, template ResolvedTemplate) (string, error) {
	payload, err := json.Marshal(struct {
		Request          ossandbox.CreateSandboxRequest `json:"request"`
		TemplateName     string                         `json:"templateName"`
		TemplateUID      string                         `json:"templateUid"`
		TemplateRevision string                         `json:"templateRevision"`
	}{
		Request: value, TemplateName: template.Name, TemplateUID: template.UID, TemplateRevision: template.Revision,
	})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return fmt.Sprintf("sha256:%x", sum[:]), nil
}

func idempotentAssignmentName(logicalTenant, key string) string {
	sum := sha256.Sum256([]byte(logicalTenant + "\x00" + key))
	return fmt.Sprintf("operation-%x", sum[:16])
}

func (h *Handler) pause(w http.ResponseWriter, request *http.Request, sandboxID string) {
	value, err := h.store.GetBySandboxID(request.Context(), h.config.Namespace, sandboxID)
	if apierrors.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "sandbox assignment is unavailable")
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !h.authorizeAssignment(w, request, value) {
		return
	}
	if err := h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, true, ""); err != nil {
		h.writeStoreError(w, err)
		return
	}
	if err := h.waitReady(request.Context(), value.Name, false); err != nil {
		_ = h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, false, "")
		writeError(w, http.StatusServiceUnavailable, "assignment did not become paused")
		return
	}
	response, body, err := h.doUpstream(request.Context(), http.MethodPost, "/sandboxes/"+url.PathEscape(sandboxID)+"/pause", request.Header, nil)
	if err != nil || response.StatusCode < 200 || response.StatusCode >= 300 {
		if err != nil {
			writeError(w, http.StatusBadGateway, "OpenSandbox is unavailable")
		} else {
			copyResponse(w, response, body)
		}
		return
	}
	copyResponse(w, response, body)
}

func (h *Handler) resume(w http.ResponseWriter, request *http.Request, sandboxID string) {
	value, err := h.store.GetBySandboxID(request.Context(), h.config.Namespace, sandboxID)
	if apierrors.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "sandbox assignment is unavailable")
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !h.authorizeAssignment(w, request, value) {
		return
	}
	oldPodUID := ""
	if value.PodRef != nil {
		oldPodUID = value.PodRef.UID
	}
	if err := h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, false, oldPodUID); err != nil {
		h.writeStoreError(w, err)
		return
	}
	response, body, err := h.doUpstream(request.Context(), http.MethodPost, "/sandboxes/"+url.PathEscape(sandboxID)+"/resume", request.Header, nil)
	if err != nil {
		_ = h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, true, "")
		writeError(w, http.StatusBadGateway, "OpenSandbox is unavailable")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, true, "")
		copyResponse(w, response, body)
		return
	}
	copyResponse(w, response, body)
}

func (h *Handler) delete(w http.ResponseWriter, request *http.Request, sandboxID string) {
	value, err := h.store.GetBySandboxID(request.Context(), h.config.Namespace, sandboxID)
	if apierrors.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "sandbox assignment is unavailable")
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if !h.authorizeAssignment(w, request, value) {
		return
	}
	if err := h.store.Delete(request.Context(), h.config.Namespace, value.Name); err != nil && !apierrors.IsNotFound(err) {
		h.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) patchMetadata(w http.ResponseWriter, request *http.Request, sandboxID string) {
	if h.config.CallerAuthorizer != nil {
		if _, ok := h.authorizedAssignment(w, request, sandboxID); !ok {
			return
		}
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, request.Body, 1<<20))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata patch")
		return
	}
	var patch ossandbox.MetadataPatch
	if err := json.Unmarshal(body, &patch); err != nil {
		writeError(w, http.StatusBadRequest, "invalid metadata patch")
		return
	}
	for _, reservedKey := range []string{assignment.AssignmentLabel, SandboxTemplateExtension} {
		if _, reserved := patch[reservedKey]; reserved {
			writeError(w, http.StatusForbidden, "governance metadata is reserved")
			return
		}
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	h.proxy.ServeHTTP(w, request)
}

func (h *Handler) authorizedAssignment(w http.ResponseWriter, request *http.Request, sandboxID string) (*assignment.Assignment, bool) {
	value, err := h.store.GetBySandboxID(request.Context(), h.config.Namespace, sandboxID)
	if apierrors.IsNotFound(err) {
		writeError(w, http.StatusNotFound, "sandbox assignment is unavailable")
		return nil, false
	}
	if err != nil {
		h.writeStoreError(w, err)
		return nil, false
	}
	if !h.authorizeAssignment(w, request, value) {
		return nil, false
	}
	return value, true
}

func (h *Handler) authorizeAssignment(w http.ResponseWriter, request *http.Request, value *assignment.Assignment) bool {
	if h.config.CallerAuthorizer == nil {
		return true
	}
	if value.LogicalTenant == "" || h.config.CallerAuthorizer.AuthorizeTenant(request.Context(), value.LogicalTenant) != nil {
		writeError(w, http.StatusForbidden, "caller is not authorized for the sandbox")
		return false
	}
	return true
}

func (h *Handler) waitReady(ctx context.Context, name string, wanted bool) error {
	ctx, cancel := context.WithTimeout(ctx, h.config.TransitionTimeout)
	defer cancel()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		value, err := h.store.Get(ctx, h.config.Namespace, name)
		if err != nil {
			return err
		}
		if value.Ready == wanted {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (h *Handler) doUpstream(ctx context.Context, method, path string, headers http.Header, body []byte) (*http.Response, []byte, error) {
	target := h.config.Upstream.ResolveReference(&url.URL{Path: path})
	request, err := http.NewRequestWithContext(ctx, method, target.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	for name, values := range headers {
		if strings.EqualFold(name, "Authorization") {
			continue
		}
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}
	setUpstreamAPIKey(request.Header, h.config.APIKey)
	response, err := h.httpClient.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	return response, responseBody, err
}

func (h *Handler) writeStoreError(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	if apierrors.IsNotFound(err) {
		status = http.StatusNotFound
	} else if apierrors.IsAlreadyExists(err) {
		status = http.StatusConflict
	}
	h.logger.Error("OpenSandbox assignment operation", "error", err)
	writeError(w, status, http.StatusText(status))
}

func sandboxOperation(path string) (id, action string, ok bool) {
	parts := strings.Split(strings.TrimPrefix(path, "/sandboxes/"), "/")
	if len(parts) < 1 || parts[0] == "" || len(parts) > 2 {
		return "", "", false
	}
	decoded, err := url.PathUnescape(parts[0])
	if err != nil || decoded == "" || strings.Contains(decoded, "/") {
		return "", "", false
	}
	if len(parts) == 2 {
		action = parts[1]
	}
	return decoded, action, true
}

func sanitizeProxiedResponse(response *http.Response) error {
	if response.StatusCode < 200 || response.StatusCode >= 300 || response.Request == nil {
		return nil
	}
	path := response.Request.URL.Path
	method := response.Request.Method
	var decoded any
	switch {
	case method == http.MethodGet && path == "/sandboxes":
		decoded = &listSandboxesResponse{}
	case method == http.MethodGet && strings.HasPrefix(path, "/sandboxes/") && strings.Count(strings.TrimPrefix(path, "/sandboxes/"), "/") == 0:
		decoded = &sandboxResponse{}
	case method == http.MethodPatch && strings.HasSuffix(path, "/metadata"):
		decoded = &sandboxResponse{}
	default:
		return nil
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, decoded); err != nil {
		return err
	}
	switch value := decoded.(type) {
	case *sandboxResponse:
		sanitizeSandbox(value)
	case *listSandboxesResponse:
		for i := range value.Items {
			sanitizeSandbox(&value.Items[i])
		}
	}
	body, err = json.Marshal(decoded)
	if err != nil {
		return err
	}
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Header.Set("Content-Length", strconv.Itoa(len(body)))
	return nil
}

func sanitizeSandbox(value *sandboxResponse) {
	delete(value.Metadata, assignment.AssignmentLabel)
	delete(value.Extensions, assignmentUIDExtension)
}

func joinURLPath(base, requestPath string) string {
	if base == "" || base == "/" {
		return requestPath
	}
	return strings.TrimSuffix(base, "/") + "/" + strings.TrimPrefix(requestPath, "/")
}

func setUpstreamAPIKey(headers http.Header, apiKey string) {
	headers.Del("OPEN-SANDBOX-API-KEY")
	if apiKey != "" {
		headers.Set("OPEN-SANDBOX-API-KEY", apiKey)
	}
}

func copyResponse(w http.ResponseWriter, response *http.Response, body []byte) {
	for name, values := range response.Header {
		if strings.EqualFold(name, "Content-Length") || strings.EqualFold(name, "Transfer-Encoding") || strings.EqualFold(name, "Connection") {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = w.Write(body)
}

func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"detail": map[string]string{"code": http.StatusText(status), "message": message},
	})
}
