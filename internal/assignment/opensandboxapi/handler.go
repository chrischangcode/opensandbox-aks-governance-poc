// Package opensandboxapi implements an assignment-aware OpenSandbox lifecycle facade.
package opensandboxapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const (
	// CapabilityProfileExtension selects an installed CapabilityBundle by name.
	CapabilityProfileExtension = "aks-sandbox.azure.com/capabilityProfile"
	// assignmentUIDExtension is injected by the facade and propagated by
	// OpenSandbox to OpenSandboxAssignmentUIDAnnotation.
	assignmentUIDExtension = "opensandbox.extensions.aks-sandbox-assignment-uid"
	defaultPrefix          = "/opensandbox"
	maxCreateBodyBytes     = 4 << 20
)

// Config configures the OpenSandbox facade.
type Config struct {
	Prefix            string
	Upstream          *url.URL
	APIKey            string
	Namespace         string
	TransitionTimeout time.Duration
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
}

// NewHandler creates an OpenSandbox-compatible facade.
func NewHandler(store assignment.Store, config Config, logger *slog.Logger) http.Handler {
	if store == nil || config.Upstream == nil {
		panic("opensandbox API: store and upstream are required")
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
			h.patchMetadata(w, request)
			return
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
	profile := strings.TrimSpace(value.Extensions[CapabilityProfileExtension])
	if profile == "" {
		writeError(w, http.StatusForbidden, "capability profile is required")
		return
	}
	bundleName := profile
	delete(value.Extensions, CapabilityProfileExtension)
	delete(value.Extensions, assignmentUIDExtension)

	// TODO: persist a create-operation/idempotency record. A process crash after
	// this create and before the upstream response can leave a pending assignment;
	// synchronous errors below are compensated, but crash recovery needs durable
	// operation intent or conservative stale-assignment garbage collection.
	created, err := h.store.Create(request.Context(), assignment.CreateRequest{
		Namespace:            h.config.Namespace,
		GenerateName:         "assignment-",
		CapabilityBundleName: bundleName,
	})
	if err != nil {
		h.writeStoreError(w, err)
		return
	}

	if value.Metadata == nil {
		value.Metadata = map[string]string{}
	}
	delete(value.Metadata, assignment.AssignmentLabel)
	value.Metadata[assignment.AssignmentLabel] = created.Name
	value.Extensions[assignmentUIDExtension] = created.UID
	forwardBody, err := json.Marshal(value)
	if err != nil {
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
		writeError(w, http.StatusInternalServerError, "encode OpenSandbox request")
		return
	}

	response, responseBody, err := h.doUpstream(request.Context(), http.MethodPost, "/sandboxes", request.Header, forwardBody)
	if err != nil {
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
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
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
		writeError(w, http.StatusBadGateway, "OpenSandbox returned an invalid create response")
		return
	}
	if err := h.store.SetSandboxID(request.Context(), h.config.Namespace, created.Name, createdSandbox.ID); err != nil {
		_ = h.store.Delete(request.Context(), h.config.Namespace, created.Name)
		_, _, _ = h.doUpstream(request.Context(), http.MethodDelete, "/sandboxes/"+url.PathEscape(createdSandbox.ID), nil, nil)
		writeError(w, http.StatusInternalServerError, "record OpenSandbox assignment")
		return
	}
	delete(createdSandbox.Metadata, assignment.AssignmentLabel)
	delete(createdSandbox.Extensions, assignmentUIDExtension)
	if createdSandbox.Extensions == nil {
		createdSandbox.Extensions = map[string]string{}
	}
	createdSandbox.Extensions[CapabilityProfileExtension] = profile
	responseBody, err = json.Marshal(createdSandbox)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "encode OpenSandbox response")
		return
	}
	copyResponse(w, response, responseBody)
}

func (h *Handler) pause(w http.ResponseWriter, request *http.Request, sandboxID string) {
	value, err := h.store.GetBySandboxID(request.Context(), h.config.Namespace, sandboxID)
	if apierrors.IsNotFound(err) {
		h.proxy.ServeHTTP(w, request)
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
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
		_ = h.store.SetLifecycleFence(request.Context(), h.config.Namespace, value.Name, false, "")
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
		h.proxy.ServeHTTP(w, request)
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
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
		h.proxy.ServeHTTP(w, request)
		return
	}
	if err != nil {
		h.writeStoreError(w, err)
		return
	}
	if err := h.store.Delete(request.Context(), h.config.Namespace, value.Name); err != nil && !apierrors.IsNotFound(err) {
		h.writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) patchMetadata(w http.ResponseWriter, request *http.Request) {
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
	if _, reserved := patch[assignment.AssignmentLabel]; reserved {
		writeError(w, http.StatusForbidden, "assignment metadata is reserved")
		return
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	request.ContentLength = int64(len(body))
	h.proxy.ServeHTTP(w, request)
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
