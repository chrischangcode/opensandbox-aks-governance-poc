package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
	"github.com/google/uuid"
)

const (
	dashboardSandboxTemplateExtension = "aks-sandbox.azure.com/template"
	maxDashboardCreateBodyBytes       = 4 << 20
)

type sandboxTemplateTransport struct {
	base      http.RoundTripper
	template  string
	tokenFile string
}

func (t *sandboxTemplateTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	isCreate := request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/sandboxes")
	if isCreate && request.Header.Get("Idempotency-Key") == "" {
		request.Header.Set("Idempotency-Key", uuid.NewString())
	}
	outbound := request.Clone(request.Context())
	outbound.Header = request.Header.Clone()
	if t.tokenFile != "" {
		token, err := os.ReadFile(t.tokenFile)
		if err != nil {
			return nil, fmt.Errorf("read lifecycle caller token: %w", err)
		}
		value := strings.TrimSpace(string(token))
		if value == "" {
			return nil, fmt.Errorf("lifecycle caller token is empty")
		}
		outbound.Header.Set("Authorization", "Bearer "+value)
	}
	if !isCreate {
		return t.base.RoundTrip(outbound)
	}
	body, err := io.ReadAll(io.LimitReader(request.Body, maxDashboardCreateBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read OpenSandbox create request: %w", err)
	}
	if len(body) > maxDashboardCreateBodyBytes {
		return nil, fmt.Errorf("OpenSandbox create request exceeds %d bytes", maxDashboardCreateBodyBytes)
	}
	var createRequest ossandbox.CreateSandboxRequest
	if err := json.Unmarshal(body, &createRequest); err != nil {
		return nil, fmt.Errorf("decode OpenSandbox create request: %w", err)
	}
	if createRequest.Extensions == nil {
		createRequest.Extensions = map[string]string{}
	}
	createRequest.Extensions = map[string]string{
		dashboardSandboxTemplateExtension: t.template,
	}
	body, err = json.Marshal(createRequest)
	if err != nil {
		return nil, fmt.Errorf("encode OpenSandbox create request: %w", err)
	}
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.ContentLength = int64(len(body))
	outbound.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return t.base.RoundTrip(outbound)
}
