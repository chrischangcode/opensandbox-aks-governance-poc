package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
)

const (
	dashboardCapabilityProfileExtension = "aks-sandbox.azure.com/capabilityProfile"
	maxDashboardCreateBodyBytes         = 4 << 20
)

type capabilityProfileTransport struct {
	base    http.RoundTripper
	profile string
}

func (t *capabilityProfileTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.Method != http.MethodPost || !strings.HasSuffix(request.URL.Path, "/sandboxes") {
		return t.base.RoundTrip(request)
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
	createRequest.Extensions[dashboardCapabilityProfileExtension] = t.profile
	body, err = json.Marshal(createRequest)
	if err != nil {
		return nil, fmt.Errorf("encode OpenSandbox create request: %w", err)
	}
	outbound := request.Clone(request.Context())
	outbound.Header = request.Header.Clone()
	outbound.Body = io.NopCloser(bytes.NewReader(body))
	outbound.ContentLength = int64(len(body))
	outbound.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return t.base.RoundTrip(outbound)
}
