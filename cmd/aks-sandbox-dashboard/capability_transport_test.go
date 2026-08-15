package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	ossandbox "github.com/alibaba/OpenSandbox/sdks/sandbox/go"
)

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func TestCapabilityProfileTransportInjectsCreateExtension(t *testing.T) {
	called := false
	transport := &capabilityProfileTransport{
		profile: "coding-default",
		base: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			called = true
			var value ossandbox.CreateSandboxRequest
			if err := json.NewDecoder(request.Body).Decode(&value); err != nil {
				t.Fatal(err)
			}
			if value.Extensions[dashboardCapabilityProfileExtension] != "coding-default" {
				t.Fatalf("extensions = %#v", value.Extensions)
			}
			return &http.Response{StatusCode: http.StatusAccepted, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}}, nil
		}),
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "http://assignmentd/opensandbox/sandboxes", strings.NewReader(`{
		"image":{"uri":"example/image"},
		"entrypoint":["sleep","infinity"],
		"resourceLimits":{"cpu":"1","memory":"1Gi"}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Fatal("base transport was not called")
	}
}

func TestCapabilityProfileTransportPassesOtherRequestsUnchanged(t *testing.T) {
	original := strings.NewReader("")
	transport := &capabilityProfileTransport{
		profile: "coding-default",
		base: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
			if request.Method != http.MethodGet || request.URL.Path != "/opensandbox/sandboxes/id" {
				t.Fatalf("request = %s %s", request.Method, request.URL.Path)
			}
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(original), Header: http.Header{}}, nil
		}),
	}
	request, _ := http.NewRequest(http.MethodGet, "http://assignmentd/opensandbox/sandboxes/id", nil)
	if _, err := transport.RoundTrip(request); err != nil {
		t.Fatal(err)
	}
}
