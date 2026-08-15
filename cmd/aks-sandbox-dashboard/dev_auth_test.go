package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDevelopmentAuthRequiresLoopback(t *testing.T) {
	_, err := parseConfig([]string{
		"--dev-auth",
		"--listen=0.0.0.0:8080",
		"--redirect-uri=http://127.0.0.1:8080/dashboard/auth/redirect/",
	})
	if err == nil {
		t.Fatal("expected non-loopback development authentication to fail")
	}
}

func TestDevelopmentAuthInjectsAdminIdentity(t *testing.T) {
	cfg, err := parseConfig([]string{
		"--dev-auth",
		"--listen=127.0.0.1:8080",
		"--redirect-uri=http://127.0.0.1:8080/dashboard/auth/redirect/",
	})
	if err != nil {
		t.Fatalf("parseConfig() error = %v", err)
	}
	auth, err := newDevelopmentDashboardAuth(cfg)
	if err != nil {
		t.Fatalf("newDevelopmentDashboardAuth() error = %v", err)
	}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identity, ok := authenticatedIdentityFromContext(r.Context())
		if !ok || identity.Name != "POC Administrator" || !contains(identity.Roles, "OpenSandbox.Admin") {
			t.Fatalf("unexpected identity: %#v", identity)
		}
		if csrf, ok := csrfTokenFromContext(r.Context()); !ok || csrf == "" {
			t.Fatal("missing CSRF token")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/dashboard/admin", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("status = %d", response.Code)
	}
}
