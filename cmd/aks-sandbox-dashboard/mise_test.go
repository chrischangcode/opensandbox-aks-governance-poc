package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

func TestMISETokenValidator(t *testing.T) {
	t.Parallel()
	expires := time.Now().Add(time.Hour).Unix()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Errorf("Authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Header.Get("mise-inbound-policies-to-filter") != "dashboard-policy" {
			t.Errorf("policy = %q", r.Header.Get("mise-inbound-policies-to-filter"))
		}
		if r.Header.Get("Original-Uri") != "/dashboard/auth/session" || r.Header.Get("Original-Method") != http.MethodPost {
			t.Errorf("original request = %s %s", r.Header.Get("Original-Method"), r.Header.Get("Original-Uri"))
		}
		w.Header().Set("Subject-Token-Claim-Tid", "tenant")
		w.Header().Set("Subject-Token-Claim-Oid", "object")
		w.Header().Set("Subject-Token-Claim-Preferred_Username", "user@example.com")
		w.Header().Set("Subject-Token-Claim-Scp", "access_as_user other")
		w.Header().Set("Subject-Token-Claim-Roles", `["OpenSandbox.User"]`)
		w.Header().Set("Subject-Token-Encoded-Claim-Exp", base64.StdEncoding.EncodeToString([]byte(strconv.FormatInt(expires, 10))))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	validator := &miseTokenValidator{
		client:        server.Client(),
		endpoint:      server.URL,
		policy:        "dashboard-policy",
		tenantID:      "tenant",
		requiredScope: "access_as_user",
		requiredRole:  "OpenSandbox.User",
	}
	identity, err := validator.Validate(context.Background(), "token")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ObjectID != "object" || identity.Name != "user@example.com" {
		t.Fatalf("identity = %+v", identity)
	}
	if !contains(identity.Roles, "OpenSandbox.User") || !contains(identity.Scopes, "access_as_user") {
		t.Fatalf("identity claims = %+v", identity)
	}
}

func TestMISETokenValidatorRejectsMissingRole(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Subject-Token-Claim-Tid", "tenant")
		w.Header().Set("Subject-Token-Claim-Oid", "object")
		w.Header().Set("Subject-Token-Claim-Scp", "access_as_user")
		w.Header().Set("Subject-Token-Claim-Roles", "OpenSandbox.User")
		w.Header().Set("Subject-Token-Claim-Exp", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	validator := &miseTokenValidator{
		client: server.Client(), endpoint: server.URL, tenantID: "tenant",
		requiredScope: "access_as_user", requiredRole: "OpenSandbox.Admin",
	}
	if _, err := validator.Validate(context.Background(), "token"); err == nil {
		t.Fatal("expected role validation error")
	}
}

func TestMISETokenValidatorRejectsWrongTenant(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Subject-Token-Claim-Tid", "other")
		w.Header().Set("Subject-Token-Claim-Oid", "object")
		w.Header().Set("Subject-Token-Claim-Scp", "access_as_user")
		w.Header().Set("Subject-Token-Claim-Exp", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	validator := &miseTokenValidator{
		client: server.Client(), endpoint: server.URL, tenantID: "tenant", requiredScope: "access_as_user",
	}
	if _, err := validator.Validate(context.Background(), "token"); err == nil {
		t.Fatal("expected tenant validation error")
	}
}
