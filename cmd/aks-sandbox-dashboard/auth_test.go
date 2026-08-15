package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeTokenValidator struct {
	identity authenticatedIdentity
	token    string
}

func (f *fakeTokenValidator) Validate(_ context.Context, token string) (authenticatedIdentity, error) {
	f.token = token
	return f.identity, nil
}

func TestDashboardAuthLoginAndSession(t *testing.T) {
	t.Parallel()
	now := time.Now().UTC()
	validator := &fakeTokenValidator{identity: authenticatedIdentity{
		TenantID:  "tenant",
		ObjectID:  "object",
		Name:      "User",
		Scopes:    []string{"access_as_user"},
		ExpiresAt: now.Add(time.Hour),
	}}
	cfg := config{
		basePath: "/dashboard", sessionLifetime: 30 * time.Minute, cookieSecure: false,
		tenantID: "tenant", clientID: "client", scope: "api://client/access_as_user",
		redirectURI: "https://dashboard.example/dashboard/auth/redirect/",
	}
	auth := newDashboardAuth(context.Background(), cfg, validator)
	defer auth.Close()

	inner := http.NewServeMux()
	auth.RegisterRoutes(inner)
	inner.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	root := http.NewServeMux()
	root.Handle("/dashboard/", http.StripPrefix("/dashboard", inner))
	handler := auth.Middleware(root)

	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example/dashboard/", nil)
	request.Header.Set("Accept", "text/html")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/dashboard/login" {
		t.Fatalf("unauthenticated response = %d location=%q", response.Code, response.Header().Get("Location"))
	}

	for _, test := range []struct {
		path    string
		content string
	}{
		{path: "/dashboard/login", content: "Sign in with Microsoft"},
		{path: "/dashboard/auth/login", content: `data-auth-action="start"`},
		{path: "/dashboard/auth/redirect/", content: `data-auth-action="callback"`},
		{path: "/dashboard/auth/pkce.js", content: "code_challenge_method"},
		{path: "/dashboard/auth/config", content: `"clientId":"client"`},
	} {
		response = httptest.NewRecorder()
		request = httptest.NewRequest(http.MethodGet, "https://dashboard.example"+test.path, nil)
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), test.content) {
			t.Fatalf("GET %s response = %d body=%s", test.path, response.Code, response.Body.String())
		}
	}

	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodPost, "https://dashboard.example/dashboard/auth/session", nil)
	request.Header.Set("Authorization", "Bearer access-token")
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("session response = %d body=%s", response.Code, response.Body.String())
	}
	if validator.token != "access-token" {
		t.Fatalf("validated token = %q", validator.token)
	}
	var sessionCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.MaxAge >= 0 {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil || sessionCookie.Value == "" || !sessionCookie.HttpOnly {
		t.Fatalf("session cookie = %+v", sessionCookie)
	}

	response = httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "https://dashboard.example/dashboard/", nil)
	request.AddCookie(sessionCookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authenticated response = %d", response.Code)
	}
}

func TestDashboardAuthRedactsCallbackQueryBeforeLoggingHandler(t *testing.T) {
	t.Parallel()
	auth := &dashboardAuth{basePath: "/dashboard", store: newMemoryAuthStore()}
	handler := auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(r.URL.RawQuery))
		if err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "https://dashboard.example/dashboard/auth/redirect/?code=secret&state=value", nil)
	handler.ServeHTTP(response, request)
	if response.Body.String() != "" {
		t.Fatalf("callback query reached wrapped handler: %q", response.Body.String())
	}
}

func TestMemoryAuthStoreExpiresAndDeletesSessions(t *testing.T) {
	t.Parallel()
	store := newMemoryAuthStore()
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	value, err := store.createSession(dashboardSession{ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := store.getSession(value); !ok {
		t.Fatal("session was not found")
	}
	now = now.Add(2 * time.Minute)
	if _, ok := store.getSession(value); ok {
		t.Fatal("expired session was returned")
	}

	value, err = store.createSession(dashboardSession{ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	store.deleteSession(value)
	if _, ok := store.getSession(value); ok {
		t.Fatal("deleted session was returned")
	}
}

func TestDashboardAuthReturnsUnauthorizedForHTMXAndWebSocket(t *testing.T) {
	t.Parallel()
	auth := &dashboardAuth{basePath: "/dashboard", store: newMemoryAuthStore()}
	handler := auth.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	for _, headers := range []http.Header{
		{"Hx-Request": []string{"true"}},
		{"Upgrade": []string{"websocket"}},
	} {
		response := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "https://dashboard.example/dashboard/private", nil)
		request.Header = headers
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Errorf("headers %v response = %d", headers, response.Code)
		}
	}
}
