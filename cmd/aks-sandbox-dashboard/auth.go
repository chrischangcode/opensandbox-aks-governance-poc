package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	sessionCookieName = "osb_dashboard_session"
	cleanupInterval   = 5 * time.Minute
	maxSessions       = 10_000
)

type identityContextKey struct{}
type csrfContextKey struct{}

type dashboardSession struct {
	Identity  authenticatedIdentity
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type memoryAuthStore struct {
	mutex    sync.RWMutex
	sessions map[[sha256.Size]byte]dashboardSession
	now      func() time.Time
}

func newMemoryAuthStore() *memoryAuthStore {
	return &memoryAuthStore{
		sessions: map[[sha256.Size]byte]dashboardSession{},
		now:      time.Now,
	}
}

func (s *memoryAuthStore) createSession(session dashboardSession) (string, error) {
	raw, err := randomValue(32)
	if err != nil {
		return "", err
	}
	s.mutex.Lock()
	defer s.mutex.Unlock()
	s.cleanupLocked()
	if len(s.sessions) >= maxSessions {
		return "", errors.New("dashboard session capacity reached")
	}
	s.sessions[sha256.Sum256([]byte(raw))] = session
	return raw, nil
}

func (s *memoryAuthStore) getSession(raw string) (dashboardSession, bool) {
	if raw == "" {
		return dashboardSession{}, false
	}
	key := sha256.Sum256([]byte(raw))
	s.mutex.RLock()
	session, ok := s.sessions[key]
	s.mutex.RUnlock()
	if !ok || !session.ExpiresAt.After(s.now()) {
		if ok {
			s.deleteSession(raw)
		}
		return dashboardSession{}, false
	}
	return session, true
}

func (s *memoryAuthStore) deleteSession(raw string) {
	if raw == "" {
		return
	}
	s.mutex.Lock()
	delete(s.sessions, sha256.Sum256([]byte(raw)))
	s.mutex.Unlock()
}

func (s *memoryAuthStore) cleanup() {
	s.mutex.Lock()
	s.cleanupLocked()
	s.mutex.Unlock()
}

func (s *memoryAuthStore) cleanupLocked() {
	now := s.now()
	for key, session := range s.sessions {
		if !session.ExpiresAt.After(now) {
			delete(s.sessions, key)
		}
	}
}

type dashboardAuth struct {
	basePath        string
	cookieSecure    bool
	sessionLifetime time.Duration
	tenantID        string
	clientID        string
	scope           string
	redirectURI     string
	validator       tokenValidator
	store           *memoryAuthStore
	now             func() time.Time
	cancel          context.CancelFunc
}

func newDashboardAuth(ctx context.Context, cfg config, validator tokenValidator) *dashboardAuth {
	cleanupContext, cancel := context.WithCancel(ctx)
	auth := &dashboardAuth{
		basePath:        cfg.basePath,
		cookieSecure:    cfg.cookieSecure,
		sessionLifetime: cfg.sessionLifetime,
		tenantID:        cfg.tenantID,
		clientID:        cfg.clientID,
		scope:           cfg.scope,
		redirectURI:     cfg.redirectURI,
		validator:       validator,
		store:           newMemoryAuthStore(),
		now:             time.Now,
		cancel:          cancel,
	}
	go auth.cleanupLoop(cleanupContext)
	return auth
}

func (a *dashboardAuth) Close() {
	a.cancel()
}

func (a *dashboardAuth) cleanupLoop(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			a.store.cleanup()
		}
	}
}

func (a *dashboardAuth) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("GET /auth/login", a.startLoginPage)
	mux.HandleFunc("GET /auth/redirect/", a.callbackPage)
	mux.HandleFunc("GET /auth/config", a.authConfig)
	mux.HandleFunc("GET /auth/pkce.js", a.pkceScript)
	mux.HandleFunc("POST /auth/session", a.createSession)
	mux.HandleFunc("POST /auth/logout", a.logout)
}

func (a *dashboardAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.publicPath(r.URL.Path) {
			if r.URL.Path == a.basePath+"/auth/redirect/" && r.URL.RawQuery != "" {
				requestCopy := r.Clone(r.Context())
				urlCopy := *r.URL
				urlCopy.RawQuery = ""
				requestCopy.URL = &urlCopy
				r = requestCopy
			}
			next.ServeHTTP(w, r)
			return
		}
		cookie, err := r.Cookie(sessionCookieName)
		if err == nil {
			if session, ok := a.store.getSession(cookie.Value); ok {
				ctx := context.WithValue(r.Context(), identityContextKey{}, session.Identity)
				ctx = context.WithValue(ctx, csrfContextKey{}, session.CSRFToken)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		a.clearSessionCookie(w)
		w.Header().Set("Cache-Control", "no-store")
		if shouldRedirectToLogin(r) {
			http.Redirect(w, r, a.basePath+"/login", http.StatusSeeOther)
			return
		}
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}

func (a *dashboardAuth) publicPath(path string) bool {
	for _, public := range []string{
		a.basePath + "/login",
		a.basePath + "/auth/login",
		a.basePath + "/auth/redirect/",
		a.basePath + "/auth/config",
		a.basePath + "/auth/pkce.js",
		a.basePath + "/auth/session",
		a.basePath + "/healthz",
	} {
		if path == public {
			return true
		}
	}
	return strings.HasPrefix(path, a.basePath+"/assets/")
}

func shouldRedirectToLogin(r *http.Request) bool {
	if r.Method != http.MethodGet || strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if strings.EqualFold(r.Header.Get("HX-Request"), "true") {
		return false
	}
	accept := r.Header.Get("Accept")
	return accept == "" || strings.Contains(accept, "text/html")
}

func (a *dashboardAuth) loginPage(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		if _, ok := a.store.getSession(cookie.Value); ok {
			http.Redirect(w, r, a.basePath+"/", http.StatusSeeOther)
			return
		}
	}
	a.setAuthPageHeaders(w)
	if err := loginPageTemplate.Execute(w, map[string]string{
		"LoginURL": a.basePath + "/auth/login",
	}); err != nil {
		http.Error(w, "Failed to render login page", http.StatusInternalServerError)
	}
}

func (a *dashboardAuth) startLoginPage(w http.ResponseWriter, _ *http.Request) {
	a.renderAuthFlowPage(w, "start", "Redirecting to Microsoft sign in…")
}

func (a *dashboardAuth) callbackPage(w http.ResponseWriter, _ *http.Request) {
	a.renderAuthFlowPage(w, "callback", "Completing sign in…")
}

func (a *dashboardAuth) renderAuthFlowPage(w http.ResponseWriter, action string, message string) {
	a.setAuthPageHeaders(w)
	if err := authFlowPageTemplate.Execute(w, map[string]string{
		"Action":    action,
		"Message":   message,
		"Script":    a.basePath + "/auth/pkce.js",
		"ConfigURL": a.basePath + "/auth/config",
	}); err != nil {
		http.Error(w, "Failed to render authentication page", http.StatusInternalServerError)
	}
}

func (a *dashboardAuth) authConfig(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(map[string]string{
		"authorizationEndpoint": "https://login.microsoftonline.com/" + a.tenantID + "/oauth2/v2.0/authorize",
		"tokenEndpoint":         "https://login.microsoftonline.com/" + a.tenantID + "/oauth2/v2.0/token",
		"clientId":              a.clientID,
		"scope":                 "openid profile " + a.scope,
		"redirectUri":           a.redirectURI,
		"basePath":              a.basePath,
	}); err != nil {
		return
	}
}

func (a *dashboardAuth) pkceScript(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if _, err := w.Write([]byte(pkceBrowserScript)); err != nil {
		return
	}
}

func (a *dashboardAuth) createSession(w http.ResponseWriter, r *http.Request) {
	authorization := r.Header.Get("Authorization")
	if len(authorization) < len("Bearer ") || !strings.EqualFold(authorization[:len("Bearer ")], "Bearer ") {
		http.Error(w, "Bearer token is required", http.StatusUnauthorized)
		return
	}
	token := strings.TrimSpace(authorization[len("Bearer "):])
	if token == "" {
		http.Error(w, "Bearer token is required", http.StatusUnauthorized)
		return
	}
	identity, err := a.validator.Validate(r.Context(), token)
	if err != nil {
		slog.WarnContext(r.Context(), "dashboard token validation failed", slog.Any("error", err))
		http.Error(w, "Token validation failed", http.StatusUnauthorized)
		return
	}
	expiresAt := minimumTime(identity.ExpiresAt, a.now().Add(a.sessionLifetime))
	if !expiresAt.After(a.now()) {
		http.Error(w, "Token has expired", http.StatusUnauthorized)
		return
	}
	csrfToken, err := randomValue(32)
	if err != nil {
		slog.ErrorContext(r.Context(), "create dashboard CSRF token", slog.Any("error", err))
		http.Error(w, "Failed to create dashboard session", http.StatusServiceUnavailable)
		return
	}
	sessionID, err := a.store.createSession(dashboardSession{
		Identity:  identity,
		CSRFToken: csrfToken,
		CreatedAt: a.now(),
		ExpiresAt: expiresAt,
	})
	if err != nil {
		slog.ErrorContext(r.Context(), "create dashboard session", slog.Any("error", err))
		http.Error(w, "Failed to create dashboard session", http.StatusServiceUnavailable)
		return
	}

	a.setSessionCookie(w, sessionID, expiresAt)
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func authenticatedIdentityFromContext(ctx context.Context) (authenticatedIdentity, bool) {
	identity, ok := ctx.Value(identityContextKey{}).(authenticatedIdentity)
	return identity, ok && identity.TenantID != "" && identity.ObjectID != ""
}

func csrfTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(csrfContextKey{}).(string)
	return token, ok && token != ""
}

func (a *dashboardAuth) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookieName); err == nil {
		a.store.deleteSession(cookie.Value)
	}
	a.clearSessionCookie(w)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.basePath+"/login", http.StatusSeeOther)
}

func (a *dashboardAuth) setSessionCookie(w http.ResponseWriter, value string, expiresAt time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     a.basePath,
		Expires:  expiresAt,
		MaxAge:   int(expiresAt.Sub(a.now()).Seconds()),
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *dashboardAuth) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Path:     a.basePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   a.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (a *dashboardAuth) setAuthPageHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self' https://login.microsoftonline.com; base-uri 'self'; frame-ancestors 'none'")
}

func randomValue(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func minimumTime(values ...time.Time) time.Time {
	minimum := time.Time{}
	for _, value := range values {
		if value.IsZero() {
			continue
		}
		if minimum.IsZero() || value.Before(minimum) {
			minimum = value
		}
	}
	return minimum
}

var loginPageTemplate = template.Must(template.New("login").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Sign in — OpenSandbox</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #0b1020; color: #eef2ff; }
    main { width: min(28rem, calc(100% - 3rem)); padding: 2.5rem; border: 1px solid #26324d; border-radius: 1rem; background: #111a2e; box-shadow: 0 1.5rem 4rem #0008; }
    h1 { margin: 0 0 .75rem; font-size: 2rem; }
    p { margin: 0 0 1.75rem; color: #b8c3dc; line-height: 1.5; }
    button { width: 100%; border: 0; border-radius: .6rem; padding: .8rem 1rem; color: white; background: #2563eb; font: inherit; font-weight: 650; cursor: pointer; }
    button:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <main>
    <h1>OpenSandbox</h1>
    <p>Sign in with your Microsoft work account to continue to the dashboard.</p>
    <form method="get" action="{{.LoginURL}}">
      <button type="submit">Sign in with Microsoft</button>
    </form>
  </main>
</body>
</html>`))

var authFlowPageTemplate = template.Must(template.New("auth-flow").Parse(`<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Signing in — OpenSandbox</title>
  <style>
    :root { color-scheme: light dark; font-family: ui-sans-serif, system-ui, sans-serif; }
    body { min-height: 100vh; margin: 0; display: grid; place-items: center; background: #0b1020; color: #eef2ff; }
    main { width: min(32rem, calc(100% - 3rem)); padding: 2rem; text-align: center; }
    p { color: #b8c3dc; }
    [role=alert] { color: #fca5a5; }
  </style>
  <script src="{{.Script}}" defer></script>
</head>
<body data-auth-action="{{.Action}}" data-auth-config="{{.ConfigURL}}">
  <main>
    <h1>OpenSandbox</h1>
    <p id="auth-status">{{.Message}}</p>
    <p id="auth-error" role="alert"></p>
  </main>
</body>
</html>`))

const pkceBrowserScript = `(() => {
  "use strict";
  const action = document.body.dataset.authAction;
  const status = document.getElementById("auth-status");
  const error = document.getElementById("auth-error");

  function randomValue(length) {
    const bytes = new Uint8Array(length);
    crypto.getRandomValues(bytes);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function challenge(verifier) {
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
    let binary = "";
    for (const byte of new Uint8Array(digest)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  async function config() {
    const response = await fetch(document.body.dataset.authConfig, {cache: "no-store"});
    if (!response.ok) throw new Error("Unable to load authentication configuration.");
    return response.json();
  }

  function fail(message) {
    status.textContent = "Sign in failed.";
    error.textContent = message;
  }

  async function start() {
    const cfg = await config();
    const verifier = randomValue(48);
    const state = randomValue(32);
    sessionStorage.setItem("osb-dashboard-pkce", JSON.stringify({verifier, state, createdAt: Date.now()}));
    const parameters = new URLSearchParams({
      client_id: cfg.clientId,
      response_type: "code",
      redirect_uri: cfg.redirectUri,
      response_mode: "query",
      scope: cfg.scope,
      state,
      code_challenge: await challenge(verifier),
      code_challenge_method: "S256"
    });
    location.replace(cfg.authorizationEndpoint + "?" + parameters.toString());
  }

  async function callback() {
    const cfg = await config();
    const parameters = new URLSearchParams(location.search);
    if (parameters.has("error")) throw new Error(parameters.get("error_description") || parameters.get("error"));
    const savedValue = sessionStorage.getItem("osb-dashboard-pkce");
    sessionStorage.removeItem("osb-dashboard-pkce");
    if (!savedValue) throw new Error("The login transaction is missing or expired.");
    const saved = JSON.parse(savedValue);
    if (Date.now() - saved.createdAt > 5 * 60 * 1000) throw new Error("The login transaction has expired.");
    if (parameters.get("state") !== saved.state) throw new Error("The login state is invalid.");
    const code = parameters.get("code");
    if (!code) throw new Error("The authorization code is missing.");

    const tokenResponse = await fetch(cfg.tokenEndpoint, {
      method: "POST",
      headers: {"Content-Type": "application/x-www-form-urlencoded"},
      body: new URLSearchParams({
        client_id: cfg.clientId,
        grant_type: "authorization_code",
        code,
        redirect_uri: cfg.redirectUri,
        code_verifier: saved.verifier,
        scope: cfg.scope
      })
    });
    const token = await tokenResponse.json();
    if (!tokenResponse.ok || !token.access_token) throw new Error(token.error_description || "Token exchange failed.");

    const sessionResponse = await fetch(cfg.basePath + "/auth/session", {
      method: "POST",
      credentials: "same-origin",
      headers: {
        "Authorization": "Bearer " + token.access_token,
        "X-OSB-CSRF": "1"
      }
    });
    token.access_token = "";
    if (!sessionResponse.ok) throw new Error(await sessionResponse.text() || "Session creation failed.");
    location.replace(cfg.basePath + "/");
  }

  (action === "start" ? start() : callback()).catch(err => fail(err.message || "Unexpected authentication error."));
})();`
