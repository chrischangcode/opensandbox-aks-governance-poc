package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
)

type dashboardAuthenticator interface {
	RegisterRoutes(*http.ServeMux)
	Middleware(http.Handler) http.Handler
	Close()
}

type developmentDashboardAuth struct {
	identity authenticatedIdentity
	csrf     string
}

func newDevelopmentDashboardAuth(cfg config) (*developmentDashboardAuth, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, errors.New("generate development CSRF token")
	}
	roles := make([]string, 0)
	for _, role := range strings.Split(cfg.devRoles, ",") {
		if role = strings.TrimSpace(role); role != "" {
			roles = append(roles, role)
		}
	}
	if len(roles) == 0 {
		return nil, errors.New("development roles are empty")
	}
	return &developmentDashboardAuth{
		identity: authenticatedIdentity{
			TenantID: cfg.devTenantID,
			ObjectID: cfg.devObjectID,
			Name:     cfg.devName,
			Roles:    roles,
		},
		csrf: base64.RawURLEncoding.EncodeToString(tokenBytes),
	}, nil
}

func (*developmentDashboardAuth) RegisterRoutes(*http.ServeMux) {}

func (a *developmentDashboardAuth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), identityContextKey{}, a.identity)
		ctx = context.WithValue(ctx, csrfContextKey{}, a.csrf)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (*developmentDashboardAuth) Close() {}
