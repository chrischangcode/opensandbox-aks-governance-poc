package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type authenticatedIdentity struct {
	TenantID  string
	ObjectID  string
	Name      string
	Roles     []string
	Scopes    []string
	ExpiresAt time.Time
}

type tokenValidator interface {
	Validate(context.Context, string) (authenticatedIdentity, error)
}

type miseTokenValidator struct {
	client        *http.Client
	endpoint      string
	policy        string
	tenantID      string
	requiredScope string
	requiredRole  string
}

func newMISETokenValidator(cfg config) *miseTokenValidator {
	return &miseTokenValidator{
		client:        &http.Client{Timeout: 10 * time.Second},
		endpoint:      cfg.miseURL,
		policy:        cfg.misePolicy,
		tenantID:      cfg.tenantID,
		requiredScope: cfg.requiredScope,
		requiredRole:  cfg.requiredRole,
	}
}

func (v *miseTokenValidator) Validate(ctx context.Context, token string) (authenticatedIdentity, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.endpoint, nil)
	if err != nil {
		return authenticatedIdentity{}, fmt.Errorf("create MISE request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Original-Uri", "/dashboard/auth/session")
	request.Header.Set("Original-Method", http.MethodPost)
	request.Header.Set("Return-All-Subject-Token-Claims", "1")
	if v.policy != "" {
		request.Header.Set("mise-inbound-policies-to-filter", v.policy)
	}
	response, err := v.client.Do(request)
	if err != nil {
		return authenticatedIdentity{}, fmt.Errorf("validate token with MISE: %w", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			return
		}
	}()
	if response.StatusCode != http.StatusOK {
		description := strings.Join(response.Header.Values("Error-Description"), "; ")
		if description == "" {
			description = http.StatusText(response.StatusCode)
		}
		return authenticatedIdentity{}, fmt.Errorf("MISE rejected token: status=%d description=%s", response.StatusCode, description)
	}

	claims, err := subjectClaims(response.Header)
	if err != nil {
		return authenticatedIdentity{}, err
	}
	identity := authenticatedIdentity{
		TenantID: claims.first("tid"),
		ObjectID: claims.first("oid"),
		Name:     firstNonEmptyClaim(claims, "preferred_username", "upn", "name"),
		Roles:    expandedClaimValues(claims["roles"]),
		Scopes:   expandedClaimValues(claims["scp"]),
	}
	if identity.TenantID != v.tenantID {
		return authenticatedIdentity{}, fmt.Errorf("validated token tenant %q does not match configured tenant", identity.TenantID)
	}
	if identity.ObjectID == "" {
		return authenticatedIdentity{}, fmt.Errorf("validated token does not include oid")
	}
	if v.requiredScope != "" && !contains(identity.Scopes, v.requiredScope) {
		return authenticatedIdentity{}, fmt.Errorf("validated token does not include required scope %q", v.requiredScope)
	}
	if v.requiredRole != "" && !contains(identity.Roles, v.requiredRole) {
		return authenticatedIdentity{}, fmt.Errorf("validated token does not include required role %q", v.requiredRole)
	}
	expiration := claims.first("exp")
	expirationUnix, err := strconv.ParseInt(expiration, 10, 64)
	if err != nil {
		return authenticatedIdentity{}, fmt.Errorf("validated token has invalid exp claim")
	}
	identity.ExpiresAt = time.Unix(expirationUnix, 0)
	if !identity.ExpiresAt.After(time.Now()) {
		return authenticatedIdentity{}, fmt.Errorf("validated token has expired")
	}
	return identity, nil
}

type claimSet map[string][]string

func (c claimSet) first(name string) string {
	values := c[strings.ToLower(name)]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func subjectClaims(headers http.Header) (claimSet, error) {
	claims := claimSet{}
	const plainPrefix = "subject-token-claim-"
	const encodedPrefix = "subject-token-encoded-claim-"
	for name, values := range headers {
		lowerName := strings.ToLower(name)
		switch {
		case strings.HasPrefix(lowerName, plainPrefix):
			claim := strings.TrimPrefix(lowerName, plainPrefix)
			claims[claim] = append(claims[claim], values...)
		case strings.HasPrefix(lowerName, encodedPrefix):
			claim := strings.TrimPrefix(lowerName, encodedPrefix)
			for _, value := range values {
				decoded, err := base64.StdEncoding.DecodeString(value)
				if err != nil {
					return nil, fmt.Errorf("decode MISE claim %s: %w", claim, err)
				}
				claims[claim] = append(claims[claim], string(decoded))
			}
		}
	}
	return claims, nil
}

func firstNonEmptyClaim(claims claimSet, names ...string) string {
	for _, name := range names {
		if value := claims.first(name); value != "" {
			return value
		}
	}
	return ""
}

func expandedClaimValues(values []string) []string {
	var expanded []string
	for _, value := range values {
		var array []string
		if json.Unmarshal([]byte(value), &array) == nil {
			expanded = append(expanded, array...)
			continue
		}
		expanded = append(expanded, strings.FieldsFunc(value, func(r rune) bool {
			return r == ' ' || r == ','
		})...)
	}
	return expanded
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
