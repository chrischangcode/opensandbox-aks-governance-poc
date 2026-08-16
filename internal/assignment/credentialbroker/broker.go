// Package credentialbroker exchanges an authorized, Pod-bound sandbox
// identity for an exact-scope short-lived credential.
package credentialbroker

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/authz"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

const (
	defaultIssuer   = "assignmentd-credential-broker"
	defaultAudience = "sandbox-brokered-upstream"
	maxRequestBytes = 32 << 10
	minimumTTL      = time.Minute
	maximumTTL      = 15 * time.Minute
)

type Config struct {
	SigningKey []byte
	Issuer     string
	Audience   string
}

type GrantClaims struct {
	AssignmentName           string `json:"assignmentName"`
	AssignmentUID            string `json:"assignmentUid"`
	SandboxID                string `json:"sandboxId"`
	PodUID                   string `json:"podUid"`
	CapabilityBundleName     string `json:"capabilityBundleName"`
	CapabilityBundleRevision string `json:"capabilityBundleRevision"`
	TaskID                   string `json:"taskId"`
	Backend                  string `json:"backend"`
	Method                   string `json:"method"`
	Host                     string `json:"host"`
	Path                     string `json:"path"`
	jwt.RegisteredClaims
}

type GrantValidator interface {
	ValidateGrant(context.Context, GrantClaims) error
}

type AuditEvent struct {
	Timestamp time.Time
	Action    string
	Grant     GrantClaims
}

type AuditSink interface {
	Record(context.Context, AuditEvent) error
}

type Broker struct {
	checker   authz.Checker
	validator GrantValidator
	audit     AuditSink
	config    Config
	logger    *slog.Logger
	now       func() time.Time
	mu        sync.Mutex
	revoked   map[string]time.Time
}

type issueRequest struct {
	IdentityToken string `json:"identityToken"`
	SourceAddress string `json:"sourceAddress"`
	Backend       string `json:"backend"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	TaskID        string `json:"taskId"`
	TTLSeconds    int64  `json:"ttlSeconds"`
}

func New(checker authz.Checker, validator GrantValidator, audit AuditSink, config Config, logger *slog.Logger) (*Broker, error) {
	if checker == nil || validator == nil {
		return nil, errors.New("credential broker checker and validator are required")
	}
	if len(config.SigningKey) < 32 {
		return nil, errors.New("credential broker signing key must be at least 32 bytes")
	}
	if config.Issuer == "" {
		config.Issuer = defaultIssuer
	}
	if config.Audience == "" {
		config.Audience = defaultAudience
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Broker{
		checker: checker, validator: validator, audit: audit, config: config,
		logger: logger, now: time.Now, revoked: map[string]time.Time{},
	}, nil
}

func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/broker/v1/credentials":
		b.issue(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/broker/v1/verify":
		b.verify(w, r)
	case r.Method == http.MethodPost && r.URL.Path == "/broker/v1/revoke":
		b.revoke(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (b *Broker) issue(w http.ResponseWriter, r *http.Request) {
	var request issueRequest
	if err := decodeJSON(w, r, &request); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if request.IdentityToken == "" || request.SourceAddress == "" {
		writeError(w, http.StatusBadRequest, "Pod-bound identity and source address are required")
		return
	}
	if !validTaskID(request.TaskID) {
		writeError(w, http.StatusBadRequest, "task ID is invalid")
		return
	}
	ttl := time.Duration(request.TTLSeconds) * time.Second
	if ttl < minimumTTL || ttl > maximumTTL {
		writeError(w, http.StatusBadRequest, "TTL must be between 60 and 900 seconds")
		return
	}
	target, err := governance.NormalizeTarget(request.Backend, request.Method, request.Host, request.Path)
	if err != nil {
		writeError(w, http.StatusBadRequest, "target is invalid")
		return
	}
	decision, err := b.checker.Check(r.Context(), authz.CheckInput{
		Backend: target.Backend, IdentityToken: request.IdentityToken,
		Method: target.Method, Host: target.Host, Path: target.Path,
		Headers: map[string]string{}, SourceAddress: request.SourceAddress,
	})
	if err != nil {
		b.logger.ErrorContext(r.Context(), "credential authorization failed", "error", err)
		writeError(w, http.StatusServiceUnavailable, "credential authorization is unavailable")
		return
	}
	if !decision.Allow {
		writeError(w, http.StatusForbidden, "credential scope is not authorized")
		return
	}
	now := b.now().UTC()
	expiresAt := now.Add(ttl)
	grantID := uuid.NewString()
	claims := GrantClaims{
		AssignmentName: decision.AssignmentName, AssignmentUID: decision.AssignmentUID,
		SandboxID: decision.SandboxID, PodUID: decision.PodUID,
		CapabilityBundleName:     decision.CapabilityBundleName,
		CapabilityBundleRevision: decision.CapabilityBundleRevision,
		TaskID:                   request.TaskID, Backend: target.Backend, Method: target.Method,
		Host: target.Host, Path: target.Path,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer: b.config.Issuer, Subject: decision.AssignmentUID,
			Audience:  jwt.ClaimStrings{b.config.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt), IssuedAt: jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now), ID: grantID,
		},
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(b.config.SigningKey)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "credential issuance failed")
		return
	}
	if err := b.record(r.Context(), "issued", claims); err != nil {
		b.logger.ErrorContext(r.Context(), "record credential issuance", "error", err)
		writeError(w, http.StatusServiceUnavailable, "credential audit is unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"credential": token, "grantId": grantID, "expiresAt": expiresAt,
		"assignment": decision.AssignmentName, "sandboxId": decision.SandboxID,
		"taskId": request.TaskID,
		"scope": map[string]string{
			"backend": target.Backend, "method": target.Method,
			"host": target.Host, "path": target.Path,
		},
	})
}

func (b *Broker) verify(w http.ResponseWriter, r *http.Request) {
	claims, err := b.parseAuthorization(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "credential is invalid or expired")
		return
	}
	if b.isRevoked(claims.ID) {
		writeError(w, http.StatusUnauthorized, "credential is revoked")
		return
	}
	if err := b.validator.ValidateGrant(r.Context(), claims); err != nil {
		writeError(w, http.StatusUnauthorized, "credential sandbox binding is stale")
		return
	}
	if err := b.record(r.Context(), "used", claims); err != nil {
		b.logger.ErrorContext(r.Context(), "record credential use", "error", err)
		writeError(w, http.StatusServiceUnavailable, "credential audit is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid": true, "grantId": claims.ID, "taskId": claims.TaskID,
		"assignment": claims.AssignmentName, "sandboxId": claims.SandboxID,
		"expiresAt": claims.ExpiresAt.Time,
		"scope": map[string]string{
			"backend": claims.Backend, "method": claims.Method,
			"host": claims.Host, "path": claims.Path,
		},
	})
}

func (b *Broker) revoke(w http.ResponseWriter, r *http.Request) {
	claims, err := b.parseAuthorization(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "credential is invalid or expired")
		return
	}
	b.mu.Lock()
	now := b.now()
	for id, expiry := range b.revoked {
		if !expiry.After(now) {
			delete(b.revoked, id)
		}
	}
	b.revoked[claims.ID] = claims.ExpiresAt.Time
	b.mu.Unlock()
	if err := b.record(r.Context(), "revoked", claims); err != nil {
		b.logger.ErrorContext(r.Context(), "record credential revocation", "error", err)
		writeError(w, http.StatusServiceUnavailable, "credential audit is unavailable")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (b *Broker) parseAuthorization(r *http.Request) (GrantClaims, error) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	tokenValue, found := strings.CutPrefix(value, "Bearer ")
	if !found || tokenValue == "" {
		return GrantClaims{}, errors.New("missing bearer credential")
	}
	claims := GrantClaims{}
	token, err := jwt.ParseWithClaims(tokenValue, &claims, func(token *jwt.Token) (any, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New("unexpected signing method")
		}
		return b.config.SigningKey, nil
	}, jwt.WithAudience(b.config.Audience), jwt.WithIssuer(b.config.Issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}), jwt.WithTimeFunc(b.now))
	if err != nil || !token.Valid || claims.ID == "" || claims.AssignmentUID == "" ||
		claims.PodUID == "" || claims.CapabilityBundleRevision == "" ||
		!validTaskID(claims.TaskID) {
		return GrantClaims{}, errors.New("invalid claims")
	}
	target, err := governance.NormalizeTarget(claims.Backend, claims.Method, claims.Host, claims.Path)
	if err != nil || target.Backend != claims.Backend || target.Method != claims.Method ||
		target.Host != claims.Host || target.Path != claims.Path {
		return GrantClaims{}, errors.New("invalid scope")
	}
	return claims, nil
}

func (b *Broker) isRevoked(id string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	expiry, revoked := b.revoked[id]
	if revoked && !expiry.After(b.now()) {
		delete(b.revoked, id)
		return false
	}
	return revoked
}

func (b *Broker) record(ctx context.Context, action string, claims GrantClaims) error {
	if b.audit == nil {
		return nil
	}
	return b.audit.Record(ctx, AuditEvent{Timestamp: b.now().UTC(), Action: action, Grant: claims})
}

func validTaskID(value string) bool {
	if len(value) < 1 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			(index > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
}

func decodeJSON(w http.ResponseWriter, r *http.Request, output any) error {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(output); err != nil {
		return errors.New("invalid JSON request")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request must contain one JSON object")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func tokenFingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", sum[:8])
}
