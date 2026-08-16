// Package governance validates the normalized fields shared by access requests,
// authorization grants, telemetry, and the dashboard.
package governance

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"time"
	"unicode"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	"github.com/google/uuid"
	"k8s.io/apimachinery/pkg/util/validation"
)

const (
	// MinimumRequestedDuration keeps the POC from creating impractically short grants.
	MinimumRequestedDuration = time.Minute
	// MaximumRequestedDuration is the hard upper bound for a temporary overlay grant.
	MaximumRequestedDuration = 8 * time.Hour
)

var (
	methodPattern  = regexp.MustCompile(`^[A-Z][A-Z0-9_-]{0,31}$`)
	backendPattern = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
	hostLabel      = regexp.MustCompile(`^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$`)
)

// Target is one normalized Agentgateway authorization target.
type Target struct {
	Backend string
	Method  string
	Host    string
	Path    string
}

// NormalizeTarget returns the canonical target used for exact grant matching.
func NormalizeTarget(backend, method, host, requestPath string) (Target, error) {
	backend = strings.TrimSpace(backend)
	if !backendPattern.MatchString(backend) {
		return Target{}, errors.New("backend must be a lowercase DNS label")
	}

	method = strings.ToUpper(strings.TrimSpace(method))
	if !methodPattern.MatchString(method) {
		return Target{}, errors.New("method is invalid")
	}

	normalizedHost, err := NormalizeHost(host)
	if err != nil {
		return Target{}, err
	}
	normalizedPath, err := NormalizePath(requestPath)
	if err != nil {
		return Target{}, err
	}
	return Target{Backend: backend, Method: method, Host: normalizedHost, Path: normalizedPath}, nil
}

// NormalizeHost lowercases an HTTP authority, removes a numeric port, and
// rejects non-host data.
func NormalizeHost(authority string) (string, error) {
	authority = strings.TrimSpace(authority)
	if authority == "" || len(authority) > 512 || strings.ContainsAny(authority, "/?#@\\\r\n\t ") {
		return "", errors.New("host is invalid")
	}

	host := authority
	if _, _, err := net.SplitHostPort(authority); err == nil {
		return "", errors.New("explicit host ports are not supported")
	} else {
		switch {
		case strings.HasPrefix(authority, "[") && strings.HasSuffix(authority, "]"):
			host = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]")
		case strings.Contains(authority, ":"):
			return "", errors.New("host is invalid")
		}
	}

	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if host == "" || len(host) > 253 {
		return "", errors.New("host is invalid")
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return address.Unmap().String(), nil
	}
	for _, label := range strings.Split(host, ".") {
		if !hostLabel.MatchString(label) {
			return "", errors.New("host is invalid")
		}
	}
	return host, nil
}

// NormalizePath removes query and fragment data while preserving the exact
// escaped path bytes used by the gateway.
func NormalizePath(value string) (string, error) {
	if before, _, found := strings.Cut(value, "?"); found {
		value = before
	}
	if before, _, found := strings.Cut(value, "#"); found {
		value = before
	}
	if value == "" {
		value = "/"
	}
	if value != strings.TrimSpace(value) || !strings.HasPrefix(value, "/") || len(value) > 2048 || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("path is invalid")
	}
	return value, nil
}

// ValidateAccessRequestSpec enforces the API invariants independently of CRD admission.
func ValidateAccessRequestSpec(spec assignmentv1alpha1.SandboxAccessRequestSpec) error {
	if errors := validation.IsDNS1123Subdomain(spec.AssignmentRef.Name); len(errors) != 0 {
		return fmt.Errorf("assignment name is invalid: %s", strings.Join(errors, ", "))
	}
	if spec.AssignmentRef.UID == "" {
		return errors.New("assignment UID is required")
	}
	if spec.PodUID == "" {
		return errors.New("Pod UID is required")
	}
	if len(spec.BasePolicyRevision) < 8 || len(spec.BasePolicyRevision) > 128 || containsControl(spec.BasePolicyRevision) {
		return errors.New("base policy revision is invalid")
	}
	target, err := NormalizeTarget(spec.Backend, spec.Method, spec.Host, spec.Path)
	if err != nil {
		return err
	}
	if target.Backend != spec.Backend || target.Method != spec.Method || target.Host != spec.Host || target.Path != spec.Path {
		return errors.New("access request target is not canonical")
	}
	if err := validateHumanText("reason", spec.Reason, 3, 512); err != nil {
		return err
	}
	if err := ValidateIdentity(spec.Requester); err != nil {
		return fmt.Errorf("requester: %w", err)
	}
	duration := time.Duration(spec.RequestedDurationSeconds) * time.Second
	if duration < MinimumRequestedDuration || duration > MaximumRequestedDuration {
		return fmt.Errorf("requested duration must be between %s and %s", MinimumRequestedDuration, MaximumRequestedDuration)
	}
	return nil
}

// ValidateIdentity validates normalized authenticated Entra identity fields.
func ValidateIdentity(identity assignmentv1alpha1.GovernanceIdentity) error {
	if _, err := uuid.Parse(identity.TenantID); err != nil {
		return errors.New("tenant ID must be a UUID")
	}
	if _, err := uuid.Parse(identity.ObjectID); err != nil {
		return errors.New("object ID must be a UUID")
	}
	if err := validateHumanText("display name", identity.DisplayName, 1, 256); err != nil {
		return err
	}
	for name, value := range map[string]string{"logical tenant": identity.LogicalTenant, "team": identity.Team} {
		if value != "" {
			if err := validateHumanText(name, value, 1, 128); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHumanText(name, value string, minimum, maximum int) error {
	if value != strings.TrimSpace(value) || len(value) < minimum || len(value) > maximum || containsControl(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
