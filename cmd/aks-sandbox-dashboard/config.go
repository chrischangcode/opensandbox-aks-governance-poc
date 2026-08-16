package main

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type config struct {
	listenAddress        string
	basePath             string
	kubeconfigPath       string
	openSandboxNamespace string
	sandboxNamespace     string
	assignmentNamespace  string
	sandboxImage         string
	lifecycleEndpoint    string
	lifecycleTokenFile   string
	sandboxTemplate      string
	tenantID             string
	clientID             string
	scope                string
	redirectURI          string
	miseURL              string
	misePolicy           string
	requiredScope        string
	requiredRole         string
	adminRole            string
	sessionLifetime      time.Duration
	cookieSecure         bool
	devAuth              bool
	devName              string
	devTenantID          string
	devObjectID          string
	devRoles             string
}

func parseConfig(args []string) (config, error) {
	cfg := config{}
	flags := flag.NewFlagSet("aks-sandbox-dashboard", flag.ContinueOnError)
	flags.StringVar(&cfg.listenAddress, "listen", envOr("HTTP_ADDR", "0.0.0.0:8080"), "HTTP listen address")
	flags.StringVar(&cfg.basePath, "base-path", envOr("OSB_DASHBOARD_BASE_PATH", "/dashboard"), "dashboard URL prefix")
	flags.StringVar(&cfg.kubeconfigPath, "kubeconfig", os.Getenv("OSB_DASHBOARD_KUBECONFIG"), "optional kubeconfig; empty uses in-cluster authentication")
	flags.StringVar(&cfg.openSandboxNamespace, "opensandbox-namespace", envOr("OSB_DASHBOARD_OPENSANDBOX_NAMESPACE", "opensandbox-system"), "namespace containing the OpenSandbox lifecycle service")
	flags.StringVar(&cfg.sandboxNamespace, "sandbox-namespace", envOr("OSB_DASHBOARD_SANDBOX_NAMESPACE", "opensandbox"), "namespace containing sandbox resources")
	flags.StringVar(&cfg.assignmentNamespace, "assignment-namespace", envOr("OSB_DASHBOARD_ASSIGNMENT_NAMESPACE", "aks-sandbox-system"), "namespace containing assignment governance resources")
	flags.StringVar(&cfg.sandboxImage, "sandbox-image", envOr("OSB_DASHBOARD_SANDBOX_IMAGE", "python:3.12-slim"), "default image used by dashboard create actions")
	flags.StringVar(&cfg.lifecycleEndpoint, "lifecycle-endpoint", os.Getenv("OSB_DASHBOARD_LIFECYCLE_ENDPOINT"), "optional OpenSandbox lifecycle facade endpoint")
	flags.StringVar(&cfg.lifecycleTokenFile, "lifecycle-token-file", os.Getenv("OSB_DASHBOARD_LIFECYCLE_TOKEN_FILE"), "projected ServiceAccount token file for the lifecycle facade")
	flags.StringVar(&cfg.sandboxTemplate, "sandbox-template", envOr("OSB_DASHBOARD_SANDBOX_TEMPLATE", "python-kata-reader-v2"), "administrator-owned sandbox template injected into create requests")
	flags.StringVar(&cfg.tenantID, "tenant-id", os.Getenv("OSB_DASHBOARD_ENTRA_TENANT_ID"), "dashboard Entra tenant ID")
	flags.StringVar(&cfg.clientID, "client-id", os.Getenv("OSB_DASHBOARD_ENTRA_CLIENT_ID"), "dashboard Entra application client ID")
	flags.StringVar(&cfg.scope, "scope", os.Getenv("OSB_DASHBOARD_ENTRA_SCOPE"), "dashboard delegated API scope")
	flags.StringVar(&cfg.redirectURI, "redirect-uri", os.Getenv("OSB_DASHBOARD_ENTRA_REDIRECT_URI"), "registered dashboard SPA callback URI")
	flags.StringVar(&cfg.miseURL, "mise-url", envOr("OSB_DASHBOARD_MISE_URL", "http://127.0.0.1:5000/ValidateRequest"), "MISE ValidateRequest endpoint")
	flags.StringVar(&cfg.misePolicy, "mise-policy", envOr("OSB_DASHBOARD_MISE_POLICY", "osb-dashboard-inbound-policy"), "MISE inbound policy label")
	flags.StringVar(&cfg.requiredScope, "required-scope", envOr("OSB_DASHBOARD_REQUIRED_SCOPE", "access_as_user"), "scope required in the validated access token")
	flags.StringVar(&cfg.requiredRole, "required-role", os.Getenv("OSB_DASHBOARD_REQUIRED_ROLE"), "app role required in the validated access token")
	flags.StringVar(&cfg.adminRole, "admin-role", envOr("OSB_DASHBOARD_ADMIN_ROLE", "OpenSandbox.Admin"), "app role required for governance administration")
	flags.DurationVar(&cfg.sessionLifetime, "session-lifetime", envDuration("OSB_DASHBOARD_SESSION_LIFETIME", 30*time.Minute), "maximum dashboard session lifetime")
	flags.BoolVar(&cfg.cookieSecure, "cookie-secure", envBool("OSB_DASHBOARD_COOKIE_SECURE", true), "set Secure on authentication cookies")
	flags.BoolVar(&cfg.devAuth, "dev-auth", envBool("OSB_DASHBOARD_DEV_AUTH", false), "use a static local identity; requires a loopback listen address")
	flags.StringVar(&cfg.devName, "dev-name", envOr("OSB_DASHBOARD_DEV_NAME", "POC Administrator"), "display name for local development authentication")
	flags.StringVar(&cfg.devTenantID, "dev-tenant-id", envOr("OSB_DASHBOARD_DEV_TENANT_ID", "00000000-0000-4000-8000-000000000001"), "tenant UUID for local development authentication")
	flags.StringVar(&cfg.devObjectID, "dev-object-id", envOr("OSB_DASHBOARD_DEV_OBJECT_ID", "00000000-0000-4000-8000-000000000002"), "object UUID for local development authentication")
	flags.StringVar(&cfg.devRoles, "dev-roles", envOr("OSB_DASHBOARD_DEV_ROLES", "OpenSandbox.Admin"), "comma-separated roles for local development authentication")
	if err := flags.Parse(args); err != nil {
		return config{}, err
	}
	if flags.NArg() != 0 {
		return config{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}

	cfg.basePath = "/" + strings.Trim(strings.TrimSpace(cfg.basePath), "/")
	if cfg.basePath == "/" {
		return config{}, errors.New("--base-path must not be the site root")
	}
	required := map[string]string{
		"--listen":               cfg.listenAddress,
		"--redirect-uri":         cfg.redirectURI,
		"--sandbox-template":     cfg.sandboxTemplate,
		"--assignment-namespace": cfg.assignmentNamespace,
		"--admin-role":           cfg.adminRole,
	}
	if cfg.devAuth {
		required["--dev-name"] = cfg.devName
		required["--dev-tenant-id"] = cfg.devTenantID
		required["--dev-object-id"] = cfg.devObjectID
		required["--dev-roles"] = cfg.devRoles
		if err := validateLoopbackListenAddress(cfg.listenAddress); err != nil {
			return config{}, err
		}
	} else {
		required["--tenant-id"] = cfg.tenantID
		required["--client-id"] = cfg.clientID
		required["--scope"] = cfg.scope
		required["--mise-url"] = cfg.miseURL
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return config{}, fmt.Errorf("%s is required", name)
		}
	}
	if cfg.sessionLifetime <= 0 {
		return config{}, errors.New("--session-lifetime must be greater than zero")
	}
	if cfg.lifecycleEndpoint != "" && strings.TrimSpace(cfg.lifecycleTokenFile) == "" {
		return config{}, errors.New("--lifecycle-token-file is required with --lifecycle-endpoint")
	}
	return cfg, nil
}

func validateLoopbackListenAddress(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("--listen must be host:port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("--dev-auth requires --listen to use a loopback IP")
	}
	return nil
}

func envOr(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envDuration(name string, fallback time.Duration) time.Duration {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}
