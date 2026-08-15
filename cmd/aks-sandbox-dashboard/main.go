package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	dashboard "github.com/bahe-msft/osb-dashboard"
	osbclient "github.com/bahe-msft/osb-dashboard/opensandbox"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(os.Args[1:], logger); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		logger.Error("dashboard exited", slog.Any("error", err))
		os.Exit(1)
	}
}

func run(args []string, logger *slog.Logger) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	kubernetesConfig, err := loadDashboardKubernetesConfig(cfg.kubeconfigPath)
	if err != nil {
		return fmt.Errorf("load dashboard Kubernetes configuration: %w", err)
	}
	governanceClient, err := dynamic.NewForConfig(kubernetesConfig)
	if err != nil {
		return fmt.Errorf("create dashboard governance client: %w", err)
	}

	clientOptions := osbclient.Options{
		Namespace:         cfg.openSandboxNamespace,
		WorkloadNamespace: cfg.sandboxNamespace,
		LifecycleEndpoint: cfg.lifecycleEndpoint,
		Logger:            logger,
	}
	if cfg.lifecycleEndpoint != "" {
		clientOptions.LifecycleHTTPClient = &http.Client{
			Transport: &capabilityProfileTransport{base: http.DefaultTransport, profile: cfg.capabilityProfile},
			Timeout:   11 * time.Minute,
		}
	}
	var client osbclient.Client
	if cfg.kubeconfigPath == "" {
		if clientOptions.LifecycleEndpoint == "" {
			clientOptions.LifecycleEndpoint = fmt.Sprintf(
				"http://opensandbox-server.%s.svc.cluster.local",
				cfg.openSandboxNamespace,
			)
		}
		client, err = osbclient.NewInCluster(clientOptions)
	} else {
		client, err = osbclient.NewFromKubeconfig(cfg.kubeconfigPath, clientOptions)
	}
	if err != nil {
		return fmt.Errorf("create OpenSandbox dashboard client: %w", err)
	}
	defer func() {
		if err := client.Close(); err != nil {
			logger.Error("close OpenSandbox dashboard client", slog.Any("error", err))
		}
	}()

	rootContext, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	var auth dashboardAuthenticator
	if cfg.devAuth {
		auth, err = newDevelopmentDashboardAuth(cfg)
		if err != nil {
			return err
		}
		logger.Warn("local development authentication enabled", "address", cfg.listenAddress)
	} else {
		auth = newDashboardAuth(rootContext, cfg, newMISETokenValidator(cfg))
	}
	defer auth.Close()
	governance, err := newGovernanceDashboard(governanceClient, cfg, logger)
	if err != nil {
		return err
	}

	app, err := dashboard.New(client, dashboard.Options{
		BasePath:     cfg.basePath,
		SandboxImage: cfg.sandboxImage,
		Context:      rootContext,
		Logger:       logger,
		RegisterRoutes: func(mux *http.ServeMux) {
			auth.RegisterRoutes(mux)
			governance.RegisterRoutes(mux)
		},
	})
	if err != nil {
		return fmt.Errorf("create embedded dashboard: %w", err)
	}
	defer app.Close()

	server := &http.Server{
		Addr:              cfg.listenAddress,
		Handler:           auth.Middleware(app.Handler()),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	shutdownDone := make(chan struct{})
	go func() {
		defer close(shutdownDone)
		<-rootContext.Done()
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			logger.Error("shutdown dashboard", slog.Any("error", err))
		}
	}()

	logger.Info(
		"dashboard listening",
		slog.String("address", cfg.listenAddress),
		slog.String("base_path", cfg.basePath),
	)
	err = server.ListenAndServe()
	cancel()
	<-shutdownDone
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("serve dashboard: %w", err)
	}
	return nil
}

func loadDashboardKubernetesConfig(kubeconfigPath string) (*rest.Config, error) {
	if kubeconfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	}
	return rest.InClusterConfig()
}
