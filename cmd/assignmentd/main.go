// Command assignmentd serves assignment-aware external authorization checks.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"

	assignmentadmission "github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/admission"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/authz"
	assignmentcontroller "github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/controller"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/credentialbroker"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/opensandboxapi"
	assignmentkubernetes "github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/store/kubernetes"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthv1 "google.golang.org/grpc/health/grpc_health_v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
)

const (
	defaultGRPCAddress         = ":9001"
	defaultAPIAddress          = ":8080"
	defaultHealthAddress       = ":8081"
	defaultAssignmentNamespace = "aks-sandbox-system"
	defaultWorkloadNamespace   = "opensandbox"
	defaultOpenSandboxURL      = "http://opensandbox-server.opensandbox-system.svc.cluster.local"
	maxCheckRequestBytes       = 1 << 20
	leaderElectionName         = "assignmentd-controller"
	capabilityGatewayAudience  = "aks-sandbox-capability-gateway"
	defaultAuditRetention      = 24 * time.Hour
	defaultAuditQueueSize      = 1024
)

type options struct {
	leaderElect bool
}

type controllerRunner interface {
	Run(context.Context) error
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		logger.Error("parse flags", "error", err)
		os.Exit(2)
	}
	if err := run(logger, opts); err != nil {
		logger.Error("assignmentd exited", "error", err)
		os.Exit(1)
	}
}

func parseOptions(args []string) (options, error) {
	var opts options
	flags := flag.NewFlagSet("assignmentd", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&opts.leaderElect, "leader-elect", true, "use a Kubernetes Lease to elect one active assignment controller")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	return opts, nil
}

func run(logger *slog.Logger, opts options) error {
	grpcAddress := envOr("ASSIGNMENTD_GRPC_ADDRESS", defaultGRPCAddress)
	apiAddress := envOr("ASSIGNMENTD_API_ADDRESS", defaultAPIAddress)
	healthAddress := envOr("ASSIGNMENTD_HEALTH_ADDRESS", defaultHealthAddress)
	assignmentNamespace := envOr("ASSIGNMENTD_NAMESPACE", defaultAssignmentNamespace)
	workloadNamespace := envOr("ASSIGNMENTD_WORKLOAD_NAMESPACE", defaultWorkloadNamespace)
	egressIdentityMode := assignmentcontroller.EgressIdentityMode(
		envOr("ASSIGNMENTD_EGRESS_IDENTITY_MODE", string(assignmentcontroller.ProjectedSidecarIdentity)),
	)
	if egressIdentityMode != assignmentcontroller.ProjectedSidecarIdentity &&
		egressIdentityMode != assignmentcontroller.ExternalMediatorIdentity {
		return fmt.Errorf("invalid ASSIGNMENTD_EGRESS_IDENTITY_MODE")
	}
	openSandboxURL, err := url.Parse(envOr("ASSIGNMENTD_OPENSANDBOX_URL", defaultOpenSandboxURL))
	if err != nil || openSandboxURL.Scheme == "" || openSandboxURL.Host == "" {
		return fmt.Errorf("invalid ASSIGNMENTD_OPENSANDBOX_URL")
	}
	listener, err := net.Listen("tcp", grpcAddress)
	if err != nil {
		return err
	}

	kubernetesConfig, err := loadKubernetesConfig()
	if err != nil {
		return err
	}
	dynamicClient, err := dynamic.NewForConfig(kubernetesConfig)
	if err != nil {
		return err
	}
	coreClient, err := kubernetes.NewForConfig(kubernetesConfig)
	if err != nil {
		return err
	}
	assignmentStore := assignmentkubernetes.NewStore(dynamicClient, assignmentNamespace)
	assignmentController := assignmentcontroller.New(dynamicClient, coreClient, assignmentcontroller.Config{
		AssignmentNamespace: assignmentNamespace,
		WorkloadNamespace:   workloadNamespace,
		EgressIdentityMode:  egressIdentityMode,
		Interval:            time.Second,
	}, logger)

	checker, err := authz.NewKubernetesChecker(dynamicClient, coreClient, assignmentNamespace, workloadNamespace, capabilityGatewayAudience)
	if err != nil {
		return err
	}
	auditRetention, err := envDuration("ASSIGNMENTD_EGRESS_EVENT_RETENTION", defaultAuditRetention)
	if err != nil {
		return err
	}
	auditQueueSize, err := envPositiveInt("ASSIGNMENTD_AUDIT_QUEUE_SIZE", defaultAuditQueueSize)
	if err != nil {
		return err
	}
	auditSink, err := authz.NewKubernetesAuditSink(dynamicClient, assignmentNamespace, auditQueueSize, auditRetention, logger)
	if err != nil {
		return err
	}
	checker.SetAuditSink(auditSink)
	authorizationServer := authz.NewServer(checker, logger)
	grpcServer := grpc.NewServer(grpc.MaxRecvMsgSize(maxCheckRequestBytes))
	authv3.RegisterAuthorizationServer(grpcServer, authorizationServer)
	grpcHealth := health.NewServer()
	grpcHealth.SetServingStatus("", healthv1.HealthCheckResponse_SERVING)
	healthv1.RegisterHealthServer(grpcServer, grpcHealth)

	lifecycleHandler := opensandboxapi.NewHandler(assignmentStore, opensandboxapi.Config{
		Prefix:    "/opensandbox",
		Upstream:  openSandboxURL,
		APIKey:    os.Getenv("ASSIGNMENTD_OPENSANDBOX_API_KEY"),
		Namespace: assignmentNamespace,
		Admission: assignmentadmission.NewKubernetesAdmission(dynamicClient, assignmentNamespace, workloadNamespace),
	}, logger)
	apiMux := http.NewServeMux()
	apiMux.Handle("/opensandbox", lifecycleHandler)
	apiMux.Handle("/opensandbox/", lifecycleHandler)
	if signingKey := os.Getenv("ASSIGNMENTD_BROKER_SIGNING_KEY"); signingKey != "" {
		broker, err := credentialbroker.New(
			checker,
			credentialbroker.NewKubernetesGrantValidator(dynamicClient, coreClient, assignmentNamespace, workloadNamespace),
			credentialbroker.NewKubernetesAuditSink(dynamicClient, assignmentNamespace),
			credentialbroker.Config{SigningKey: []byte(signingKey)},
			logger,
		)
		if err != nil {
			return err
		}
		apiMux.Handle("/broker/", broker)
	} else {
		logger.Warn("credential broker disabled because ASSIGNMENTD_BROKER_SIGNING_KEY is unset")
	}
	apiServer := &http.Server{
		Addr:              apiAddress,
		Handler:           apiMux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute,
		IdleTimeout:       2 * time.Minute,
	}

	healthMux := http.NewServeMux()
	healthMux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	healthMux.Handle("/metrics", checker.MetricsHandler())
	healthServer := &http.Server{
		Addr:              healthAddress,
		Handler:           healthMux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	signalCtx, stopSignals := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSignals()
	runtimeCtx, cancelRuntime := context.WithCancel(context.Background())
	defer cancelRuntime()
	if err := assignmentStore.Start(runtimeCtx); err != nil {
		return err
	}
	auditSink.Start(runtimeCtx)
	if err := checker.Start(runtimeCtx); err != nil {
		return err
	}
	errCh := make(chan error, 4)
	go func() {
		if err := runAssignmentController(runtimeCtx, assignmentController, coreClient, assignmentNamespace, opts.leaderElect, logger); err != nil {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("assignmentd gRPC server listening", "address", grpcAddress)
		if err := grpcServer.Serve(listener); err != nil {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("assignmentd assignment API listening", "address", apiAddress, "namespace", assignmentNamespace)
		if err := apiServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		logger.Info("assignmentd health server listening", "address", healthAddress)
		if err := healthServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	var runErr error
	select {
	case <-signalCtx.Done():
	case runErr = <-errCh:
	}

	grpcHealth.SetServingStatus("", healthv1.HealthCheckResponse_NOT_SERVING)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := apiServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutting down assignment API", "error", err)
	}
	if err := healthServer.Shutdown(shutdownCtx); err != nil {
		logger.Warn("shutting down health server", "error", err)
	}

	stopped := make(chan struct{})
	go func() {
		grpcServer.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-shutdownCtx.Done():
		grpcServer.Stop()
	}
	if err := auditSink.Shutdown(shutdownCtx); err != nil {
		logger.Warn("draining authorization audit records", "error", err)
	}
	cancelRuntime()
	return runErr
}

func runAssignmentController(
	ctx context.Context,
	controller controllerRunner,
	client kubernetes.Interface,
	namespace string,
	leaderElect bool,
	logger *slog.Logger,
) error {
	if !leaderElect {
		logger.Warn("assignment controller leader election disabled")
		return controller.Run(ctx)
	}

	identity := os.Getenv("POD_UID")
	if identity == "" {
		var err error
		identity, err = os.Hostname()
		if err != nil {
			return fmt.Errorf("determine leader identity: %w", err)
		}
	}
	lock, err := resourcelock.New(
		resourcelock.LeasesResourceLock,
		namespace,
		leaderElectionName,
		client.CoreV1(),
		client.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: identity},
	)
	if err != nil {
		return fmt.Errorf("create leader election lock: %w", err)
	}

	electionCtx, cancelElection := context.WithCancel(ctx)
	defer cancelElection()
	var started atomic.Bool
	callbackErr := make(chan error, 1)
	elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
		Lock:            lock,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		ReleaseOnCancel: false,
		Name:            leaderElectionName,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(leaderCtx context.Context) {
				started.Store(true)
				logger.Info("assignment controller became leader", "identity", identity)
				if err := controller.Run(leaderCtx); err != nil && leaderCtx.Err() == nil {
					select {
					case callbackErr <- err:
					default:
					}
					cancelElection()
				}
			},
			OnStoppedLeading: func() {
				if started.Load() && ctx.Err() == nil {
					select {
					case callbackErr <- errors.New("assignment controller lost leadership"):
					default:
					}
				}
			},
			OnNewLeader: func(newIdentity string) {
				if newIdentity != identity {
					logger.Info("observed assignment controller leader", "identity", newIdentity)
				}
			},
		},
	})
	if err != nil {
		return fmt.Errorf("configure leader election: %w", err)
	}

	elector.Run(electionCtx)
	select {
	case err := <-callbackErr:
		return err
	default:
		return nil
	}
}

func loadKubernetesConfig() (*rest.Config, error) {
	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) (time.Duration, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration", key)
	}
	return duration, nil
}

func envPositiveInt(key string, fallback int) (int, error) {
	value := os.Getenv(key)
	if value == "" {
		return fallback, nil
	}
	number, err := strconv.Atoi(value)
	if err != nil || number <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer", key)
	}
	return number, nil
}
