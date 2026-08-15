package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/authz"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var assignmentsGVR = schema.GroupVersionResource{
	Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxassignments",
}

type options struct {
	kubeconfig string
	namespace  string
	workloads  string
	assignment string
	address    string
	backend    string
	method     string
	target     string
}

func main() {
	if err := run(context.Background(), os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "egress-probe:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	opts, err := parseOptions(args)
	if err != nil {
		return err
	}
	target, err := url.Parse(opts.target)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return errors.New("--target must be an absolute URL")
	}

	restConfig, err := clientcmd.BuildConfigFromFlags("", opts.kubeconfig)
	if err != nil {
		return fmt.Errorf("load kubeconfig: %w", err)
	}
	dynamicClient, err := dynamic.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("create dynamic client: %w", err)
	}
	coreClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("create Kubernetes client: %w", err)
	}

	assignment, err := dynamicClient.Resource(assignmentsGVR).Namespace(opts.namespace).Get(
		ctx, opts.assignment, metav1.GetOptions{},
	)
	if err != nil {
		return fmt.Errorf("get assignment: %w", err)
	}
	podName, _, _ := unstructuredString(assignment.Object, "status", "podRef", "name")
	podUID, _, _ := unstructuredString(assignment.Object, "status", "podRef", "uid")
	if podName == "" || podUID == "" {
		return errors.New("assignment is not ready: status.podRef is empty")
	}
	pod, err := coreClient.CoreV1().Pods(opts.workloads).Get(ctx, podName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("get sandbox pod: %w", err)
	}
	if string(pod.UID) != podUID || pod.Status.PodIP == "" {
		return errors.New("assignment pod identity is stale or incomplete")
	}

	expiration := int64(600)
	token, err := coreClient.CoreV1().ServiceAccounts(opts.workloads).CreateToken(
		ctx,
		pod.Spec.ServiceAccountName,
		&authenticationv1.TokenRequest{Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{"aks-sandbox-capability-gateway"},
			ExpirationSeconds: &expiration,
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind: "Pod", APIVersion: "v1", Name: pod.Name, UID: pod.UID,
			},
		}},
		metav1.CreateOptions{},
	)
	if err != nil {
		return fmt.Errorf("create bound identity token: %w", err)
	}

	requestContext, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	connection, err := grpc.NewClient(
		opts.address,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return fmt.Errorf("connect to assignmentd: %w", err)
	}
	defer connection.Close()

	path := target.EscapedPath()
	if path == "" {
		path = "/"
	}
	if target.RawQuery != "" {
		path += "?" + target.RawQuery
	}
	response, err := authv3.NewAuthorizationClient(connection).Check(requestContext, &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			ContextExtensions: map[string]string{authz.BackendContextKey: opts.backend},
			Source: &authv3.AttributeContext_Peer{Address: &corev3.Address{
				Address: &corev3.Address_SocketAddress{
					SocketAddress: &corev3.SocketAddress{Address: pod.Status.PodIP},
				},
			}},
			Request: &authv3.AttributeContext_Request{Http: &authv3.AttributeContext_HttpRequest{
				Method: strings.ToUpper(opts.method),
				Host:   target.Host,
				Path:   path,
				Headers: map[string]string{
					authz.IdentityHeader: token.Status.Token,
				},
			}},
		},
	})
	if err != nil {
		return fmt.Errorf("check egress authorization: %w", err)
	}

	allowed := response.GetStatus().GetCode() == int32(codes.OK)
	sandboxID := assignment.GetAnnotations()["aks-sandbox.azure.com/opensandbox-id"]
	fmt.Printf("assignment: %s\nsandbox:    %s\npod:        %s\ntarget:     %s %s\nbackend:    %s\nallowed:    %t\n",
		assignment.GetName(), sandboxID, pod.Name, strings.ToUpper(opts.method), target.String(), opts.backend, allowed)
	if !allowed && response.GetStatus().GetCode() != int32(codes.PermissionDenied) {
		return fmt.Errorf("unexpected authorization status code %d", response.GetStatus().GetCode())
	}
	return nil
}

func parseOptions(args []string) (options, error) {
	opts := options{}
	flags := flag.NewFlagSet("egress-probe", flag.ContinueOnError)
	flags.StringVar(&opts.kubeconfig, "kubeconfig", envOr("KUBECONFIG", clientcmd.RecommendedHomeFile), "path to kubeconfig")
	flags.StringVar(&opts.namespace, "namespace", "aks-sandbox-system", "assignment namespace")
	flags.StringVar(&opts.workloads, "workload-namespace", "opensandbox", "sandbox workload namespace")
	flags.StringVar(&opts.assignment, "assignment", "", "SandboxAssignment name")
	flags.StringVar(&opts.address, "address", "127.0.0.1:19001", "assignmentd gRPC address")
	flags.StringVar(&opts.backend, "backend", "external-web", "trusted backend name")
	flags.StringVar(&opts.method, "method", "GET", "HTTP method")
	flags.StringVar(&opts.target, "target", "", "absolute target URL")
	if err := flags.Parse(args); err != nil {
		return options{}, err
	}
	if flags.NArg() != 0 {
		return options{}, fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if strings.TrimSpace(opts.assignment) == "" || strings.TrimSpace(opts.target) == "" {
		return options{}, errors.New("--assignment and --target are required")
	}
	return opts, nil
}

func unstructuredString(object map[string]any, fields ...string) (string, bool, error) {
	current := any(object)
	for _, field := range fields {
		mapping, ok := current.(map[string]any)
		if !ok {
			return "", false, nil
		}
		current, ok = mapping[field]
		if !ok {
			return "", false, nil
		}
	}
	value, ok := current.(string)
	return value, ok, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
