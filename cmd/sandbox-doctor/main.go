// Command sandbox-doctor checks whether an AKS cluster satisfies the governed
// OpenSandbox readiness contract.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/doctor"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var kubeconfig, assignmentNamespace, workloadNamespace, runtimeClass, output string
	defaultKubeconfig := os.Getenv("KUBECONFIG")
	if defaultKubeconfig == "" {
		defaultKubeconfig = clientcmd.RecommendedHomeFile
	}
	flag.StringVar(&kubeconfig, "kubeconfig", defaultKubeconfig, "path to kubeconfig")
	flag.StringVar(&assignmentNamespace, "assignment-namespace", "aks-sandbox-system", "governance namespace")
	flag.StringVar(&workloadNamespace, "workload-namespace", "opensandbox", "OpenSandbox workload namespace")
	flag.StringVar(&runtimeClass, "runtime-class", "kata-optimized", "required RuntimeClass")
	flag.StringVar(&output, "output", "table", "output format: table or json")
	flag.Parse()

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		exitError(err)
	}
	kube, err := kubernetes.NewForConfig(config)
	if err != nil {
		exitError(err)
	}
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		exitError(err)
	}
	report := doctor.New(kube, dynamicClient, doctor.Config{
		AssignmentNamespace: assignmentNamespace,
		WorkloadNamespace:   workloadNamespace,
		RuntimeClass:        runtimeClass,
	}).Run(context.Background())

	switch output {
	case "json":
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(report); err != nil {
			exitError(err)
		}
	case "table":
		writer := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(writer, "CHECK\tSTATUS\tSUMMARY")
		for _, check := range report.Checks {
			_, _ = fmt.Fprintf(writer, "%s\t%s\t%s\n", check.Name, check.Status, check.Summary)
			if check.Remediation != "" {
				_, _ = fmt.Fprintf(writer, "\t\tremediation: %s\n", check.Remediation)
			}
		}
		_ = writer.Flush()
	default:
		exitError(fmt.Errorf("unsupported output format %q", output))
	}
	if !report.Ready {
		os.Exit(1)
	}
}

func exitError(err error) {
	_, _ = fmt.Fprintln(os.Stderr, "sandbox-doctor:", err)
	os.Exit(2)
}
