package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/validation"
)

var digestPinnedImagePattern = regexp.MustCompile(`^.+@sha256:[a-f0-9]{64}$`)

type templatePageRow struct {
	Name, DisplayName, Description, Image, Entrypoint, CapabilityBundle string
	CPU, Memory, Timeout, Enabled                                       string
}

func (g *governanceDashboard) templateRows(ctx context.Context) ([]templatePageRow, error) {
	list, err := g.client.Resource(dashboardTemplatesGVR).Namespace(g.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	rows := make([]templatePageRow, 0, len(list.Items))
	for i := range list.Items {
		item := &list.Items[i]
		entrypoint, _, _ := unstructured.NestedStringSlice(item.Object, "spec", "entrypoint")
		displayName, _, _ := unstructured.NestedString(item.Object, "spec", "displayName")
		description, _, _ := unstructured.NestedString(item.Object, "spec", "description")
		image, _, _ := unstructured.NestedString(item.Object, "spec", "image")
		bundle, _, _ := unstructured.NestedString(item.Object, "spec", "capabilityBundleRef", "name")
		cpu, _, _ := unstructured.NestedString(item.Object, "spec", "resources", "cpu")
		memory, _, _ := unstructured.NestedString(item.Object, "spec", "resources", "memory")
		timeoutSeconds, _, _ := unstructured.NestedInt64(item.Object, "spec", "timeoutSeconds")
		enabled, _, _ := unstructured.NestedBool(item.Object, "spec", "enabled")
		rows = append(rows, templatePageRow{
			Name: item.GetName(), DisplayName: displayName, Description: description,
			Image: image, Entrypoint: strings.Join(entrypoint, " "), CapabilityBundle: bundle,
			CPU: cpu, Memory: memory, Timeout: (time.Duration(timeoutSeconds) * time.Second).String(),
			Enabled: strconv.FormatBool(enabled),
		})
	}
	return rows, nil
}

func (g *governanceDashboard) createSandboxTemplate(w http.ResponseWriter, r *http.Request) {
	if _, ok := g.requireAdmin(w, r); !ok {
		return
	}
	form, ok := g.parseMutation(
		w, r, "csrf", "name", "displayName", "description", "image", "entrypoint",
		"capabilityBundle", "cpu", "memory", "timeoutSeconds", "enabled",
	)
	if !ok {
		return
	}
	name := strings.TrimSpace(form.Get("name"))
	if errs := validation.IsDNS1123Subdomain(name); len(errs) != 0 {
		http.Error(w, "Template name must be a DNS subdomain", http.StatusBadRequest)
		return
	}
	displayName := strings.TrimSpace(form.Get("displayName"))
	description := strings.TrimSpace(form.Get("description"))
	image := strings.TrimSpace(form.Get("image"))
	bundle := strings.TrimSpace(form.Get("capabilityBundle"))
	if len(displayName) < 3 || len(displayName) > 128 || len(description) > 512 ||
		len(image) > 512 || !digestPinnedImagePattern.MatchString(image) ||
		len(bundle) == 0 || len(bundle) > 253 {
		http.Error(w, "Template fields are invalid", http.StatusBadRequest)
		return
	}
	bundleObject, err := g.client.Resource(dashboardBundlesGVR).Namespace(g.namespace).Get(r.Context(), bundle, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			http.Error(w, "Capability bundle does not exist", http.StatusBadRequest)
			return
		}
		g.resourceError(w, "get capability bundle", err)
		return
	}
	policyRevision, err := templatePolicyRevision(bundleObject)
	if err != nil {
		g.internalError(w, r, "calculate capability bundle revision", err)
		return
	}
	var entrypoint []string
	if err := json.Unmarshal([]byte(form.Get("entrypoint")), &entrypoint); err != nil ||
		len(entrypoint) == 0 || len(entrypoint) > 32 {
		http.Error(w, "Entrypoint must be a JSON string array", http.StatusBadRequest)
		return
	}
	for _, value := range entrypoint {
		if strings.TrimSpace(value) == "" || len(value) > 512 {
			http.Error(w, "Entrypoint values are invalid", http.StatusBadRequest)
			return
		}
	}
	cpu := strings.TrimSpace(form.Get("cpu"))
	memory := strings.TrimSpace(form.Get("memory"))
	if _, err := resource.ParseQuantity(cpu); err != nil {
		http.Error(w, "CPU quantity is invalid", http.StatusBadRequest)
		return
	}
	if _, err := resource.ParseQuantity(memory); err != nil {
		http.Error(w, "Memory quantity is invalid", http.StatusBadRequest)
		return
	}
	timeoutSeconds, err := strconv.ParseInt(form.Get("timeoutSeconds"), 10, 64)
	if err != nil || timeoutSeconds < 60 || timeoutSeconds > 3600 {
		http.Error(w, "Lifetime must be between 60 and 3600 seconds", http.StatusBadRequest)
		return
	}
	enabled, err := strconv.ParseBool(form.Get("enabled"))
	if err != nil {
		http.Error(w, "Enabled must be true or false", http.StatusBadRequest)
		return
	}
	entrypointValues := make([]any, len(entrypoint))
	for i := range entrypoint {
		entrypointValues[i] = entrypoint[i]
	}

	object := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "aks-sandbox.azure.com/v1alpha1",
		"kind":       "SandboxTemplate",
		"metadata": map[string]any{
			"name":      name,
			"namespace": g.namespace,
		},
		"spec": map[string]any{
			"displayName": displayName,
			"description": description,
			"image":       image,
			"entrypoint":  entrypointValues,
			"capabilityBundleRef": map[string]any{
				"name":           bundle,
				"policyRevision": policyRevision,
			},
			"resources": map[string]any{
				"cpu": cpu, "memory": memory,
			},
			"timeoutSeconds": timeoutSeconds,
			"enabled":        enabled,
		},
	}}
	if _, err := g.client.Resource(dashboardTemplatesGVR).Namespace(g.namespace).Create(
		r.Context(), object, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	); err != nil {
		g.resourceError(w, "create sandbox template", err)
		return
	}
	g.redirectWithMessage(w, r, "/admin", fmt.Sprintf("Sandbox template %s created", name))
}

func templatePolicyRevision(bundle *unstructured.Unstructured) (string, error) {
	spec, _, _ := unstructured.NestedMap(bundle.Object, "spec")
	return governance.PolicyRevision(spec)
}
