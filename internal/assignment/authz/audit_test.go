package authz

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
)

func TestAuditSinkQueueOverflowDoesNotBlock(t *testing.T) {
	sink := newFakeAuditSink(t, 1)
	decision := validAuditDecision()
	if !sink.Enqueue(decision) {
		t.Fatal("first audit decision was dropped")
	}
	if sink.Enqueue(decision) {
		t.Fatal("second audit decision unexpectedly fit in full queue")
	}
	metrics := sink.Metrics()
	if metrics.Enqueued != 1 || metrics.Dropped != 1 {
		t.Fatalf("metrics = %+v", metrics)
	}
}

func TestAuditSinkWritesSanitizedEvent(t *testing.T) {
	sink := newFakeAuditSink(t, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	decisionTime := time.Date(2026, time.August, 15, 19, 0, 0, 0, time.UTC)
	sink.now = func() time.Time { return decisionTime }
	decision := validAuditDecision()
	decision.Reason = "denied\nsecret"
	if !sink.Enqueue(decision) {
		t.Fatal("audit decision was dropped")
	}
	sink.now = func() time.Time { return decisionTime.Add(time.Hour) }
	sink.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for sink.Metrics().Written == 0 && sink.Metrics().Errors == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if metrics := sink.Metrics(); metrics.Written != 1 || metrics.Errors != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
	list, err := sink.client.Resource(checkerEgressEventsGVR).Namespace("aks-sandbox-system").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("events = %d", len(list.Items))
	}
	reason, _, _ := unstructured.NestedString(list.Items[0].Object, "spec", "reason")
	if strings.ContainsAny(reason, "\r\n") || reason != "deniedsecret" {
		t.Fatalf("sanitized reason = %q", reason)
	}
	timestamp, _, _ := unstructured.NestedString(list.Items[0].Object, "spec", "timestamp")
	if timestamp != decisionTime.Format(time.RFC3339) {
		t.Fatalf("event timestamp = %q, want %q", timestamp, decisionTime.Format(time.RFC3339))
	}
	if _, found, _ := unstructured.NestedFieldNoCopy(list.Items[0].Object, "spec", "headers"); found {
		t.Fatal("audit event contains headers")
	}
}

func TestAuditSinkShutdownDrainsQueue(t *testing.T) {
	sink := newFakeAuditSink(t, 2)
	sink.Start(context.Background())
	if !sink.Enqueue(validAuditDecision()) {
		t.Fatal("audit decision was dropped")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sink.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	metrics := sink.Metrics()
	if metrics.Written != 1 || metrics.Dropped != 0 {
		t.Fatalf("metrics = %+v", metrics)
	}
	if sink.Enqueue(validAuditDecision()) {
		t.Fatal("audit sink accepted a record after shutdown")
	}
}

func TestAuditCleanupRetainsRecentEventsAndExpiresRequests(t *testing.T) {
	now := time.Now().UTC()
	oldEvent, err := egressEventForDecision("aks-sandbox-system", now.Add(-25*time.Hour), validAuditDecision())
	if err != nil {
		t.Fatal(err)
	}
	oldEvent.SetName("old-event")
	oldEvent.SetGenerateName("")
	recentEvent, err := egressEventForDecision("aks-sandbox-system", now.Add(-time.Hour), validAuditDecision())
	if err != nil {
		t.Fatal(err)
	}
	recentEvent.SetName("recent-event")
	recentEvent.SetGenerateName("")
	request := accessRequestObject(t, "access-expired", "sha256:0123456789", now.Add(-time.Minute))

	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClient(scheme, oldEvent, recentEvent, request)
	sink, err := NewKubernetesAuditSink(client, "aks-sandbox-system", 1, 24*time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	sink.now = func() time.Time { return now }
	if err := sink.cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := sink.cleanup(context.Background()); err != nil {
		t.Fatalf("idempotent cleanup: %v", err)
	}
	if _, err := client.Resource(checkerEgressEventsGVR).Namespace("aks-sandbox-system").Get(context.Background(), "old-event", metav1.GetOptions{}); !apierrors.IsNotFound(err) {
		t.Fatalf("old event get error = %v", err)
	}
	if _, err := client.Resource(checkerEgressEventsGVR).Namespace("aks-sandbox-system").Get(context.Background(), "recent-event", metav1.GetOptions{}); err != nil {
		t.Fatalf("recent event was removed: %v", err)
	}
	updated, err := client.Resource(checkerAccessRequestsGVR).Namespace("aks-sandbox-system").Get(context.Background(), "access-expired", metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	state, _, _ := unstructured.NestedString(updated.Object, "status", "state")
	if state != string(assignmentv1alpha1.SandboxAccessRequestExpired) {
		t.Fatalf("request state = %q", state)
	}
}

func newFakeAuditSink(t *testing.T, queueSize int) *KubernetesAuditSink {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := assignmentv1alpha1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	client := fake.NewSimpleDynamicClient(scheme)
	sink, err := NewKubernetesAuditSink(
		client, "aks-sandbox-system", queueSize, 24*time.Hour,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	if err != nil {
		t.Fatal(err)
	}
	return sink
}

func validAuditDecision() Decision {
	return Decision{
		Allow: true, Reason: "allowed", Source: assignmentv1alpha1.DecisionSourceBundle,
		AssignmentName: "assignment-a", AssignmentUID: "assignment-uid", SandboxID: "sandbox-a", PodUID: "pod-uid",
		CapabilityBundleName: "coding", CapabilityBundleRevision: "sha256:0123456789",
		LogicalTenant: "tenant-a", Team: "team-a", PermissionLevel: "contributor",
		Backend: "cachew", Method: "GET", Host: "cachew.example.test", Path: "/repo/info/refs",
	}
}
