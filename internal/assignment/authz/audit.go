package authz

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	ktypes "k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var checkerEgressEventsGVR = schema.GroupVersionResource{
	Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxegressevents",
}

// AuditMetricsSnapshot is a point-in-time view of audit counters.
type AuditMetricsSnapshot struct {
	Enqueued uint64
	Written  uint64
	Dropped  uint64
	Errors   uint64
}

// AuditSink durably records authorization decisions.
type AuditSink interface {
	Record(context.Context, Decision) error
	Metrics() AuditMetricsSnapshot
}

type auditMetrics struct {
	enqueued atomic.Uint64
	written  atomic.Uint64
	dropped  atomic.Uint64
	errors   atomic.Uint64
}

// KubernetesAuditSink writes immutable SandboxEgressEvent resources before an
// allow is returned and performs idempotent retention/request expiry cleanup.
type KubernetesAuditSink struct {
	client          dynamic.Interface
	namespace       string
	retention       time.Duration
	cleanupInterval time.Duration
	logger          *slog.Logger
	metrics         auditMetrics
	now             func() time.Time
	accepting       atomic.Bool
}

// NewKubernetesAuditSink creates a synchronous fail-closed audit sink.
func NewKubernetesAuditSink(
	client dynamic.Interface,
	namespace string,
	queueSize int,
	retention time.Duration,
	logger *slog.Logger,
) (*KubernetesAuditSink, error) {
	if client == nil {
		return nil, fmt.Errorf("audit sink Kubernetes client is required")
	}
	if namespace == "" {
		return nil, fmt.Errorf("audit sink namespace is required")
	}
	if queueSize <= 0 {
		return nil, fmt.Errorf("audit queue size must be greater than zero")
	}
	if retention <= 0 {
		return nil, fmt.Errorf("audit retention must be greater than zero")
	}
	if logger == nil {
		logger = slog.Default()
	}
	cleanupInterval := retention / 4
	if cleanupInterval < time.Minute {
		cleanupInterval = time.Minute
	}
	if cleanupInterval > 15*time.Minute {
		cleanupInterval = 15 * time.Minute
	}
	sink := &KubernetesAuditSink{
		client:          client,
		namespace:       namespace,
		retention:       retention,
		cleanupInterval: cleanupInterval,
		logger:          logger,
		now:             time.Now,
	}
	sink.accepting.Store(true)
	return sink, nil
}

// Start runs cleanup until the context is canceled.
func (s *KubernetesAuditSink) Start(ctx context.Context) {
	go s.cleanupLoop(ctx)
}

// Record writes a sanitized decision before returning.
func (s *KubernetesAuditSink) Record(ctx context.Context, decision Decision) error {
	decision = sanitizeDecision(decision)
	if decision.AssignmentName == "" || decision.AssignmentUID == "" || decision.PodUID == "" ||
		decision.CapabilityBundleName == "" || decision.CapabilityBundleRevision == "" ||
		decision.Backend == "" || decision.Method == "" || decision.Host == "" || decision.Path == "" ||
		decision.Reason == "" || decision.Source == "" {
		s.metrics.errors.Add(1)
		s.metrics.dropped.Add(1)
		return fmt.Errorf("authorization audit record is incomplete")
	}
	if !s.accepting.Load() {
		s.metrics.dropped.Add(1)
		return fmt.Errorf("authorization audit sink is shutting down")
	}
	s.metrics.enqueued.Add(1)
	if err := s.write(ctx, decision, s.now()); err != nil {
		s.metrics.errors.Add(1)
		return err
	}
	s.metrics.written.Add(1)
	return nil
}

// Shutdown stops accepting new records.
func (s *KubernetesAuditSink) Shutdown(_ context.Context) error {
	s.accepting.Store(false)
	return nil
}

// Metrics returns audit counters.
func (s *KubernetesAuditSink) Metrics() AuditMetricsSnapshot {
	return AuditMetricsSnapshot{
		Enqueued: s.metrics.enqueued.Load(),
		Written:  s.metrics.written.Load(),
		Dropped:  s.metrics.dropped.Load(),
		Errors:   s.metrics.errors.Load(),
	}
}

func (s *KubernetesAuditSink) write(ctx context.Context, decision Decision, timestamp time.Time) error {
	event, err := egressEventForDecision(s.namespace, timestamp, decision)
	if err != nil {
		return err
	}
	_, err = s.client.Resource(checkerEgressEventsGVR).Namespace(s.namespace).Create(
		ctx, event, metav1.CreateOptions{FieldValidation: metav1.FieldValidationStrict},
	)
	return err
}

func egressEventForDecision(namespace string, timestamp time.Time, decision Decision) (*unstructured.Unstructured, error) {
	event := &assignmentv1alpha1.SandboxEgressEvent{
		TypeMeta: metav1.TypeMeta{
			APIVersion: assignmentv1alpha1.GroupVersion.String(),
			Kind:       "SandboxEgressEvent",
		},
		ObjectMeta: metav1.ObjectMeta{
			Namespace:    namespace,
			GenerateName: "egress-",
		},
		Spec: assignmentv1alpha1.SandboxEgressEventSpec{
			Timestamp: metav1.NewTime(timestamp.UTC()),
			AssignmentRef: assignmentv1alpha1.AssignmentReference{
				Name: decision.AssignmentName,
				UID:  ktypes.UID(decision.AssignmentUID),
			},
			SandboxID:                decision.SandboxID,
			PodUID:                   ktypes.UID(decision.PodUID),
			CapabilityBundleName:     decision.CapabilityBundleName,
			CapabilityBundleRevision: decision.CapabilityBundleRevision,
			LogicalTenant:            decision.LogicalTenant,
			Team:                     decision.Team,
			PermissionLevel:          decision.PermissionLevel,
			BoundaryDisplayName:      decision.BoundaryDisplayName,
			Backend:                  decision.Backend,
			Method:                   decision.Method,
			Host:                     decision.Host,
			Path:                     decision.Path,
			Allowed:                  decision.Allow,
			Reason:                   decision.Reason,
			DecisionSource:           decision.Source,
			AccessRequestName:        decision.AccessRequestName,
		},
	}
	object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(event)
	if err != nil {
		return nil, err
	}
	return &unstructured.Unstructured{Object: object}, nil
}

func (s *KubernetesAuditSink) cleanupLoop(ctx context.Context) {
	if err := s.cleanup(ctx); err != nil && ctx.Err() == nil {
		s.logger.Error("initial governance cleanup", "error_category", auditErrorCategory(err))
	}
	ticker := time.NewTicker(s.cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.cleanup(ctx); err != nil && ctx.Err() == nil {
				s.logger.Error("governance cleanup", "error_category", auditErrorCategory(err))
			}
		}
	}
}

func (s *KubernetesAuditSink) cleanup(ctx context.Context) error {
	if err := s.cleanupEvents(ctx); err != nil {
		return err
	}
	return s.expireAccessRequests(ctx)
}

func (s *KubernetesAuditSink) cleanupEvents(ctx context.Context) error {
	events, err := s.client.Resource(checkerEgressEventsGVR).Namespace(s.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	cutoff := s.now().Add(-s.retention)
	for i := range events.Items {
		event := &events.Items[i]
		value, _, _ := unstructured.NestedString(event.Object, "spec", "timestamp")
		timestamp, err := time.Parse(time.RFC3339Nano, value)
		if err != nil {
			timestamp = event.GetCreationTimestamp().Time
		}
		if timestamp.IsZero() || !timestamp.Before(cutoff) {
			continue
		}
		if err := s.client.Resource(checkerEgressEventsGVR).Namespace(s.namespace).Delete(
			ctx, event.GetName(), metav1.DeleteOptions{},
		); err != nil && !apierrors.IsNotFound(err) {
			return err
		}
	}
	return nil
}

func (s *KubernetesAuditSink) expireAccessRequests(ctx context.Context) error {
	requests, err := s.client.Resource(checkerAccessRequestsGVR).Namespace(s.namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	now := s.now()
	for i := range requests.Items {
		request := &requests.Items[i]
		state, _, _ := unstructured.NestedString(request.Object, "status", "state")
		expiresAt, _, _ := unstructured.NestedString(request.Object, "status", "expiresAt")
		expiry, err := time.Parse(time.RFC3339Nano, expiresAt)
		if state != string(assignmentv1alpha1.SandboxAccessRequestApproved) || err != nil || expiry.After(now) {
			continue
		}
		patch := []byte(`{"status":{"state":"Expired"}}`)
		if _, err := s.client.Resource(checkerAccessRequestsGVR).Namespace(s.namespace).Patch(
			ctx, request.GetName(), ktypes.MergePatchType, patch, metav1.PatchOptions{}, "status",
		); err != nil && !apierrors.IsNotFound(err) && !apierrors.IsConflict(err) {
			return err
		}
	}
	return nil
}

func sanitizeDecision(decision Decision) Decision {
	decision.AssignmentName = sanitizeAuditValue(decision.AssignmentName, 253)
	decision.AssignmentUID = sanitizeAuditValue(decision.AssignmentUID, 128)
	decision.SandboxID = sanitizeAuditValue(decision.SandboxID, 253)
	decision.PodUID = sanitizeAuditValue(decision.PodUID, 128)
	decision.CapabilityBundleName = sanitizeAuditValue(decision.CapabilityBundleName, 253)
	decision.CapabilityBundleRevision = sanitizeAuditValue(decision.CapabilityBundleRevision, 128)
	decision.LogicalTenant = sanitizeAuditValue(decision.LogicalTenant, 128)
	decision.Team = sanitizeAuditValue(decision.Team, 128)
	decision.PermissionLevel = sanitizeAuditValue(decision.PermissionLevel, 64)
	decision.BoundaryDisplayName = sanitizeAuditValue(decision.BoundaryDisplayName, 128)
	decision.Backend = sanitizeAuditValue(decision.Backend, 63)
	decision.Method = sanitizeAuditValue(decision.Method, 32)
	decision.Host = sanitizeAuditValue(decision.Host, 253)
	decision.Path = sanitizeAuditValue(decision.Path, 2048)
	decision.Reason = sanitizeAuditValue(decision.Reason, 512)
	decision.AccessRequestName = sanitizeAuditValue(decision.AccessRequestName, 253)
	return decision
}

func sanitizeAuditValue(value string, maximum int) string {
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, value)
	value = strings.TrimSpace(value)
	runes := []rune(value)
	if len(runes) > maximum {
		value = string(runes[:maximum])
	}
	return value
}

func auditErrorCategory(err error) string {
	reason := apierrors.ReasonForError(err)
	if reason == "" {
		return "internal"
	}
	return string(reason)
}
