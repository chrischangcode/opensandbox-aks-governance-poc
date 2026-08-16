package authz

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	assignmentv1alpha1 "github.com/chrischangcode/opensandbox-aks-governance-poc/api/assignment/v1alpha1"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment"
	"github.com/chrischangcode/opensandbox-aks-governance-poc/internal/assignment/governance"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicinformer "k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
)

const (
	podUIDIndex              = "podUID"
	assignmentPodUIDIndex    = "assignmentPodUID"
	accessAssignmentUIDIndex = "accessAssignmentUID"
	podNameExtra             = "authentication.kubernetes.io/pod-name"
	podUIDExtra              = "authentication.kubernetes.io/pod-uid"
	serviceAccountPrefix     = "system:serviceaccount:"
	celRuntimeCostLimit      = 10_000
	maxCompiledPrograms      = 1_024
	maxTokenCacheEntries     = 4_096
	tokenCacheTTL            = 30 * time.Second
	freshnessLimit           = 10 * time.Second
	freshnessProbePeriod     = 5 * time.Second
)

var (
	checkerAssignmentsGVR    = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxassignments"}
	checkerBundlesGVR        = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "capabilitybundles"}
	checkerAccessRequestsGVR = schema.GroupVersionResource{Group: "aks-sandbox.azure.com", Version: "v1alpha1", Resource: "sandboxaccessrequests"}
)

// KubernetesChecker verifies projected Pod identity and evaluates the exact
// ready assignment bundle selected by the trusted backend key.
type KubernetesChecker struct {
	dynamic             dynamic.Interface
	kube                kubernetes.Interface
	assignmentNamespace string
	workloadNamespace   string
	audience            string
	assignments         cache.SharedIndexInformer
	bundles             cache.SharedIndexInformer
	accessRequests      cache.SharedIndexInformer
	pods                cache.SharedIndexInformer
	serviceAccounts     cache.SharedIndexInformer
	dynamicFactory      dynamicinformer.DynamicSharedInformerFactory
	coreFactory         informers.SharedInformerFactory
	celEnv              *cel.Env
	programs            *programCache
	tokens              *tokenCache
	lastFreshUnixNano   atomic.Int64
	metrics             checkerMetrics
	audit               AuditSink
	now                 func() time.Time
}

type programCache struct {
	mu     sync.RWMutex
	values map[string]cel.Program
}

type tokenCache struct {
	mu     sync.Mutex
	values map[[sha256.Size]byte]cachedIdentity
}

type cachedIdentity struct {
	identity  reviewedIdentity
	expiresAt time.Time
}

type checkerMetrics struct {
	allows          atomic.Uint64
	denies          atomic.Uint64
	errors          atomic.Uint64
	tokenReviews    atomic.Uint64
	tokenCacheHits  atomic.Uint64
	celErrors       atomic.Uint64
	freshnessDenies atomic.Uint64
	grantsUsed      atomic.Uint64
}

// NewKubernetesChecker creates informer-backed authorization state.
func NewKubernetesChecker(
	dynamicClient dynamic.Interface,
	kube kubernetes.Interface,
	assignmentNamespace, workloadNamespace, audience string,
) (*KubernetesChecker, error) {
	dynamicFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, 0, assignmentNamespace, nil)
	assignments := dynamicFactory.ForResource(checkerAssignmentsGVR).Informer()
	if err := assignments.AddIndexers(cache.Indexers{assignmentPodUIDIndex: assignmentPodUIDs}); err != nil {
		return nil, err
	}
	bundles := dynamicFactory.ForResource(checkerBundlesGVR).Informer()
	accessRequests := dynamicFactory.ForResource(checkerAccessRequestsGVR).Informer()
	if err := accessRequests.AddIndexers(cache.Indexers{accessAssignmentUIDIndex: accessRequestAssignmentUIDs}); err != nil {
		return nil, err
	}

	coreFactory := informers.NewSharedInformerFactoryWithOptions(kube, 0, informers.WithNamespace(workloadNamespace))
	pods := coreFactory.Core().V1().Pods().Informer()
	if err := pods.AddIndexers(cache.Indexers{podUIDIndex: podUIDs}); err != nil {
		return nil, err
	}
	serviceAccounts := coreFactory.Core().V1().ServiceAccounts().Informer()

	celEnv, err := newPolicyEnvironment()
	if err != nil {
		return nil, err
	}

	checker := &KubernetesChecker{
		dynamic: dynamicClient, kube: kube,
		assignmentNamespace: assignmentNamespace, workloadNamespace: workloadNamespace, audience: audience,
		assignments: assignments, bundles: bundles, accessRequests: accessRequests, pods: pods, serviceAccounts: serviceAccounts,
		celEnv: celEnv, programs: &programCache{values: map[string]cel.Program{}},
		tokens: &tokenCache{values: map[[sha256.Size]byte]cachedIdentity{}},
		now:    time.Now,
	}
	checker.dynamicFactory = dynamicFactory
	checker.coreFactory = coreFactory
	return checker, nil
}

func newPolicyEnvironment() (*cel.Env, error) {
	return cel.NewEnv(
		cel.Variable("request", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("backend", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("source", cel.MapType(cel.StringType, cel.DynType)),
	)
}

// ValidateAllowExpression compiles and type-checks one backend allow expression.
func ValidateAllowExpression(expression string) error {
	environment, err := newPolicyEnvironment()
	if err != nil {
		return err
	}
	ast, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return errors.New("allow expression must return bool")
	}
	return nil
}

// SetAuditSink installs the non-blocking decision sink before checks are served.
func (c *KubernetesChecker) SetAuditSink(sink AuditSink) {
	c.audit = sink
}

// MetricsHandler exposes bounded, credential-free authorization counters.
func (c *KubernetesChecker) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		fresh := 0
		if c.fresh() {
			fresh = 1
		}
		audit := AuditMetricsSnapshot{}
		if c.audit != nil {
			audit = c.audit.Metrics()
		}
		_, _ = fmt.Fprintf(w,
			"assignmentd_authz_allows_total %d\nassignmentd_authz_denies_total %d\nassignmentd_authz_errors_total %d\nassignmentd_authz_token_reviews_total %d\nassignmentd_authz_token_cache_hits_total %d\nassignmentd_authz_cel_errors_total %d\nassignmentd_authz_freshness_denies_total %d\nassignmentd_authz_grants_used_total %d\nassignmentd_authz_cache_fresh %d\nassignmentd_audit_enqueued_total %d\nassignmentd_audit_written_total %d\nassignmentd_audit_dropped_total %d\nassignmentd_audit_errors_total %d\n",
			c.metrics.allows.Load(), c.metrics.denies.Load(), c.metrics.errors.Load(), c.metrics.tokenReviews.Load(),
			c.metrics.tokenCacheHits.Load(), c.metrics.celErrors.Load(), c.metrics.freshnessDenies.Load(), c.metrics.grantsUsed.Load(), fresh,
			audit.Enqueued, audit.Written, audit.Dropped, audit.Errors,
		)
	})
}

// Start synchronizes every authorization cache before checks can be served.
func (c *KubernetesChecker) Start(ctx context.Context) error {
	c.dynamicFactory.Start(ctx.Done())
	c.coreFactory.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), c.assignments.HasSynced, c.bundles.HasSynced, c.accessRequests.HasSynced, c.pods.HasSynced, c.serviceAccounts.HasSynced) {
		return errors.New("synchronize authorization caches")
	}
	c.lastFreshUnixNano.Store(time.Now().UnixNano())
	go c.freshnessLoop(ctx)
	return nil
}

// Check validates identity and evaluates one backend allow expression.
func (c *KubernetesChecker) Check(ctx context.Context, input CheckInput) (decision Decision, err error) {
	defer func() {
		if c.audit != nil && decision.AssignmentUID != "" {
			if auditErr := c.audit.Record(ctx, decision); auditErr != nil && decision.Allow {
				decision.Allow = false
				decision.Reason = "authorization audit is unavailable"
				err = fmt.Errorf("record authorization decision: %w", auditErr)
			}
		}
		switch {
		case err != nil:
			c.metrics.errors.Add(1)
			c.metrics.denies.Add(1)
		case decision.Allow:
			c.metrics.allows.Add(1)
		default:
			c.metrics.denies.Add(1)
		}
	}()
	if !c.fresh() {
		c.metrics.freshnessDenies.Add(1)
		return Decision{Reason: "authorization cache is stale"}, nil
	}
	identity, tokenDecision, err := c.reviewToken(ctx, input.IdentityToken)
	if err != nil || !tokenDecision.Allow {
		return tokenDecision, err
	}
	podObjects, err := c.pods.GetIndexer().ByIndex(podUIDIndex, identity.podUID)
	if err != nil {
		return Decision{}, err
	}
	if len(podObjects) != 1 {
		return Decision{Reason: "live Pod UID is not unique"}, nil
	}
	pod := podObjects[0].(*corev1.Pod)
	if pod.DeletionTimestamp != nil || pod.Namespace != c.workloadNamespace || pod.Namespace != identity.namespace || pod.Name != identity.podName || string(pod.UID) != identity.podUID || pod.Spec.ServiceAccountName != identity.serviceAccount {
		return Decision{Reason: "token does not match live Pod"}, nil
	}
	effectiveSource := input.SourceAddress
	if input.DeriveSourceFromIdentity {
		effectiveSource = pod.Status.PodIP
	}
	sourceAddress, err := netip.ParseAddr(effectiveSource)
	if err != nil || !sourceMatchesPod(sourceAddress.Unmap(), pod) {
		return Decision{Reason: "request source does not match token Pod"}, nil
	}
	if pod.Spec.AutomountServiceAccountToken == nil || *pod.Spec.AutomountServiceAccountToken {
		return Decision{Reason: "sandbox Pod permits token automount"}, nil
	}
	serviceAccountObject, exists, err := c.serviceAccounts.GetStore().GetByKey(pod.Namespace + "/" + pod.Spec.ServiceAccountName)
	if err != nil {
		return Decision{}, err
	}
	if !exists {
		return Decision{Reason: "sandbox ServiceAccount is unavailable"}, nil
	}
	serviceAccount := serviceAccountObject.(*corev1.ServiceAccount)
	if serviceAccount.Labels[assignment.EligibleServiceAccountLabel] != "true" || serviceAccount.AutomountServiceAccountToken == nil || *serviceAccount.AutomountServiceAccountToken {
		return Decision{Reason: "sandbox ServiceAccount is not eligible"}, nil
	}

	assignmentObjects, err := c.assignments.GetIndexer().ByIndex(assignmentPodUIDIndex, identity.podUID)
	if err != nil {
		return Decision{}, err
	}
	if len(assignmentObjects) != 1 {
		return Decision{Reason: "ready assignment for Pod UID is not unique"}, nil
	}
	assignmentObject := assignmentObjects[0].(*unstructured.Unstructured)
	if assignmentObject.GetDeletionTimestamp() != nil || assignmentObject.GetAnnotations()[assignment.PausedAnnotation] == "true" || !conditionTrue(assignmentObject, "Ready") {
		return Decision{Reason: "assignment is not ready"}, nil
	}
	statusPodUID, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "podRef", "uid")
	if statusPodUID != identity.podUID {
		return Decision{Reason: "assignment Pod UID mismatch"}, nil
	}

	bundleName, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "name")
	specBundleName, _, _ := unstructured.NestedString(assignmentObject.Object, "spec", "capabilityBundleRef", "name")
	if bundleName == "" || specBundleName != bundleName {
		return Decision{Reason: "assignment bundle reference mismatch"}, nil
	}
	bundleUID, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "uid")
	bundleRevision, _, _ := unstructured.NestedString(assignmentObject.Object, "status", "resolvedCapabilityBundle", "policyRevision")
	bundleObject, exists, err := c.bundles.GetStore().GetByKey(c.assignmentNamespace + "/" + bundleName)
	if err != nil {
		return Decision{}, err
	}
	if !exists {
		return Decision{Reason: "capability bundle is unavailable"}, nil
	}
	bundle := bundleObject.(*unstructured.Unstructured)
	if bundle.GetDeletionTimestamp() != nil || string(bundle.GetUID()) != bundleUID {
		return Decision{Reason: "capability bundle UID mismatch"}, nil
	}
	revision, err := checkerPolicyRevision(bundle)
	if err != nil {
		return Decision{}, err
	}
	if revision != bundleRevision {
		return Decision{Reason: "capability bundle revision mismatch"}, nil
	}

	decision = Decision{
		Source:                   assignmentv1alpha1.DecisionSourceDeny,
		AssignmentName:           assignmentObject.GetName(),
		AssignmentUID:            string(assignmentObject.GetUID()),
		SandboxID:                assignmentObject.GetAnnotations()[assignment.SandboxIDAnnotation],
		PodUID:                   identity.podUID,
		CapabilityBundleName:     bundleName,
		CapabilityBundleRevision: bundleRevision,
		Backend:                  input.Backend,
		Method:                   input.Method,
		Host:                     input.Host,
		Path:                     input.Path,
	}
	decision.LogicalTenant, _, _ = unstructured.NestedString(bundle.Object, "spec", "governance", "logicalTenant")
	decision.Team, _, _ = unstructured.NestedString(bundle.Object, "spec", "governance", "team")
	decision.PermissionLevel, _, _ = unstructured.NestedString(bundle.Object, "spec", "governance", "permissionLevel")
	decision.BoundaryDisplayName, _, _ = unstructured.NestedString(bundle.Object, "spec", "governance", "displayName")

	expression, found, err := unstructured.NestedString(bundle.Object, "spec", "egress", "agentgateway", input.Backend, "allow")
	if err != nil {
		return decision, err
	}
	bundleReason := "backend is not granted"
	if found {
		if expression == "" {
			decision.Reason = "backend policy is invalid"
			return decision, nil
		}
		program, err := c.program(bundleUID, bundleRevision, input.Backend, expression)
		if err != nil {
			c.metrics.celErrors.Add(1)
			decision.Reason = "backend policy is invalid"
			return decision, nil
		}
		result, _, err := program.Eval(map[string]any{
			"backend": map[string]any{"name": input.Backend},
			"request": map[string]any{"method": input.Method, "host": input.Host, "path": input.Path, "headers": input.Headers},
			"source":  map[string]any{"address": effectiveSource},
		})
		if err != nil {
			c.metrics.celErrors.Add(1)
			decision.Reason = "backend policy evaluation failed"
			return decision, nil
		}
		if result == types.True {
			decision.Allow = true
			decision.Source = assignmentv1alpha1.DecisionSourceBundle
			decision.Reason = "backend allow expression returned true"
			return decision, nil
		}
		bundleReason = "backend allow expression returned false"
	}

	requestName, grantReason, granted, err := c.matchAccessGrant(decision, c.now())
	if err != nil {
		return decision, err
	}
	if granted {
		c.metrics.grantsUsed.Add(1)
		decision.Allow = true
		decision.Source = assignmentv1alpha1.DecisionSourceAccessRequest
		decision.AccessRequestName = requestName
		decision.Reason = "approved access request matched exact target"
		return decision, nil
	}
	decision.Reason = bundleReason + "; " + grantReason
	return decision, nil
}

func (c *KubernetesChecker) fresh() bool {
	last := c.lastFreshUnixNano.Load()
	return last != 0 && time.Since(time.Unix(0, last)) <= freshnessLimit
}

func (c *KubernetesChecker) freshnessLoop(ctx context.Context) {
	ticker := time.NewTicker(freshnessProbePeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.probeFreshness(ctx) == nil {
				c.lastFreshUnixNano.Store(time.Now().UnixNano())
			}
		}
	}
}

func (c *KubernetesChecker) probeFreshness(ctx context.Context) error {
	options := metav1.ListOptions{Limit: 1}
	if _, err := c.dynamic.Resource(checkerAssignmentsGVR).Namespace(c.assignmentNamespace).List(ctx, options); err != nil {
		return err
	}
	if _, err := c.dynamic.Resource(checkerBundlesGVR).Namespace(c.assignmentNamespace).List(ctx, options); err != nil {
		return err
	}
	if _, err := c.dynamic.Resource(checkerAccessRequestsGVR).Namespace(c.assignmentNamespace).List(ctx, options); err != nil {
		return err
	}
	if _, err := c.kube.CoreV1().Pods(c.workloadNamespace).List(ctx, options); err != nil {
		return err
	}
	if _, err := c.kube.CoreV1().ServiceAccounts(c.workloadNamespace).List(ctx, options); err != nil {
		return err
	}
	return nil
}

type reviewedIdentity struct {
	namespace      string
	serviceAccount string
	podName        string
	podUID         string
}

func (c *KubernetesChecker) reviewToken(ctx context.Context, token string) (reviewedIdentity, Decision, error) {
	tokenHash := sha256.Sum256([]byte(token))
	now := time.Now()
	c.tokens.mu.Lock()
	if cached, found := c.tokens.values[tokenHash]; found && now.Before(cached.expiresAt) {
		c.tokens.mu.Unlock()
		c.metrics.tokenCacheHits.Add(1)
		return cached.identity, Decision{Allow: true}, nil
	}
	delete(c.tokens.values, tokenHash)
	c.tokens.mu.Unlock()

	c.metrics.tokenReviews.Add(1)
	review, err := c.kube.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{Token: token, Audiences: []string{c.audience}},
	}, metav1.CreateOptions{})
	if err != nil {
		return reviewedIdentity{}, Decision{}, err
	}
	if !review.Status.Authenticated || review.Status.Error != "" || !slices.Contains(review.Status.Audiences, c.audience) {
		return reviewedIdentity{}, Decision{Reason: "TokenReview rejected identity"}, nil
	}
	username := strings.TrimPrefix(review.Status.User.Username, serviceAccountPrefix)
	parts := strings.Split(username, ":")
	if len(parts) != 2 || username == review.Status.User.Username {
		return reviewedIdentity{}, Decision{Reason: "token is not a ServiceAccount identity"}, nil
	}
	podNames := review.Status.User.Extra[podNameExtra]
	podUIDs := review.Status.User.Extra[podUIDExtra]
	if len(podNames) != 1 || len(podUIDs) != 1 || podNames[0] == "" || podUIDs[0] == "" {
		return reviewedIdentity{}, Decision{Reason: "token is not Pod-bound"}, nil
	}
	identity := reviewedIdentity{namespace: parts[0], serviceAccount: parts[1], podName: podNames[0], podUID: podUIDs[0]}
	expiresAt := now.Add(tokenCacheTTL)
	if tokenExpiry, ok := jwtExpiration(token); ok && tokenExpiry.Before(expiresAt) {
		expiresAt = tokenExpiry
	}
	if expiresAt.After(now) {
		c.tokens.mu.Lock()
		if len(c.tokens.values) >= maxTokenCacheEntries {
			c.tokens.values = map[[sha256.Size]byte]cachedIdentity{}
		}
		c.tokens.values[tokenHash] = cachedIdentity{identity: identity, expiresAt: expiresAt}
		c.tokens.mu.Unlock()
	}
	return identity, Decision{Allow: true}, nil
}

func jwtExpiration(token string) (time.Time, bool) {
	claims := &jwt.RegisteredClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(token, claims)
	if err != nil || claims.ExpiresAt == nil || claims.ExpiresAt.Time.IsZero() {
		return time.Time{}, false
	}
	return claims.ExpiresAt.Time, true
}

func (c *KubernetesChecker) program(bundleUID, revision, backend, expression string) (cel.Program, error) {
	key := bundleUID + "\x00" + revision + "\x00" + backend
	c.programs.mu.RLock()
	program := c.programs.values[key]
	c.programs.mu.RUnlock()
	if program != nil {
		return program, nil
	}
	ast, issues := c.celEnv.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	if ast.OutputType() != cel.BoolType {
		return nil, errors.New("allow expression must return bool")
	}
	program, err := c.celEnv.Program(ast, cel.CostLimit(celRuntimeCostLimit))
	if err != nil {
		return nil, err
	}
	c.programs.mu.Lock()
	if len(c.programs.values) >= maxCompiledPrograms {
		c.programs.values = map[string]cel.Program{}
	}
	c.programs.values[key] = program
	c.programs.mu.Unlock()
	return program, nil
}

func (c *KubernetesChecker) matchAccessGrant(decision Decision, now time.Time) (string, string, bool, error) {
	objects, err := c.accessRequests.GetIndexer().ByIndex(accessAssignmentUIDIndex, decision.AssignmentUID)
	if err != nil {
		return "", "", false, err
	}
	return matchAccessGrantObjects(objects, decision, now)
}

func matchAccessGrantObjects(objects []any, decision Decision, now time.Time) (string, string, bool, error) {
	var matches []string
	invalidExact := false
	for _, raw := range objects {
		object, ok := raw.(*unstructured.Unstructured)
		if !ok {
			return "", "", false, fmt.Errorf("unexpected access request object %T", raw)
		}
		if object.GetDeletionTimestamp() != nil {
			continue
		}
		request := &assignmentv1alpha1.SandboxAccessRequest{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(object.Object, request); err != nil {
			return "", "", false, fmt.Errorf("convert SandboxAccessRequest %q: %w", object.GetName(), err)
		}
		if request.Status.State != assignmentv1alpha1.SandboxAccessRequestApproved ||
			string(request.Spec.AssignmentRef.UID) != decision.AssignmentUID {
			continue
		}
		if request.Spec.AssignmentRef.Name != decision.AssignmentName ||
			string(request.Spec.PodUID) != decision.PodUID ||
			request.Spec.BasePolicyRevision != decision.CapabilityBundleRevision {
			continue
		}
		if err := governance.ValidateAccessRequestSpec(request.Spec); err != nil {
			invalidExact = true
			continue
		}
		if request.Spec.Backend != decision.Backend || request.Spec.Method != decision.Method ||
			request.Spec.Host != decision.Host || request.Spec.Path != decision.Path {
			continue
		}
		if !validApproval(request, now) {
			invalidExact = true
			continue
		}
		matches = append(matches, request.Name)
	}
	switch len(matches) {
	case 0:
		if invalidExact {
			return "", "matching access request is malformed, stale, or expired", false, nil
		}
		return "", "no matching approved access request", false, nil
	case 1:
		return matches[0], "", true, nil
	default:
		return "", "multiple approved access requests match exact target", false, nil
	}
}

func validApproval(request *assignmentv1alpha1.SandboxAccessRequest, now time.Time) bool {
	if request.Status.Approver == nil || governance.ValidateIdentity(*request.Status.Approver) != nil ||
		strings.TrimSpace(request.Status.DecisionReason) == "" ||
		request.Status.ApprovedAt == nil || request.Status.ExpiresAt == nil {
		return false
	}
	approvedAt := request.Status.ApprovedAt.Time
	expiresAt := request.Status.ExpiresAt.Time
	requestedDuration := time.Duration(request.Spec.RequestedDurationSeconds) * time.Second
	return !approvedAt.After(now) &&
		expiresAt.After(now) &&
		expiresAt.After(approvedAt) &&
		expiresAt.Sub(approvedAt) <= requestedDuration &&
		expiresAt.Sub(approvedAt) <= governance.MaximumRequestedDuration
}

func accessRequestAssignmentUIDs(raw any) ([]string, error) {
	object, ok := raw.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected access request object %T", raw)
	}
	uid, _, _ := unstructured.NestedString(object.Object, "spec", "assignmentRef", "uid")
	if uid == "" {
		return nil, nil
	}
	return []string{uid}, nil
}

func assignmentPodUIDs(raw any) ([]string, error) {
	object, ok := raw.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected assignment object %T", raw)
	}
	uid, _, _ := unstructured.NestedString(object.Object, "status", "podRef", "uid")
	if uid == "" {
		return nil, nil
	}
	return []string{uid}, nil
}

func podUIDs(raw any) ([]string, error) {
	pod, ok := raw.(*corev1.Pod)
	if !ok {
		return nil, fmt.Errorf("unexpected Pod object %T", raw)
	}
	if pod.UID == "" {
		return nil, nil
	}
	return []string{string(pod.UID)}, nil
}

func sourceMatchesPod(source netip.Addr, pod *corev1.Pod) bool {
	for _, podIP := range pod.Status.PodIPs {
		candidate, err := netip.ParseAddr(podIP.IP)
		if err == nil && candidate.Unmap() == source {
			return true
		}
	}
	candidate, err := netip.ParseAddr(pod.Status.PodIP)
	return err == nil && candidate.Unmap() == source
}

func conditionTrue(object *unstructured.Unstructured, kind string) bool {
	conditions, _, _ := unstructured.NestedSlice(object.Object, "status", "conditions")
	for _, raw := range conditions {
		condition, ok := raw.(map[string]any)
		if ok && condition["type"] == kind && condition["status"] == "True" {
			return true
		}
	}
	return false
}

func checkerPolicyRevision(bundle *unstructured.Unstructured) (string, error) {
	spec, _, _ := unstructured.NestedMap(bundle.Object, "spec")
	return governance.PolicyRevision(spec)
}
