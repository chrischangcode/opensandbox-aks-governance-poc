package credentialbroker

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
)

func TestKubernetesRevocationStoreSharesStateAcrossInstances(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	first := NewKubernetesRevocationStore(client, "governance")
	second := NewKubernetesRevocationStore(client, "governance")
	claims := revocationClaims(time.Now().Add(time.Hour))

	if err := first.Revoke(context.Background(), claims); err != nil {
		t.Fatal(err)
	}
	if err := first.Revoke(context.Background(), claims); err != nil {
		t.Fatalf("idempotent Revoke() error = %v", err)
	}
	revoked, err := second.IsRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("revocation was not visible to another store instance")
	}
}

func TestKubernetesRevocationStoreRemovesExpiredState(t *testing.T) {
	client := dynamicfake.NewSimpleDynamicClient(runtime.NewScheme())
	store := NewKubernetesRevocationStore(client, "governance")
	now := time.Now().UTC()
	store.now = func() time.Time { return now }
	claims := revocationClaims(now.Add(time.Minute))

	if err := store.Revoke(context.Background(), claims); err != nil {
		t.Fatal(err)
	}
	store.now = func() time.Time { return now.Add(2 * time.Minute) }
	revoked, err := store.IsRevoked(context.Background(), claims.ID)
	if err != nil {
		t.Fatal(err)
	}
	if revoked {
		t.Fatal("expired revocation remained active")
	}
	if _, err := client.Resource(credentialRevocationGVR).Namespace("governance").Get(
		context.Background(), "grant-"+claims.ID, metav1.GetOptions{},
	); !apierrors.IsNotFound(err) {
		t.Fatalf("expired revocation Get() error = %v, want NotFound", err)
	}
}

func revocationClaims(expiry time.Time) GrantClaims {
	return GrantClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "grant-a",
			ExpiresAt: jwt.NewNumericDate(expiry),
		},
		AssignmentName: "assignment-a",
		AssignmentUID:  "assignment-uid",
		PodUID:         "pod-uid",
		SandboxID:      "sandbox-a",
	}
}
