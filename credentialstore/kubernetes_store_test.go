package credentialstore

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newKubernetesStore(t *testing.T, namespace string) (*KubernetesStore, *fake.Clientset) {
	t.Helper()
	client := fake.NewClientset()
	store, err := NewKubernetesStore(KubernetesConfig{
		Client: client, Namespace: namespace, Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewKubernetesStore: %v", err)
	}
	return store, client
}

func TestKubernetesStoreLifecycle(t *testing.T) {
	store, client := newKubernetesStore(t, "team")
	secret := testSecret()
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	name := store.secretName("cred-1")
	stored, err := client.CoreV1().Secrets("team").Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("Get secret: %v", err)
	}
	if bytes.Contains(stored.Data["record"], []byte("super-secret-token")) {
		t.Fatalf("secret data contains plaintext")
	}
	loaded, err := store.Get(context.Background(), "cred-1")
	if err != nil || string(loaded.Material) != "super-secret-token" || loaded.Revision != 1 {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := store.Rotate(context.Background(), "cred-1", []byte("rotated"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 || string(rotated.Material) != "rotated" {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	if err := store.Delete(context.Background(), "cred-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}

func TestKubernetesStoreConflictsAndNamespaces(t *testing.T) {
	store, client := newKubernetesStore(t, "team")
	if _, err := store.Put(context.Background(), testSecret()); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := store.Put(context.Background(), testSecret()); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("duplicate Put = %v", err)
	}
	other, _ := newKubernetesStore(t, "other")
	if _, err := other.Get(context.Background(), "cred-1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("cross-namespace Get = %v", err)
	}
	wrongKey, err := NewKubernetesStore(KubernetesConfig{
		Client: client, Namespace: "team", Key: []byte("abcdef0123456789abcdef0123456789"),
	})
	if err != nil {
		t.Fatalf("NewKubernetesStore: %v", err)
	}
	if _, err := wrongKey.Get(context.Background(), "cred-1"); err == nil {
		t.Fatalf("wrong key decrypted material")
	}
	if err := store.Delete(context.Background(), "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
}

func TestKubernetesSecretNameIsDNS1123(t *testing.T) {
	store, _ := newKubernetesStore(t, "team")
	for _, id := range []domain.CredentialID{"cred-1", "Cred/With Spaces", domain.CredentialID(strings.Repeat("x", 400))} {
		name := store.secretName(id)
		if name == "" || len(name) > 253 || strings.HasPrefix(name, "-") || strings.HasSuffix(name, "-") {
			t.Fatalf("secret name %q for id %q", name, id)
		}
		if strings.ContainsAny(name, "/ _") {
			t.Fatalf("invalid characters in %q", name)
		}
	}
}
