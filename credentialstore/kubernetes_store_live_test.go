package credentialstore

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func TestKubernetesStoreIntegrationLive(t *testing.T) {
	kubeconfig := os.Getenv("QUARSHELL_KUBECONFIG")
	if kubeconfig == "" {
		t.Skip("QUARSHELL_KUBECONFIG is not set")
	}
	namespace := os.Getenv("QUARSHELL_K8S_NAMESPACE")
	if namespace == "" {
		namespace = "default"
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		t.Fatalf("BuildConfigFromFlags: %v", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		t.Fatalf("NewForConfig: %v", err)
	}
	store, err := NewKubernetesStore(KubernetesConfig{
		Client: client, Namespace: namespace, Key: []byte("0123456789abcdef0123456789abcdef"),
	})
	if err != nil {
		t.Fatalf("NewKubernetesStore: %v", err)
	}
	secret := testSecret()
	secret.ID = domain.CredentialID("it-" + time.Now().Format("150405.000000000"))
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() { _ = store.Delete(context.Background(), secret.ID) })
	loaded, err := store.Get(context.Background(), secret.ID)
	if err != nil || string(loaded.Material) != "super-secret-token" {
		t.Fatalf("Get = %+v %v", loaded, err)
	}
	rotated, err := store.Rotate(context.Background(), secret.ID, []byte("rotated"), time.Now().Add(time.Hour))
	if err != nil || rotated.Revision != 2 {
		t.Fatalf("Rotate = %+v %v", rotated, err)
	}
	if err := store.Delete(context.Background(), secret.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := store.Get(context.Background(), secret.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("Get after delete = %v", err)
	}
}
