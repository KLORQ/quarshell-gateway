package credentialstore

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// KubernetesConfig configures the Kubernetes Secrets store.
type KubernetesConfig struct {
	Client    kubernetes.Interface
	Namespace string
	Prefix    string
	Key       []byte
}

// KubernetesStore stores encrypted records in Kubernetes Secrets.
type KubernetesStore struct {
	client    kubernetes.Interface
	namespace string
	prefix    string
	box       *cipherBox
}

// NewKubernetesStore validates configuration.
func NewKubernetesStore(config KubernetesConfig) (*KubernetesStore, error) {
	if config.Client == nil {
		return nil, domain.Invalidf("credentials.kubernetes", "client is required")
	}
	if strings.TrimSpace(config.Namespace) == "" {
		return nil, domain.Invalidf("credentials.kubernetes", "namespace is required")
	}
	prefix := config.Prefix
	if prefix == "" {
		prefix = "quarshell-credential-"
	}
	if len(prefix) > 200 {
		return nil, domain.Invalidf("credentials.kubernetes", "prefix is too long")
	}
	box, err := newCipherBox(config.Key)
	if err != nil {
		return nil, err
	}
	return &KubernetesStore{client: config.Client, namespace: config.Namespace, prefix: prefix, box: box}, nil
}

func (s *KubernetesStore) Put(ctx context.Context, secret Secret) (uint64, error) {
	if secret.ID == "" || secret.Provider == "" {
		return 0, domain.Invalidf("credentials.kubernetes", "credential id and provider are required")
	}
	record, err := s.sealRecord(secret, 1)
	if err != nil {
		return 0, err
	}
	_, err = s.client.CoreV1().Secrets(s.namespace).Create(ctx, s.secretObject(secret.ID, record), metav1.CreateOptions{})
	if err != nil {
		return 0, kubernetesError(err, "put")
	}
	return 1, nil
}

func (s *KubernetesStore) Get(ctx context.Context, id domain.CredentialID) (Secret, error) {
	record, _, err := s.read(ctx, id)
	if err != nil {
		return Secret{}, err
	}
	return s.open(record)
}

func (s *KubernetesStore) Rotate(ctx context.Context, id domain.CredentialID, material []byte, expiresAt time.Time) (Secret, error) {
	existing, object, err := s.read(ctx, id)
	if err != nil {
		return Secret{}, err
	}
	nonce, ciphertext, err := s.box.seal(material)
	if err != nil {
		return Secret{}, err
	}
	existing.Nonce = base64.StdEncoding.EncodeToString(nonce)
	existing.Ciphertext = base64.StdEncoding.EncodeToString(ciphertext)
	existing.Secret.Revision++
	existing.Secret.ExpiresAt = expiresAt
	encoded, err := json.Marshal(existing)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.kubernetes", "encode record")
	}
	object.Data = map[string][]byte{"record": encoded}
	if _, err := s.client.CoreV1().Secrets(s.namespace).Update(ctx, object, metav1.UpdateOptions{}); err != nil {
		return Secret{}, kubernetesError(err, "rotate")
	}
	return Secret{
		ID: existing.Secret.ID, Provider: existing.Secret.Provider, Material: append([]byte(nil), material...),
		Endpoint: existing.Secret.Endpoint, ExpiresAt: existing.Secret.ExpiresAt, Revision: existing.Secret.Revision,
	}, nil
}

func (s *KubernetesStore) Delete(ctx context.Context, id domain.CredentialID) error {
	err := s.client.CoreV1().Secrets(s.namespace).Delete(ctx, s.secretName(id), metav1.DeleteOptions{})
	if apierrors.IsNotFound(err) {
		return domain.Wrap(domain.ErrNotFound, "credentials.kubernetes", "credential not found")
	}
	if err != nil {
		return kubernetesError(err, "delete")
	}
	return nil
}

func (s *KubernetesStore) read(ctx context.Context, id domain.CredentialID) (encryptedRecord, *corev1.Secret, error) {
	object, err := s.client.CoreV1().Secrets(s.namespace).Get(ctx, s.secretName(id), metav1.GetOptions{})
	if err != nil {
		return encryptedRecord{}, nil, kubernetesError(err, "get")
	}
	encoded, exists := object.Data["record"]
	if !exists {
		return encryptedRecord{}, nil, domain.Invalidf("credentials.kubernetes", "secret record is missing")
	}
	var record encryptedRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		return encryptedRecord{}, nil, domain.Wrap(err, "credentials.kubernetes", "decode record")
	}
	return record, object, nil
}

func (s *KubernetesStore) sealRecord(secret Secret, revision uint64) (encryptedRecord, error) {
	nonce, ciphertext, err := s.box.seal(secret.Material)
	if err != nil {
		return encryptedRecord{}, err
	}
	return encryptedRecord{
		Nonce: base64.StdEncoding.EncodeToString(nonce), Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Secret: fileSecret{ID: secret.ID, Provider: secret.Provider, Endpoint: secret.Endpoint, ExpiresAt: secret.ExpiresAt, Revision: revision},
	}, nil
}

func (s *KubernetesStore) open(record encryptedRecord) (Secret, error) {
	nonce, err := base64.StdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.kubernetes", "decode nonce")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return Secret{}, domain.Wrap(err, "credentials.kubernetes", "decode ciphertext")
	}
	material, err := s.box.open(nonce, ciphertext)
	if err != nil {
		return Secret{}, err
	}
	return Secret{
		ID: record.Secret.ID, Provider: record.Secret.Provider, Material: material,
		Endpoint: record.Secret.Endpoint, ExpiresAt: record.Secret.ExpiresAt, Revision: record.Secret.Revision,
	}, nil
}

func (s *KubernetesStore) secretObject(id domain.CredentialID, record encryptedRecord) *corev1.Secret {
	encoded, _ := json.Marshal(record)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name: s.secretName(id), Namespace: s.namespace,
			Labels: map[string]string{"app.kubernetes.io/managed-by": "quarshell"},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{"record": encoded},
	}
}

func (s *KubernetesStore) secretName(id domain.CredentialID) string {
	base := strings.ToLower(string(id))
	var builder strings.Builder
	for _, char := range base {
		if (char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-' || char == '.' {
			builder.WriteRune(char)
		} else {
			builder.WriteByte('-')
		}
	}
	clean := strings.Trim(builder.String(), "-.")
	if clean == "" {
		clean = "credential"
	}
	sum := sha256.Sum256([]byte(id))
	suffix := hex.EncodeToString(sum[:4])
	maxBase := 253 - len(s.prefix) - len(suffix) - 1
	if maxBase < 1 {
		maxBase = 1
	}
	if len(clean) > maxBase {
		clean = strings.TrimRight(clean[:maxBase], "-.")
		if clean == "" {
			clean = "credential"
		}
	}
	return s.prefix + clean + "-" + suffix
}

func kubernetesError(err error, operation string) error {
	switch {
	case err == nil:
		return nil
	case apierrors.IsNotFound(err):
		return domain.Wrap(domain.ErrNotFound, "credentials.kubernetes", operation+": credential not found")
	case apierrors.IsAlreadyExists(err), apierrors.IsConflict(err):
		return domain.New(domain.CodeConflict, "credentials.kubernetes", operation+": credential version conflict")
	case apierrors.IsForbidden(err), apierrors.IsUnauthorized(err):
		return domain.Wrap(domain.ErrPermissionDenied, "credentials.kubernetes", operation+": access denied")
	default:
		return domain.New(domain.CodeUnavailable, "credentials.kubernetes", operation+": kubernetes API unavailable")
	}
}
