// Package token issues OpenShell-compatible sandbox session JWTs.
package token

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

const (
	GatewaySessionJWTType  = "openshell-gateway-session+jwt"
	SandboxSessionJWTType  = "openshell-sandbox-session+jwt"
	SandboxSessionAudience = "openshell-sandbox"
	SupervisorComponent    = "openshell-supervisor"
	maxSessionTokenTTL     = time.Hour
	minSessionTokenTTL     = time.Minute
)

// Claims is the verified session identity plus local context. Workspace is
// intentionally not serialized: OpenShell session claims identify a globally
// unique sandbox ID and never include the Gateway's workspace model.
type Claims struct {
	Workspace       domain.WorkspaceID `json:"-"`
	Sandbox         domain.SandboxID   `json:"-"`
	Generation      domain.Generation  `json:"-"`
	CredentialEpoch uint64             `json:"-"`
	Audience        string             `json:"-"`
	Subject         string             `json:"-"`
	TokenID         string             `json:"-"`
	IssuedAt        time.Time          `json:"-"`
	ExpiresAt       time.Time          `json:"-"`
}

type jwtHeader struct {
	Algorithm string `json:"alg"`
	Type      string `json:"typ"`
	KeyID     string `json:"kid"`
}

type sessionClaims struct {
	Issuer            string `json:"iss"`
	Subject           string `json:"sub"`
	Audience          string `json:"aud"`
	IssuedAt          int64  `json:"iat"`
	ExpiresAt         int64  `json:"exp"`
	TokenID           string `json:"jti"`
	SandboxID         string `json:"sandbox_id"`
	RuntimeGeneration string `json:"runtime_generation"`
	AuthEpoch         uint64 `json:"auth_epoch"`
	Component         string `json:"component"`
}

// Service signs and verifies OpenShell v0.1.4 session tokens.
type Service struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
	gatewayID  string
	ttl        time.Duration
	now        func() time.Time
}

// NewService derives a stable Ed25519 key from the configured secret. The
// deterministic derivation preserves existing deployments while emitting the
// OpenShell EdDSA JWT profile. New deployments should use NewServiceForGateway
// with a dedicated session-signing secret.
func NewService(key []byte, ttl time.Duration) (*Service, error) {
	return NewServiceForGateway(key, "openshell", ttl)
}

// NewServiceForGateway creates a token issuer bound to one Gateway identity.
func NewServiceForGateway(key []byte, gatewayID string, ttl time.Duration) (*Service, error) {
	if len(key) < 16 {
		return nil, domain.Invalidf("token.service", "signing secret must be at least 16 bytes")
	}
	if strings.TrimSpace(gatewayID) == "" || strings.TrimSpace(gatewayID) != gatewayID || strings.ContainsAny(gatewayID, " \t\r\n") {
		return nil, domain.Invalidf("token.service", "gateway ID is invalid")
	}
	if ttl <= 0 {
		ttl = maxSessionTokenTTL
	}
	if ttl < minSessionTokenTTL || ttl > maxSessionTokenTTL {
		return nil, domain.Invalidf("token.service", "session token lifetime must be between 60 and 3600 seconds")
	}
	seed := sha256.Sum256(key)
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	return NewServiceWithEd25519Key(privateKey, "quarshell-session-v1", gatewayID, ttl)
}

// NewServiceWithEd25519Key accepts the PEM-derived Ed25519 private-key
// equivalent used by OpenShell deployments.
func NewServiceWithEd25519Key(privateKey ed25519.PrivateKey, keyID, gatewayID string, ttl time.Duration) (*Service, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, domain.Invalidf("token.service", "Ed25519 private key is invalid")
	}
	if strings.TrimSpace(keyID) == "" || strings.TrimSpace(keyID) != keyID || strings.ContainsAny(keyID, " \t\r\n") {
		return nil, domain.Invalidf("token.service", "key ID is invalid")
	}
	if strings.TrimSpace(gatewayID) == "" || strings.TrimSpace(gatewayID) != gatewayID || strings.ContainsAny(gatewayID, " \t\r\n") {
		return nil, domain.Invalidf("token.service", "gateway ID is invalid")
	}
	if ttl <= 0 {
		ttl = maxSessionTokenTTL
	}
	if ttl < minSessionTokenTTL || ttl > maxSessionTokenTTL {
		return nil, domain.Invalidf("token.service", "session token lifetime must be between 60 and 3600 seconds")
	}
	privateCopy := append(ed25519.PrivateKey(nil), privateKey...)
	publicCopy := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
	return &Service{privateKey: privateCopy, publicKey: publicCopy, keyID: keyID, gatewayID: gatewayID, ttl: ttl, now: time.Now}, nil
}

// VerificationKeyPEM returns the public key to install in the sandbox's
// immutable Gateway verification bundle.
func (s *Service) VerificationKeyPEM() ([]byte, error) {
	if s == nil || len(s.publicKey) != ed25519.PublicKeySize {
		return nil, domain.Invalidf("token.verification_key", "token service is not configured")
	}
	der, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func (s *Service) KeyID() string {
	if s == nil {
		return ""
	}
	return s.keyID
}

// GatewayID returns the stable OpenShell Gateway identity used as JWT issuer
// and audience. It is part of the sandbox boundary configuration.
func (s *Service) GatewayID() string {
	if s == nil {
		return ""
	}
	return s.gatewayID
}

// OpenShellClaims returns the exact signed claim values for an API response
// without adding the Gateway's workspace-only model.
func (s *Service) OpenShellClaims(claims Claims) map[string]any {
	_, audience, _ := s.profile(claims.Audience)
	return map[string]any{
		"iss":                "openshell-gateway:" + s.gatewayID,
		"sub":                "spiffe://openshell/sandbox/" + string(claims.Sandbox),
		"aud":                audience,
		"iat":                claims.IssuedAt.Unix(),
		"exp":                claims.ExpiresAt.Unix(),
		"jti":                claims.TokenID,
		"sandbox_id":         string(claims.Sandbox),
		"runtime_generation": fmt.Sprintf("g%016x", uint64(claims.Generation)),
		"auth_epoch":         claims.CredentialEpoch,
		"component":          SupervisorComponent,
	}
}

// Issue returns a short-lived Gateway session token for one sandbox.
func (s *Service) Issue(ctx context.Context, ref domain.SandboxRef, subject string, ttl time.Duration) (string, Claims, error) {
	return s.IssueForGeneration(ctx, ref, 1, subject, ttl)
}

// IssueForGeneration returns a Gateway-profile token bound to a runtime launch.
func (s *Service) IssueForGeneration(_ context.Context, ref domain.SandboxRef, generation domain.Generation, subject string, ttl time.Duration) (string, Claims, error) {
	return s.IssueForAudience(ref, generation, "gateway", subject, ttl)
}

// IssueForAudience returns a session token for Gateway or Sandbox Protocol.
func (s *Service) IssueForAudience(ref domain.SandboxRef, generation domain.Generation, audience, subject string, ttl time.Duration) (string, Claims, error) {
	return s.IssueForAudienceEpoch(ref, generation, 1, audience, subject, ttl)
}

// IssueForAudienceEpoch binds the token pair member to one runtime generation
// and durable authorization epoch.
func (s *Service) IssueForAudienceEpoch(ref domain.SandboxRef, generation domain.Generation, credentialEpoch uint64, audience, subject string, ttl time.Duration) (string, Claims, error) {
	if s == nil || !ref.Valid() || generation == 0 || credentialEpoch == 0 || strings.TrimSpace(subject) == "" {
		return "", Claims{}, domain.Invalidf("token.issue", "sandbox, runtime generation and auth epoch are required")
	}
	profileType, jwtAudience, err := s.profile(audience)
	if err != nil {
		return "", Claims{}, err
	}
	if ttl <= 0 {
		ttl = s.ttl
	}
	if ttl < minSessionTokenTTL || ttl > maxSessionTokenTTL {
		return "", Claims{}, domain.Invalidf("token.issue", "session token lifetime must be between 60 and 3600 seconds")
	}
	now := s.now().UTC().Truncate(time.Second)
	expires := now.Add(ttl)
	id, err := newUUID()
	if err != nil {
		return "", Claims{}, fmt.Errorf("generate session token ID: %w", err)
	}
	generationID := fmt.Sprintf("g%016x", uint64(generation))
	wireClaims := sessionClaims{
		Issuer:   "openshell-gateway:" + s.gatewayID,
		Subject:  "spiffe://openshell/sandbox/" + string(ref.Sandbox),
		Audience: jwtAudience, IssuedAt: now.Unix(), ExpiresAt: expires.Unix(),
		TokenID: id, SandboxID: string(ref.Sandbox), RuntimeGeneration: generationID,
		AuthEpoch: credentialEpoch, Component: SupervisorComponent,
	}
	headerBytes, err := json.Marshal(jwtHeader{Algorithm: "EdDSA", Type: profileType, KeyID: s.keyID})
	if err != nil {
		return "", Claims{}, err
	}
	claimsBytes, err := json.Marshal(wireClaims)
	if err != nil {
		return "", Claims{}, err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)
	token := unsigned + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.privateKey, []byte(unsigned)))
	return token, Claims{Workspace: ref.Workspace, Sandbox: ref.Sandbox, Generation: generation,
		CredentialEpoch: credentialEpoch, Audience: audience, Subject: SupervisorComponent, TokenID: id,
		IssuedAt: now, ExpiresAt: expires}, nil
}

// RefreshForSandbox refreshes a verified token after the caller resolved its
// globally unique sandbox ID to a trusted Gateway sandbox record.
func (s *Service) RefreshForSandbox(_ context.Context, ref domain.SandboxRef, raw string, ttl time.Duration) (string, Claims, error) {
	claims, err := s.Verify(raw)
	if err != nil {
		return "", Claims{}, err
	}
	if claims.Sandbox != ref.Sandbox {
		return "", Claims{}, domain.New(domain.CodeUnauthorized, "token.refresh", "sandbox token belongs to another sandbox")
	}
	return s.IssueForAudienceEpoch(ref, claims.Generation, claims.CredentialEpoch, claims.Audience, claims.Subject, ttl)
}

// Verify validates JOSE header, EdDSA signature, strict OpenShell claims,
// profile, issuer, subject, epoch, runtime generation and temporal bounds.
func (s *Service) Verify(raw string) (Claims, error) {
	unauthorized := func(message string) (Claims, error) {
		return Claims{}, domain.New(domain.CodeUnauthorized, "token.verify", message)
	}
	if s == nil {
		return unauthorized("token service is not configured")
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return unauthorized("malformed JWT")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return unauthorized("invalid JWT header")
	}
	var header jwtHeader
	if err := strictJSON(headerBytes, &header); err != nil || header.Algorithm != "EdDSA" || header.KeyID != s.keyID {
		return unauthorized("invalid JWT header profile")
	}
	var audience string
	switch header.Type {
	case GatewaySessionJWTType:
		audience = "gateway"
	case SandboxSessionJWTType:
		audience = "sandbox"
	default:
		return unauthorized("unsupported session JWT type")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(s.publicKey, []byte(parts[0]+"."+parts[1]), signature) {
		return unauthorized("invalid JWT signature")
	}
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return unauthorized("invalid JWT claims encoding")
	}
	var wire sessionClaims
	if err := strictJSON(claimsBytes, &wire); err != nil {
		return unauthorized("invalid OpenShell session claims")
	}
	if wire.Issuer != "openshell-gateway:"+s.gatewayID || wire.Component != SupervisorComponent || wire.AuthEpoch == 0 || wire.Audience != s.jwtAudience(audience) || wire.Subject != "spiffe://openshell/sandbox/"+wire.SandboxID {
		return unauthorized("OpenShell session claims do not match issuer or profile")
	}
	generation, ok := parseRuntimeGeneration(wire.RuntimeGeneration)
	if !ok || !canonicalUUID(wire.TokenID) || wire.SandboxID == "" || strings.TrimSpace(wire.SandboxID) != wire.SandboxID {
		return unauthorized("invalid OpenShell runtime identity")
	}
	if wire.IssuedAt > s.now().Unix()+30 || (wire.ExpiresAt != 0 && (wire.ExpiresAt <= wire.IssuedAt || wire.ExpiresAt-wire.IssuedAt > int64(maxSessionTokenTTL.Seconds()) || wire.ExpiresAt < s.now().Unix()-30)) {
		return unauthorized("session token lifetime is invalid or expired")
	}
	return Claims{Sandbox: domain.SandboxID(wire.SandboxID), Generation: generation,
		CredentialEpoch: wire.AuthEpoch, Audience: audience, Subject: SupervisorComponent,
		TokenID: wire.TokenID, IssuedAt: time.Unix(wire.IssuedAt, 0).UTC(), ExpiresAt: time.Unix(wire.ExpiresAt, 0).UTC()}, nil
}

func (s *Service) profile(audience string) (string, string, error) {
	if audience != "gateway" && audience != "sandbox" {
		return "", "", domain.Invalidf("token.issue", "unsupported session profile")
	}
	profileType, jwtAudience := GatewaySessionJWTType, "openshell-gateway:"+s.gatewayID
	if audience == "sandbox" {
		profileType, jwtAudience = SandboxSessionJWTType, SandboxSessionAudience
	}
	return profileType, jwtAudience, nil
}

func (s *Service) jwtAudience(profile string) string {
	if profile == "sandbox" {
		return SandboxSessionAudience
	}
	return "openshell-gateway:" + s.gatewayID
}

func strictJSON(raw []byte, value any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

// rejectDuplicateJSONKeys matches serde's duplicate-field rejection. Go's
// encoding/json otherwise silently keeps the last value, which can make two
// verifiers interpret a signed JWT differently.
func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value")
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("JSON object repeats field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return fmt.Errorf("JSON object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return fmt.Errorf("JSON array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func parseRuntimeGeneration(value string) (domain.Generation, bool) {
	if len(value) != 17 || value[0] != 'g' || strings.ToLower(value) != value {
		return 0, false
	}
	n, err := hex.DecodeString(value[1:])
	if err != nil || len(n) != 8 {
		return 0, false
	}
	var generation uint64
	for _, b := range n {
		generation = generation<<8 | uint64(b)
	}
	return domain.Generation(generation), generation != 0
}

func canonicalUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' || strings.ToLower(value) != value {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	decoded, err := hex.DecodeString(compact)
	return err == nil && len(decoded) == 16 && decoded[6]&0xf0 == 0x40 && decoded[8]&0xc0 == 0x80
}

func newUUID() (string, error) {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	encoded := hex.EncodeToString(value[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}
