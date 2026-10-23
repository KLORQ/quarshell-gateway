package token

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
)

func TestTokenIssueVerifyRefresh(t *testing.T) {
	service, err := NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	raw, claims, err := service.Issue(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, "alice", time.Minute)
	if err != nil || claims.Sandbox != "sb" || !strings.Contains(raw, ".") {
		t.Fatalf("Issue = %q %+v err=%v", raw, claims, err)
	}
	verified, err := service.Verify(raw)
	if err != nil || verified.Subject != SupervisorComponent || verified.TokenID != claims.TokenID || verified.Audience != "gateway" || verified.Workspace != "" {
		t.Fatalf("Verify = %+v err=%v", verified, err)
	}
	refreshed, next, err := service.RefreshForSandbox(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, raw, time.Minute)
	if err != nil || next.TokenID == claims.TokenID || refreshed == raw {
		t.Fatalf("Refresh = %q %+v err=%v", refreshed, next, err)
	}
	if _, err := service.Verify(raw + "x"); err == nil {
		t.Fatalf("tampered token accepted")
	}
}

func TestJWTMatchesOpenShellSessionClaimAndJOSEContract(t *testing.T) {
	service, err := NewServiceForGateway([]byte("0123456789abcdef0123456789abcdef"), "gateway-a", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "workspace-private", Sandbox: "sb-global"}
	raw, _, err := service.IssueForAudienceEpoch(ref, 42, 9, "gateway", "ignored", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d segments, want 3", len(parts))
	}
	decode := func(segment string, into any) {
		t.Helper()
		data, err := base64.RawURLEncoding.DecodeString(segment)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, into); err != nil {
			t.Fatal(err)
		}
	}
	var header map[string]any
	decode(parts[0], &header)
	if len(header) != 3 || header["alg"] != "EdDSA" || header["typ"] != GatewaySessionJWTType || header["kid"] != service.KeyID() {
		t.Fatalf("JOSE header=%v, not OpenShell Gateway profile", header)
	}
	var claims map[string]json.RawMessage
	decode(parts[1], &claims)
	want := []string{"iss", "sub", "aud", "iat", "exp", "jti", "sandbox_id", "runtime_generation", "auth_epoch", "component"}
	if len(claims) != len(want) {
		t.Fatalf("JWT claim set=%v, want exactly %v", claims, want)
	}
	for _, key := range want {
		if _, ok := claims[key]; !ok {
			t.Fatalf("JWT is missing upstream claim %q", key)
		}
	}
	for _, forbidden := range []string{"workspace", "generation", "credential_epoch", "token_id", "issued_at", "expires_at"} {
		if _, ok := claims[forbidden]; ok {
			t.Fatalf("JWT contains non-upstream claim %q", forbidden)
		}
	}
	verified, err := service.Verify(raw)
	if err != nil || verified.Sandbox != ref.Sandbox || verified.Generation != 42 || verified.CredentialEpoch != 9 || verified.Workspace != "" {
		t.Fatalf("verified JWT claims=%+v err=%v", verified, err)
	}
	publicPEM, err := service.VerificationKeyPEM()
	if err != nil || !strings.Contains(string(publicPEM), "BEGIN PUBLIC KEY") {
		t.Fatalf("verification key PEM=%q err=%v", publicPEM, err)
	}
}

func TestDefaultGatewayIssuerMatchesOpenShellConfig(t *testing.T) {
	service, err := NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, claims, err := service.Issue(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, "supervisor", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if got := service.OpenShellClaims(claims)["iss"]; got != "openshell-gateway:openshell" {
		t.Fatalf("default issuer=%v, want OpenShell default gateway ID", got)
	}
}

func TestStrictJSONRejectsDuplicateFields(t *testing.T) {
	var claims map[string]any
	if err := strictJSON([]byte(`{"aud":"openshell-sandbox","aud":"openshell-gateway:gateway"}`), &claims); err == nil {
		t.Fatal("strictJSON accepted duplicate JWT audience fields")
	}
}

func TestTokenRefreshPreservesSandboxGeneration(t *testing.T) {
	service, err := NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	raw, claims, err := service.IssueForGeneration(context.Background(), ref, 7, "supervisor", time.Minute)
	if err != nil {
		t.Fatalf("IssueForGeneration: %v", err)
	}
	if claims.Generation != 7 {
		t.Fatalf("issued generation = %d, want 7", claims.Generation)
	}
	_, refreshed, err := service.RefreshForSandbox(context.Background(), ref, raw, time.Minute)
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if refreshed.Generation != claims.Generation || refreshed.Sandbox != claims.Sandbox || refreshed.Workspace != ref.Workspace || refreshed.Audience != "gateway" {
		t.Fatalf("refreshed claims = %+v, want sandbox generation %d", refreshed, claims.Generation)
	}
}

func TestIssueForAudienceSeparatesGatewayAndSandboxTokens(t *testing.T) {
	service, err := NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	for _, audience := range []string{"gateway", "sandbox"} {
		raw, claims, err := service.IssueForAudience(ref, 4, audience, "supervisor", time.Minute)
		if err != nil {
			t.Fatalf("IssueForAudience(%q): %v", audience, err)
		}
		verified, err := service.Verify(raw)
		if err != nil || claims.Audience != audience || verified.Audience != audience || verified.Generation != 4 {
			t.Fatalf("audience=%q claims=%+v verified=%+v err=%v", audience, claims, verified, err)
		}
		refreshed, refreshClaims, err := service.RefreshForSandbox(context.Background(), ref, raw, time.Minute)
		if err != nil {
			t.Fatalf("Refresh(%q): %v", audience, err)
		}
		verifiedRefresh, err := service.Verify(refreshed)
		if err != nil || verifiedRefresh.Audience != audience || refreshClaims.Audience != audience {
			t.Fatalf("refreshed audience=%q claims=%+v verified=%+v err=%v", audience, refreshClaims, verifiedRefresh, err)
		}
	}
	if _, _, err := service.IssueForAudience(ref, 1, "other", "supervisor", time.Minute); err == nil {
		t.Fatal("unsupported audience accepted")
	}
}

func TestRefreshPreservesCredentialEpoch(t *testing.T) {
	service, err := NewService([]byte("0123456789abcdef"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	ref := domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}
	raw, claims, err := service.IssueForAudienceEpoch(ref, 4, 9, "gateway", "supervisor", time.Minute)
	if err != nil || claims.CredentialEpoch != 9 {
		t.Fatalf("IssueForAudienceEpoch claims=%+v err=%v", claims, err)
	}
	refreshed, next, err := service.RefreshForSandbox(context.Background(), ref, raw, time.Minute)
	if err != nil || next.CredentialEpoch != 9 {
		t.Fatalf("Refresh claims=%+v err=%v", next, err)
	}
	verified, err := service.Verify(refreshed)
	if err != nil || verified.CredentialEpoch != 9 {
		t.Fatalf("Verify refreshed claims=%+v err=%v", verified, err)
	}
	if _, _, err := service.IssueForAudienceEpoch(ref, 4, 0, "gateway", "supervisor", time.Minute); err == nil {
		t.Fatal("zero credential epoch was accepted")
	}
}

func TestTokenValidation(t *testing.T) {
	service, _ := NewService([]byte("0123456789abcdef"), time.Hour)
	if _, _, err := service.Issue(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, "", time.Minute); err == nil {
		t.Fatalf("empty subject accepted")
	}
	if _, _, err := service.Issue(context.Background(), domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, "alice", 25*time.Hour); err == nil {
		t.Fatalf("oversized ttl accepted")
	}
	if _, err := NewService([]byte("short"), time.Hour); err == nil {
		t.Fatalf("short key accepted")
	}
}
