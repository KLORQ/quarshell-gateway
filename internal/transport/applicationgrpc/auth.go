package applicationgrpc

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/KLORQ/quarshell-core/domain"
	tokenapp "github.com/KLORQ/quarshell-gateway/internal/application/token"
	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type principalContextKey struct{}

type authenticatedPrincipal struct {
	subject          string
	identityProvider string
	roles            []string
	workspace        domain.WorkspaceID
	sandbox          domain.SandboxID
	generation       domain.Generation
	credentialEpoch  uint64
}

// UnaryAuthInterceptor authenticates gRPC calls with the gateway's configured
// static operator token. Health remains public for liveness probes.
func UnaryAuthInterceptor(token, principal string) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == gatewayv1.OpenShell_Health_FullMethodName {
			return handler(ctx, request)
		}
		authenticated, err := withAuthenticatedPrincipal(ctx, token, principal)
		if err != nil {
			return nil, err
		}
		return handler(authenticated, request)
	}
}

// StreamAuthInterceptor authenticates streaming gRPC calls with the same
// configured operator token. Streaming Health does not exist.
func StreamAuthInterceptor(token, principal string) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		authenticated, err := withAuthenticatedPrincipal(stream.Context(), token, principal)
		if err != nil {
			return err
		}
		return handler(server, principalServerStream{ServerStream: stream, ctx: authenticated})
	}
}

// UnaryAuthInterceptorWithSandboxTokens allows generation-bound sandbox
// credentials only on RPCs whose OpenShell authorization mode is "sandbox".
func UnaryAuthInterceptorWithSandboxTokens(operatorToken, operatorSubject string, tokens *tokenapp.Service) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if info.FullMethod == gatewayv1.OpenShell_Health_FullMethodName {
			return handler(ctx, request)
		}
		if authenticated, err := withAuthenticatedPrincipal(ctx, operatorToken, operatorSubject); err == nil {
			return handler(authenticated, request)
		}
		if tokens != nil && info.FullMethod == gatewayv1.OpenShell_RefreshSandboxToken_FullMethodName {
			if authenticated, err := withSandboxPrincipal(ctx, tokens); err == nil {
				return handler(authenticated, request)
			}
		}
		if tokens != nil && isSandboxUnaryMethod(info.FullMethod) {
			if authenticated, err := withSandboxProtocolPrincipal(ctx, tokens); err == nil {
				return handler(authenticated, request)
			}
		}
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
}

// StreamAuthInterceptorWithSandboxTokens permits sandbox bearers only on
// supervisor control and relay streams; all other streams require operator auth.
func StreamAuthInterceptorWithSandboxTokens(operatorToken, operatorSubject string, tokens *tokenapp.Service) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if authenticated, err := withAuthenticatedPrincipal(stream.Context(), operatorToken, operatorSubject); err == nil {
			return handler(server, principalServerStream{ServerStream: stream, ctx: authenticated})
		}
		method := info.FullMethod
		if tokens != nil && (method == gatewayv1.OpenShell_ConnectSupervisor_FullMethodName || method == gatewayv1.OpenShell_RelayStream_FullMethodName || method == gatewayv1.OpenShell_PushSandboxLogs_FullMethodName) {
			if authenticated, err := withSandboxProtocolPrincipal(stream.Context(), tokens); err == nil {
				return handler(server, principalServerStream{ServerStream: stream, ctx: authenticated})
			}
		}
		return status.Error(codes.Unauthenticated, "authentication required")
	}
}

func isSandboxUnaryMethod(method string) bool {
	switch method {
	case gatewayv1.OpenShell_ReportPolicyStatus_FullMethodName,
		gatewayv1.OpenShell_ReportMainProcessExit_FullMethodName,
		gatewayv1.OpenShell_FinalizeMainProcessExit_FullMethodName,
		gatewayv1.OpenShell_ReportEndpointStatus_FullMethodName,
		gatewayv1.OpenShell_ReportProviderReadiness_FullMethodName,
		gatewayv1.OpenShell_ReportSandboxConfiguration_FullMethodName,
		gatewayv1.OpenShell_GetSandboxProviderEnvironment_FullMethodName,
		gatewayv1.OpenShell_ExchangeProviderSubjectToken_FullMethodName:
		return true
	default:
		return false
	}
}

func withAuthenticatedPrincipal(ctx context.Context, expectedToken, subject string) (context.Context, error) {
	if expectedToken == "" || subject == "" || !validStaticCredential(ctx, expectedToken) {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	principal := authenticatedPrincipal{
		subject:          subject,
		identityProvider: "static-token",
		roles:            []string{"platform_admin"},
	}
	return context.WithValue(ctx, principalContextKey{}, principal), nil
}

func validStaticCredential(ctx context.Context, expected string) bool {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	if authorization := md.Get("authorization"); len(authorization) > 0 {
		if len(authorization) != 1 {
			return false
		}
		value := strings.TrimSpace(authorization[0])
		if len(value) <= len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(strings.TrimSpace(value[len("Bearer "):])), []byte(expected)) == 1
	}
	values := md.Get("x-quarshell-token")
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
}

func withSandboxPrincipal(ctx context.Context, tokens *tokenapp.Service) (context.Context, error) {
	return withSandboxPrincipalForAudience(ctx, tokens, "gateway")
}

func withSandboxProtocolPrincipal(ctx context.Context, tokens *tokenapp.Service) (context.Context, error) {
	return withSandboxPrincipalForAudience(ctx, tokens, "sandbox")
}

func withSandboxPrincipalForAudience(ctx context.Context, tokens *tokenapp.Service, audience string) (context.Context, error) {
	if tokens == nil {
		return nil, status.Error(codes.Unauthenticated, "sandbox authentication is unavailable")
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	values := md.Get("authorization")
	if len(values) != 1 {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	value := strings.TrimSpace(values[0])
	if len(value) <= len("Bearer ") || !strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
		return nil, status.Error(codes.Unauthenticated, "authentication required")
	}
	claims, err := tokens.Verify(strings.TrimSpace(value[len("Bearer "):]))
	if err != nil || claims.Generation == 0 || claims.Audience != audience {
		return nil, status.Error(codes.Unauthenticated, "invalid sandbox credential")
	}
	principal := authenticatedPrincipal{
		subject: claims.Subject, identityProvider: "sandbox-token",
		sandbox: claims.Sandbox, generation: claims.Generation,
		credentialEpoch: claims.CredentialEpoch,
	}
	return context.WithValue(ctx, principalContextKey{}, principal), nil
}

func sandboxPrincipalFromContext(ctx context.Context) (authenticatedPrincipal, bool) {
	principal, ok := principalFromContext(ctx)
	return principal, ok && principal.identityProvider == "sandbox-token" && principal.sandbox != "" && principal.generation != 0 && principal.credentialEpoch != 0
}

func principalFromContext(ctx context.Context) (authenticatedPrincipal, bool) {
	principal, ok := ctx.Value(principalContextKey{}).(authenticatedPrincipal)
	return principal, ok
}

type principalServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s principalServerStream) Context() context.Context { return s.ctx }
