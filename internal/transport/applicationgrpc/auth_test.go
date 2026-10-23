package applicationgrpc

import (
	"context"
	"net"
	"testing"
	"time"

	gatewayv1 "github.com/KLORQ/quarshell-proto/gen/go/openshell/gateway/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestUnaryAuthInterceptor(t *testing.T) {
	interceptor := UnaryAuthInterceptor("shared-secret", "gateway-client")
	method := gatewayv1.OpenShell_GetCurrentUser_FullMethodName
	request := &gatewayv1.GetCurrentUserRequest{}

	for _, test := range []struct {
		name    string
		md      metadata.MD
		want    codes.Code
		subject string
	}{
		{name: "missing", want: codes.Unauthenticated},
		{name: "wrong", md: metadata.Pairs("authorization", "Bearer wrong"), want: codes.Unauthenticated},
		{name: "malformed", md: metadata.Pairs("authorization", "shared-secret"), want: codes.Unauthenticated},
		{name: "duplicate", md: metadata.Pairs("authorization", "Bearer shared-secret", "authorization", "Bearer shared-secret"), want: codes.Unauthenticated},
		{name: "bearer", md: metadata.Pairs("authorization", "Bearer shared-secret"), want: codes.OK, subject: "gateway-client"},
		{name: "legacy header", md: metadata.Pairs("x-quarshell-token", "shared-secret"), want: codes.OK, subject: "gateway-client"},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.md != nil {
				ctx = metadata.NewIncomingContext(ctx, test.md)
			}
			response, err := interceptor(ctx, request, &grpc.UnaryServerInfo{FullMethod: method}, func(ctx context.Context, _ any) (any, error) {
				return serverForAuthTest().GetCurrentUser(ctx, request)
			})
			if got := status.Code(err); err == nil {
				got = codes.OK
				if test.want != got {
					t.Fatalf("status = %s, want %s", got, test.want)
				}
			} else if got != test.want {
				t.Fatalf("status = %s, want %s (%v)", got, test.want, err)
			}
			if test.subject != "" {
				currentUser := response.(*gatewayv1.GetCurrentUserResponse)
				if currentUser.GetSubject() != test.subject || currentUser.GetIdentityProvider() != "static-token" || len(currentUser.GetRoles()) != 1 || currentUser.GetRoles()[0] != "platform_admin" {
					t.Fatalf("GetCurrentUser = %+v", currentUser)
				}
			}
		})
	}

	response, err := interceptor(context.Background(), &gatewayv1.HealthRequest{}, &grpc.UnaryServerInfo{FullMethod: gatewayv1.OpenShell_Health_FullMethodName}, func(context.Context, any) (any, error) {
		return &gatewayv1.HealthResponse{Status: gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY}, nil
	})
	if err != nil || response.(*gatewayv1.HealthResponse).GetStatus() != gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY {
		t.Fatalf("unauthenticated Health response = %v, err=%v", response, err)
	}
}

func TestStreamAuthInterceptor(t *testing.T) {
	interceptor := StreamAuthInterceptor("shared-secret", "gateway-client")
	info := &grpc.StreamServerInfo{FullMethod: gatewayv1.OpenShell_PeerRelay_FullMethodName}
	var gotPrincipal authenticatedPrincipal
	handler := func(_ any, stream grpc.ServerStream) error {
		principal, ok := principalFromContext(stream.Context())
		if !ok {
			return status.Error(codes.Internal, "authenticated principal missing")
		}
		gotPrincipal = principal
		return nil
	}

	if err := interceptor(nil, fixtureServerStream{ctx: context.Background()}, info, handler); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated stream status = %s, want %s", status.Code(err), codes.Unauthenticated)
	}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer shared-secret"))
	if err := interceptor(nil, fixtureServerStream{ctx: ctx}, info, handler); err != nil {
		t.Fatalf("authenticated stream error = %v", err)
	}
	if gotPrincipal.subject != "gateway-client" || gotPrincipal.identityProvider != "static-token" {
		t.Fatalf("stream principal = %+v", gotPrincipal)
	}
}

func TestGetCurrentUserRequiresAuthenticatedPrincipal(t *testing.T) {
	server := serverForAuthTest()
	if _, err := server.GetCurrentUser(context.Background(), &gatewayv1.GetCurrentUserRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated GetCurrentUser status = %s, want %s", status.Code(err), codes.Unauthenticated)
	}
}

func TestRegisteredServerAuthenticatesUnaryCalls(t *testing.T) {
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer(
		grpc.UnaryInterceptor(UnaryAuthInterceptor("shared-secret", "gateway-client")),
		grpc.StreamInterceptor(StreamAuthInterceptor("shared-secret", "gateway-client")),
	)
	gatewayv1.RegisterOpenShellServer(grpcServer, serverForAuthTest())
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(func() {
		grpcServer.Stop()
		_ = listener.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	connection, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient() error = %v", err)
	}
	defer connection.Close()
	client := gatewayv1.NewOpenShellClient(connection)

	if health, err := client.Health(ctx, &gatewayv1.HealthRequest{}); err != nil || health.GetStatus() != gatewayv1.ServiceStatus_SERVICE_STATUS_HEALTHY {
		t.Fatalf("unauthenticated Health = %+v, err=%v", health, err)
	}
	if _, err := client.GetGatewayInfo(ctx, &gatewayv1.GetGatewayInfoRequest{}); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated GetGatewayInfo status = %s, want %s", status.Code(err), codes.Unauthenticated)
	}
	authenticated := metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer shared-secret")
	currentUser, err := client.GetCurrentUser(authenticated, &gatewayv1.GetCurrentUserRequest{})
	if err != nil || currentUser.GetSubject() != "gateway-client" || len(currentUser.GetRoles()) != 1 || currentUser.GetRoles()[0] != "platform_admin" {
		t.Fatalf("authenticated GetCurrentUser = %+v, err=%v", currentUser, err)
	}
	if info, err := client.GetGatewayInfo(authenticated, &gatewayv1.GetGatewayInfoRequest{}); err != nil || info.GetGatewayVersion() != "test" {
		t.Fatalf("authenticated GetGatewayInfo = %+v, err=%v", info, err)
	}
}

func serverForAuthTest() *Server {
	return New("test", nil, nil, nil, nil, nil, nil, nil)
}
