package credentialstore

import (
	"context"
	"os"
	"testing"
)

func TestSpiffeJWTSourceIntegrationLive(t *testing.T) {
	socket := os.Getenv("QUARSHELL_SPIFFE_SOCKET")
	if socket == "" {
		t.Skip("QUARSHELL_SPIFFE_SOCKET is not set")
	}
	source := &SpiffeJWTSource{Socket: socket}
	token, err := source.FetchJWTSVID(context.Background(), "test")
	if err != nil {
		t.Fatalf("FetchJWTSVID: %v", err)
	}
	if token.Value == "" || token.Audience != "test" {
		t.Fatalf("token = %+v", token)
	}
}
