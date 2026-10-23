package credentialstore

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
)

func testRewriter(t *testing.T) (*Rewriter, *Broker, IssueRequest) {
	t.Helper()
	store, broker := newTestBroker(t, nil)
	secret := testSecret()
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	request := IssueRequest{Credential: "cred-1", Sandbox: domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, Endpoint: secret.Endpoint}
	handle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	request.StableKey = string(handle)
	return &Rewriter{Broker: broker}, broker, request
}

func TestRewriteBodyAndHeader(t *testing.T) {
	rewriter, _, request := testRewriter(t)
	input := []byte(`{"token":"` + Placeholder + `"}`)
	output, err := rewriter.Rewrite(context.Background(), Handle(request.StableKey), request.Endpoint, input, RewriteBody)
	if err != nil {
		t.Fatalf("Rewrite: %v", err)
	}
	if !strings.Contains(string(output), "super-secret-token") || strings.Contains(string(output), Placeholder) {
		t.Fatalf("output = %q", output)
	}
}

func TestRewriteRejectsHeaderInjection(t *testing.T) {
	store, broker := newTestBroker(t, nil)
	secret := testSecret()
	secret.Material = []byte("token\r\nX-Evil: 1")
	if _, err := store.Put(context.Background(), secret); err != nil {
		t.Fatalf("Put: %v", err)
	}
	request := IssueRequest{Credential: "cred-1", Sandbox: domain.SandboxRef{Workspace: "ws", Sandbox: "sb"}, Endpoint: secret.Endpoint}
	handle, _, err := broker.Issue(context.Background(), request)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	rewriter := &Rewriter{Broker: broker}
	_, err = rewriter.Rewrite(context.Background(), handle, secret.Endpoint, []byte("Authorization: "+Placeholder), RewriteHeader)
	if err == nil || strings.Contains(err.Error(), "token") {
		t.Fatalf("header rewrite error = %v", err)
	}
}

func TestRewriteRejectsWrongEndpointAndMissingPlaceholder(t *testing.T) {
	rewriter, _, request := testRewriter(t)
	wrong := request.Endpoint
	wrong.Host = "evil.example.com"
	if _, err := rewriter.Rewrite(context.Background(), Handle(request.StableKey), wrong, []byte(Placeholder), RewriteBody); !errors.Is(err, domain.ErrPermissionDenied) {
		t.Fatalf("wrong endpoint = %v", err)
	}
	if _, err := rewriter.Rewrite(context.Background(), Handle(request.StableKey), request.Endpoint, []byte("no token"), RewriteBody); err == nil {
		t.Fatalf("missing placeholder accepted")
	}
}

func TestRewriteBounds(t *testing.T) {
	rewriter, _, request := testRewriter(t)
	rewriter.MaxBodyBytes = 8
	if _, err := rewriter.Rewrite(context.Background(), Handle(request.StableKey), request.Endpoint, []byte(strings.Repeat("x", 16)), RewriteBody); err == nil {
		t.Fatalf("oversized request accepted")
	}
}
