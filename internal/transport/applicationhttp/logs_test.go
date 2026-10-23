package applicationhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/lifecycle"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

func TestLogsHTTP(t *testing.T) {
	store := lifecycle.NewMemoryStore()
	workspaces, _ := workspace.NewService(store)
	sandboxes, _ := sandbox.NewService(store)
	server, _ := New(workspaces, sandboxes, "secret")
	server.Logs = func(context.Context, domain.SandboxRef) (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("line one\nline two\n")), nil
	}
	httpServer := httptest.NewServer(server.Handler())
	defer httpServer.Close()
	request, _ := http.NewRequest(http.MethodGet, httpServer.URL+"/v1/workspaces/ws/sandboxes/sb/logs", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("logs: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "line two") {
		t.Fatalf("logs = %d %q", response.StatusCode, body)
	}
}
