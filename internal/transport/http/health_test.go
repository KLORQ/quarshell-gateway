package httptransport

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/health"
	"github.com/KLORQ/quarshell-spi/compute"
)

type readyCompute struct{}

func (readyCompute) Describe(context.Context) (compute.Capabilities, error) {
	return compute.Capabilities{Backend: "test", Capabilities: domain.NewCapabilitySet(domain.CapExec)}, nil
}

func (readyCompute) Validate(context.Context, compute.CreateSpec) error { return nil }

func (readyCompute) Ensure(context.Context, compute.DesiredSandbox) (compute.ObservedSandbox, error) {
	return compute.ObservedSandbox{}, nil
}

func (readyCompute) Delete(context.Context, domain.SandboxRef) error { return nil }

func TestHealthHandler(t *testing.T) {
	handler := NewHealthHandler(health.New(readyCompute{}))
	for _, path := range []string{"/healthz", "/readyz", "/capabilities"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s: status = %d", path, response.Code)
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("%s: content type = %q", path, response.Header().Get("Content-Type"))
		}
	}
}

func TestHealthHandlerUnready(t *testing.T) {
	handler := NewHealthHandler(health.New(nil))
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d", response.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["ready"] != "false" || body["error"] == "" {
		t.Fatalf("body = %v", body)
	}
}
