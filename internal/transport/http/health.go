// Package httptransport maps application health to HTTP without leaking
// internal error details.
package httptransport

import (
	"encoding/json"
	"net/http"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/health"
)

// HealthHandler serves liveness, readiness, and capabilities.
type HealthHandler struct {
	service *health.Service
}

// NewHealthHandler creates an HTTP health handler.
func NewHealthHandler(service *health.Service) *HealthHandler {
	return &HealthHandler{service: service}
}

// ServeHTTP routes health requests.
func (h *HealthHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/healthz":
		writeJSON(writer, http.StatusOK, map[string]bool{"live": true})
	case "/readyz":
		status, err := h.service.Check(request.Context())
		if err != nil {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
				"live":  "true",
				"ready": "false",
				"error": domain.SafeMessage(err),
			})
			return
		}
		code := http.StatusOK
		if !status.Ready {
			code = http.StatusServiceUnavailable
		}
		writeJSON(writer, code, status)
	case "/capabilities":
		status, err := h.service.Check(request.Context())
		if err != nil {
			writeJSON(writer, http.StatusServiceUnavailable, map[string]string{
				"error": domain.SafeMessage(err),
			})
			return
		}
		writeJSON(writer, http.StatusOK, status)
	default:
		http.NotFound(writer, request)
	}
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}
