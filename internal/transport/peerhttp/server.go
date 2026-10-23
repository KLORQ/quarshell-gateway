// Package peerhttp exposes peer ownership fencing over HTTP.
package peerhttp

import (
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-gateway/internal/application/peer"
)

// Server exposes peer ownership state.
type Server struct {
	Registry *peer.Registry
	Token    string
}

// New returns a peer transport server.
func New(registry *peer.Registry, token string) (*Server, error) {
	if registry == nil {
		return nil, domain.Invalidf("peerhttp.server", "registry is required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, domain.Invalidf("peerhttp.server", "token is required")
	}
	return &Server{Registry: registry, Token: token}, nil
}

// Handler returns the authenticated handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/peer/owner", s.owner)
	mux.HandleFunc("GET /v1/peer/peers", s.peers)
	mux.HandleFunc("POST /v1/peer/join", s.join)
	mux.HandleFunc("POST /v1/peer/claim", s.claim)
	mux.HandleFunc("POST /v1/peer/heartbeat", s.heartbeat)
	mux.HandleFunc("POST /v1/peer/release", s.release)
	mux.HandleFunc("POST /v1/peer/validate", s.validate)
	mux.HandleFunc("POST /v1/peer/relay", s.unavailable("peer relay"))
	mux.HandleFunc("POST /v1/peer/provider-readiness", s.unavailable("peer provider readiness"))
	mux.HandleFunc("POST /v1/peer/endpoint-status", s.unavailable("peer endpoint status"))
	mux.HandleFunc("GET /v1/peer/sandbox-provider-status", s.unavailable("peer sandbox provider status"))
	return s.authenticate(mux)
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value := strings.TrimSpace(request.Header.Get("Authorization"))
		if len(value) > len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
			value = strings.TrimSpace(value[len("Bearer "):])
		}
		if subtle.ConstantTimeCompare([]byte(value), []byte(s.Token)) != 1 {
			writeError(writer, domain.Wrap(domain.ErrUnauthorized, "peerhttp.auth", "authentication required"))
			return
		}
		next.ServeHTTP(writer, request)
	})
}

func (s *Server) unavailable(feature string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writeJSON(writer, http.StatusNotImplemented, map[string]string{"code": "unavailable", "message": feature + " is not configured"})
	}
}

func (s *Server) owner(writer http.ResponseWriter, _ *http.Request) {
	owner, ok := s.Registry.Owner()
	if !ok {
		writeError(writer, domain.Wrap(domain.ErrNotFound, "peerhttp.owner", "no gateway owner"))
		return
	}
	writeJSON(writer, http.StatusOK, owner)
}

func (s *Server) peers(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"peers": s.Registry.List()})
}

type peerRequest struct {
	ID         string `json:"id"`
	Endpoint   string `json:"endpoint"`
	Token      uint64 `json:"token"`
	TTLSeconds int64  `json:"ttl_seconds"`
}

func (s *Server) decodePeer(writer http.ResponseWriter, request *http.Request) (peerRequest, bool) {
	var body peerRequest
	request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil {
		writeError(writer, domain.Invalidf("peerhttp", "invalid request body"))
		return peerRequest{}, false
	}
	return body, true
}

func (s *Server) join(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.decodePeer(writer, request)
	if !ok {
		return
	}
	joined, err := s.Registry.Join(request.Context(), body.ID, body.Endpoint)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, joined)
}

func (s *Server) claim(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.decodePeer(writer, request)
	if !ok {
		return
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	claimed, err := s.Registry.Claim(request.Context(), body.ID, ttl)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, claimed)
}

func (s *Server) heartbeat(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.decodePeer(writer, request)
	if !ok {
		return
	}
	ttl := time.Duration(body.TTLSeconds) * time.Second
	renewed, err := s.Registry.Heartbeat(request.Context(), body.ID, body.Token, ttl)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, renewed)
}

func (s *Server) release(writer http.ResponseWriter, request *http.Request) {
	body, ok := s.decodePeer(writer, request)
	if !ok {
		return
	}
	if err := s.Registry.Release(request.Context(), body.ID, body.Token); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) validate(writer http.ResponseWriter, request *http.Request) {
	var body struct {
		ID    string `json:"id"`
		Token uint64 `json:"token"`
	}
	request.Body = http.MaxBytesReader(writer, request.Body, 1<<20)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&body); err != nil && err != io.EOF {
		writeError(writer, domain.Invalidf("peerhttp.validate", "invalid request body"))
		return
	}
	if err := s.Registry.Validate(body.ID, body.Token); err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"valid": true})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch domain.CodeOf(err) {
	case domain.CodeInvalid:
		status = http.StatusBadRequest
	case domain.CodeNotFound:
		status = http.StatusNotFound
	case domain.CodeConflict:
		status = http.StatusConflict
	case domain.CodeUnauthorized, domain.CodePermissionDenied:
		status = http.StatusUnauthorized
	}
	writeJSON(writer, status, map[string]string{"code": string(domain.CodeOf(err)), "message": domain.SafeMessage(err)})
}
