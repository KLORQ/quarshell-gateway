// Package applicationhttp exposes the new application use cases over HTTP.
package applicationhttp

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/KLORQ/quarshell-core/domain"
	"github.com/KLORQ/quarshell-credentials"
	"github.com/KLORQ/quarshell-gateway/internal/application/endpoint"
	"github.com/KLORQ/quarshell-gateway/internal/application/eventlog"
	policyapp "github.com/KLORQ/quarshell-gateway/internal/application/policy"
	"github.com/KLORQ/quarshell-gateway/internal/application/provider"
	"github.com/KLORQ/quarshell-gateway/internal/application/quota"
	"github.com/KLORQ/quarshell-gateway/internal/application/sandbox"
	"github.com/KLORQ/quarshell-gateway/internal/application/secrets"
	"github.com/KLORQ/quarshell-gateway/internal/application/settings"
	"github.com/KLORQ/quarshell-gateway/internal/application/template"
	"github.com/KLORQ/quarshell-gateway/internal/application/token"
	"github.com/KLORQ/quarshell-gateway/internal/application/workspace"
)

// Server maps HTTP requests to application use cases.
type Server struct {
	Workspaces   *workspace.Service
	Sandboxes    *sandbox.Service
	Token        string
	MaxBodyBytes int64
	Events       eventlog.Log
	Policies     *policyapp.Service
	PolicyChunks *policyapp.ChunkService
	Settings     *settings.Service
	Templates    *template.Service
	Quotas       *quota.Service
	Providers    *provider.Service
	ProviderDefs *provider.Registry
	Services     *endpoint.ServiceRegistry
	Forwards     *endpoint.ForwardRegistry
	Secrets      *secrets.Service
	Tokens       *token.Service
	Logs         func(context.Context, domain.SandboxRef) (io.ReadCloser, error)
	PTY          func(context.Context, domain.SandboxRef, uint32, uint32) (io.ReadWriteCloser, error)
	GatewayName  string
	Capabilities []string
	Principal    string
}

// New returns a transport server. A non-empty bearer token is required.
func New(workspaces *workspace.Service, sandboxes *sandbox.Service, token string) (*Server, error) {
	if workspaces == nil || sandboxes == nil {
		return nil, domain.Invalidf("http.server", "workspace and sandbox services are required")
	}
	if strings.TrimSpace(token) == "" {
		return nil, domain.Invalidf("http.server", "bearer token is required")
	}
	return &Server{Workspaces: workspaces, Sandboxes: sandboxes, Token: token, MaxBodyBytes: 1 << 20}, nil
}

// Handler returns the authenticated HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/workspaces", s.createWorkspace)
	mux.HandleFunc("GET /v1/workspaces", s.listWorkspaces)
	mux.HandleFunc("GET /v1/workspaces/{workspace}", s.getWorkspace)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}", s.deleteWorkspace)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes", s.createSandbox)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/start", s.startSandbox)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/stop", s.stopSandbox)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/exec", s.runtimeUnavailable("exec"))
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/ssh", s.runtimeUnavailable("ssh"))
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/streams/{stream}", s.runtimeUnavailable("stream"))
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/logs", s.streamLogs)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/pty", s.streamPTY)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes", s.listSandboxes)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}", s.getSandbox)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/sandboxes/{sandbox}", s.deleteSandbox)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/events", s.policyEvents)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/drafts", s.createPolicyDraft)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/active", s.activePolicy)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/history", s.policyHistory)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/draft", s.getPolicyDraft)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/draft/chunks", s.editPolicyChunk)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/draft/chunks/{chunk}/approve", s.approvePolicyChunk)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/draft/chunks/{chunk}/reject", s.rejectPolicyChunk)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/draft/chunks/{chunk}/undo", s.undoPolicyChunk)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/draft/approve-all", s.approveAllPolicyChunks)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/policies/draft/chunks", s.clearPolicyChunks)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/draft/history", s.policyChunkHistory)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/{revision}/approve", s.approvePolicy)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/{revision}/reject", s.rejectPolicy)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/policies/{revision}/observe", s.observePolicy)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/policies/{revision}/analysis", s.analyzePolicy)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/settings", s.listSettings)
	mux.HandleFunc("PUT /v1/workspaces/{workspace}/settings/{key}", s.setSetting)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/settings/{key}", s.getSetting)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/settings/{key}", s.deleteSetting)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/templates", s.createTemplate)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/templates", s.listTemplates)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/templates/{template}", s.getTemplate)
	mux.HandleFunc("PUT /v1/workspaces/{workspace}/templates/{template}", s.updateTemplate)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/templates/{template}", s.deleteTemplate)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/quota", s.getQuota)
	mux.HandleFunc("PUT /v1/workspaces/{workspace}/quota", s.setQuota)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/quota/check", s.checkQuota)
	mux.HandleFunc("GET /v1/providers", s.listProviderDefs)
	mux.HandleFunc("POST /v1/providers", s.createProviderDef)
	mux.HandleFunc("GET /v1/providers/{provider}", s.getProviderDef)
	mux.HandleFunc("PUT /v1/providers/{provider}", s.updateProviderDef)
	mux.HandleFunc("DELETE /v1/providers/{provider}", s.deleteProviderDef)
	mux.HandleFunc("GET /v1/providers/{provider}/profiles", s.listProviderProfiles)
	mux.HandleFunc("POST /v1/providers/{provider}/profiles", s.importProviderProfiles)
	mux.HandleFunc("POST /v1/providers/{provider}/profiles/lint", s.lintProviderProfiles)
	mux.HandleFunc("GET /v1/providers/{provider}/profiles/{profile}", s.getProviderProfile)
	mux.HandleFunc("DELETE /v1/providers/{provider}/profiles/{profile}", s.deleteProviderProfile)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers", s.bindProvider)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers", s.listProviders)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers/{provider}", s.getProvider)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers/{provider}/ack", s.ackProvider)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers/{provider}/fail", s.failProvider)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/sandboxes/{sandbox}/providers/{provider}", s.unbindProvider)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/services", s.exposeService)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/services", s.listServices)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/services/{service}", s.getService)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/sandboxes/{sandbox}/services/{service}", s.deleteService)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/forwards", s.createForward)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/forwards", s.listForwards)
	mux.HandleFunc("GET /v1/workspaces/{workspace}/sandboxes/{sandbox}/forwards/{forward}", s.getForward)
	mux.HandleFunc("DELETE /v1/workspaces/{workspace}/sandboxes/{sandbox}/forwards/{forward}", s.deleteForward)
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /v1/healthz", s.health)
	mux.HandleFunc("GET /v1/gateway/info", s.gatewayInfo)
	mux.HandleFunc("GET /v1/whoami", s.whoami)
	mux.HandleFunc("GET /v1/events", s.genericEvents)
	mux.HandleFunc("POST /v1/workspaces/{workspace}/sandboxes/{sandbox}/tokens", s.issueSandboxToken)
	mux.HandleFunc("POST /v1/tokens/refresh", s.refreshSandboxToken)
	mux.HandleFunc("POST /v1/credentials", s.createCredential)
	mux.HandleFunc("GET /v1/credentials/{credential}", s.getCredential)
	mux.HandleFunc("DELETE /v1/credentials/{credential}", s.deleteCredential)
	mux.HandleFunc("POST /v1/credentials/{credential}/rotate", s.rotateCredential)
	mux.HandleFunc("POST /v1/credentials/{credential}/handles", s.issueHandle)
	mux.HandleFunc("DELETE /v1/handles/{handle}", s.revokeHandle)
	return s.authenticate(mux)
}

func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet && (request.URL.Path == "/healthz" || request.URL.Path == "/v1/healthz") {
			next.ServeHTTP(writer, request)
			return
		}
		value := request.Header.Get("Authorization")
		if value == "" {
			value = request.Header.Get("X-Quarshell-Token")
		}
		value = strings.TrimSpace(value)
		if len(value) > len("Bearer ") && strings.EqualFold(value[:len("Bearer ")], "Bearer ") {
			value = strings.TrimSpace(value[len("Bearer "):])
		}
		if subtle.ConstantTimeCompare([]byte(value), []byte(s.Token)) != 1 {
			writer.Header().Set("WWW-Authenticate", "Bearer")
			writeError(writer, domain.Wrap(domain.ErrUnauthorized, "http.auth", "authentication required"))
			return
		}
		next.ServeHTTP(writer, request)
	})
}

type createWorkspaceRequest struct {
	ID     string            `json:"id"`
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels"`
	Owner  string            `json:"owner"`
}

func (s *Server) createWorkspace(writer http.ResponseWriter, request *http.Request) {
	var body createWorkspaceRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	created, replayed, err := s.Workspaces.Create(request.Context(), workspace.CreateRequest{
		ID: domain.WorkspaceID(body.ID), Name: body.Name, Labels: body.Labels, Owner: body.Owner,
		IdempotencyKey: domain.OperationID(request.Header.Get("Idempotency-Key")),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, created)
}

func (s *Server) getWorkspace(writer http.ResponseWriter, request *http.Request) {
	found, err := s.Workspaces.Get(request.Context(), domain.WorkspaceID(request.PathValue("workspace")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, found)
}

func (s *Server) listWorkspaces(writer http.ResponseWriter, request *http.Request) {
	items, err := s.Workspaces.List(request.Context())
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"workspaces": items})
}

func (s *Server) deleteWorkspace(writer http.ResponseWriter, request *http.Request) {
	if err := s.Workspaces.Delete(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type createSandboxRequest struct {
	ID               string            `json:"id"`
	Generation       uint64            `json:"generation"`
	Image            string            `json:"image"`
	Command          []string          `json:"command"`
	TTY              bool              `json:"tty"`
	Resources        sandbox.Resources `json:"resources"`
	Network          sandbox.Network   `json:"network"`
	Labels           map[string]string `json:"labels"`
	DriverConfigJSON string            `json:"driver_config_json,omitempty"`
}

func (s *Server) createSandbox(writer http.ResponseWriter, request *http.Request) {
	var body createSandboxRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	created, replayed, err := s.Sandboxes.Create(request.Context(), sandbox.Request{
		Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(body.ID),
		Generation: domain.Generation(body.Generation), Image: body.Image, Command: body.Command, TTY: body.TTY,
		Resources: body.Resources, Network: body.Network, Labels: body.Labels, DriverConfigJSON: body.DriverConfigJSON,
		IdempotencyKey: domain.OperationID(request.Header.Get("Idempotency-Key")),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, created)
}

type sandboxLifecycleRequest struct {
	Generation     uint64 `json:"generation"`
	IdempotencyKey string `json:"idempotency_key"`
}

func (s *Server) startSandbox(writer http.ResponseWriter, request *http.Request) {
	s.sandboxLifecycle(writer, request, "start")
}

func (s *Server) stopSandbox(writer http.ResponseWriter, request *http.Request) {
	s.sandboxLifecycle(writer, request, "stop")
}

func (s *Server) streamLogs(writer http.ResponseWriter, request *http.Request) {
	if s.Logs == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.logs", "log runtime is not configured"))
		return
	}
	ref := domain.SandboxRef{Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(request.PathValue("sandbox"))}
	stream, err := s.Logs(request.Context(), ref)
	if err != nil {
		writeError(writer, err)
		return
	}
	defer stream.Close()
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, _ = io.Copy(writer, stream)
}

func (s *Server) streamPTY(writer http.ResponseWriter, request *http.Request) {
	if s.PTY == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.pty", "pty runtime is not configured"))
		return
	}
	columns := parseUint32(request.URL.Query().Get("cols"), 80)
	rows := parseUint32(request.URL.Query().Get("rows"), 24)
	ref := domain.SandboxRef{Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(request.PathValue("sandbox"))}
	terminal, err := s.PTY(request.Context(), ref, columns, rows)
	if err != nil {
		writeError(writer, err)
		return
	}
	defer terminal.Close()
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.pty", "hijacking is unavailable"))
		return
	}
	connection, buffer, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer connection.Close()
	_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = buffer.Flush()
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(terminal, connection); done <- struct{}{} }()
	go func() { _, _ = io.Copy(connection, terminal); done <- struct{}{} }()
	<-done
}

func parseUint32(value string, fallback uint32) uint32 {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseUint(value, 10, 32)
	if err != nil || parsed == 0 {
		return fallback
	}
	return uint32(parsed)
}

func (s *Server) runtimeUnavailable(feature string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusNotImplemented)
		_ = json.NewEncoder(writer).Encode(map[string]string{"code": "unavailable", "message": feature + " runtime is not configured"})
	}
}

func (s *Server) sandboxLifecycle(writer http.ResponseWriter, request *http.Request, operation string) {
	if s.Sandboxes == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.sandbox", "sandbox service is not configured"))
		return
	}
	var body sandboxLifecycleRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	ref := domain.SandboxRef{Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(request.PathValue("sandbox"))}
	var (
		result   sandbox.Sandbox
		replayed bool
		err      error
	)
	if operation == "start" {
		result, replayed, err = s.Sandboxes.Start(request.Context(), ref, domain.Generation(body.Generation), domain.OperationID(body.IdempotencyKey))
	} else {
		result, replayed, err = s.Sandboxes.Stop(request.Context(), ref, domain.Generation(body.Generation), domain.OperationID(body.IdempotencyKey))
	}
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"sandbox": result, "replayed": replayed})
}

func (s *Server) getSandbox(writer http.ResponseWriter, request *http.Request) {
	found, err := s.Sandboxes.Get(request.Context(), sandboxRef(request))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, found)
}

func (s *Server) listSandboxes(writer http.ResponseWriter, request *http.Request) {
	items, err := s.Sandboxes.List(request.Context(), domain.WorkspaceID(request.PathValue("workspace")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"sandboxes": items})
}

func (s *Server) deleteSandbox(writer http.ResponseWriter, request *http.Request) {
	if err := s.Sandboxes.Delete(request.Context(), sandboxRef(request), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) policyEvents(writer http.ResponseWriter, request *http.Request) {
	if s.Events == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.events", "event stream is not configured"))
		return
	}
	scope := policyapp.Scope{
		Workspace: domain.WorkspaceID(request.PathValue("workspace")),
		Sandbox:   domain.SandboxID(request.URL.Query().Get("sandbox")),
	}
	if !scope.Valid() {
		writeError(writer, domain.Invalidf("http.events", "scope is invalid"))
		return
	}
	cursor := eventlog.Cursor(request.Header.Get("Last-Event-ID"))
	if cursor == "" {
		cursor = eventlog.Cursor(request.URL.Query().Get("cursor"))
	}
	if _, _, err := s.Events.After(request.Context(), cursor, 1); err != nil {
		if errors.Is(err, eventlog.ErrCursorLost) {
			writeError(writer, domain.New(domain.CodeConflict, "http.events", "cursor is no longer retained"))
			return
		}
		writeError(writer, err)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.events", "streaming is unavailable"))
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.Header().Set("Connection", "keep-alive")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, _, err := s.Events.After(request.Context(), cursor, 100)
		if err != nil {
			if errors.Is(err, eventlog.ErrCursorLost) {
				_, _ = fmt.Fprintf(writer, "event: error\ndata: {\"code\":\"cursor_lost\"}\n\n")
				flusher.Flush()
			}
			return
		}
		if len(events) > 0 {
			for _, event := range events {
				payload, err := json.Marshal(event)
				if err != nil {
					continue
				}
				_, _ = fmt.Fprintf(writer, "id: %d\ndata: %s\n\n", event.ID, payload)
				cursor = eventlog.Cursor(strconv.FormatUint(event.ID, 10))
			}
			flusher.Flush()
			continue
		}
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func policyScope(request *http.Request, sandbox string) policyapp.Scope {
	return policyapp.Scope{Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(sandbox)}
}

type policyDraftRequest struct {
	Sandbox string `json:"sandbox"`
	Source  string `json:"source"`
	Author  string `json:"author"`
}

func (s *Server) createPolicyDraft(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	var body policyDraftRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	revision, replayed, err := s.Policies.CreateDraft(request.Context(), policyapp.DraftRequest{
		Scope: policyScope(request, body.Sandbox), Source: []byte(body.Source), Author: body.Author,
		IdempotencyKey: domain.OperationID(request.Header.Get("Idempotency-Key")),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, revision)
}

type policyApprovalRequest struct {
	Sandbox  string `json:"sandbox"`
	Approver string `json:"approver"`
	Reason   string `json:"reason"`
}

func (s *Server) approvePolicy(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	var body policyApprovalRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	revision, err := s.Policies.Approve(request.Context(), policyScope(request, body.Sandbox), request.PathValue("revision"), body.Approver, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, revision)
}

func (s *Server) rejectPolicy(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	var body policyApprovalRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	revision, err := s.Policies.Reject(request.Context(), policyScope(request, body.Sandbox), request.PathValue("revision"), body.Approver, body.Reason)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, revision)
}

type policyObserveRequest struct {
	Sandbox    string `json:"sandbox"`
	Generation uint64 `json:"generation"`
}

func (s *Server) observePolicy(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	var body policyObserveRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	revision, err := s.Policies.Observe(request.Context(), policyScope(request, body.Sandbox), request.PathValue("revision"), domain.Generation(body.Generation))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, revision)
}

func (s *Server) activePolicy(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	revision, found, err := s.Policies.Active(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"found": found, "revision": revision})
}

type policyChunkRequest struct {
	Sandbox        string `json:"sandbox"`
	ID             string `json:"id"`
	Index          int    `json:"index"`
	Source         string `json:"source"`
	Author         string `json:"author"`
	Approver       string `json:"approver"`
	Reason         string `json:"reason"`
	IdempotencyKey string `json:"idempotency_key"`
}

func (s *Server) policyChunks(writer http.ResponseWriter) bool {
	if s.PolicyChunks == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy chunks are not configured"))
		return false
	}
	return true
}

func (s *Server) getPolicyDraft(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	draft, err := s.PolicyChunks.GetDraft(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, draft)
}

func (s *Server) editPolicyChunk(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	var body policyChunkRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	chunk, err := s.PolicyChunks.Edit(request.Context(), policyScope(request, body.Sandbox), body.ID, body.Index, []byte(body.Source), body.Author, domain.OperationID(body.IdempotencyKey))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, chunk)
}

func (s *Server) approvePolicyChunk(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	var body policyChunkRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	chunk, err := s.PolicyChunks.Approve(request.Context(), policyScope(request, body.Sandbox), request.PathValue("chunk"), body.Approver)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, chunk)
}

func (s *Server) rejectPolicyChunk(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	var body policyChunkRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	chunk, err := s.PolicyChunks.Reject(request.Context(), policyScope(request, body.Sandbox), request.PathValue("chunk"), body.Approver, body.Reason)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, chunk)
}

func (s *Server) undoPolicyChunk(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	var body policyChunkRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	chunk, err := s.PolicyChunks.Undo(request.Context(), policyScope(request, body.Sandbox), request.PathValue("chunk"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, chunk)
}

func (s *Server) approveAllPolicyChunks(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	var body policyChunkRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	draft, err := s.PolicyChunks.ApproveAll(request.Context(), policyScope(request, body.Sandbox), body.Approver)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"draft": draft, "source": string(draft.Source())})
}

func (s *Server) clearPolicyChunks(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	if err := s.PolicyChunks.Clear(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) policyChunkHistory(writer http.ResponseWriter, request *http.Request) {
	if !s.policyChunks(writer) {
		return
	}
	revisions, history, err := s.PolicyChunks.History(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"revisions": revisions, "chunks": history})
}

func (s *Server) policyHistory(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	revisions, err := s.Policies.List(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"revisions": revisions})
}

func (s *Server) analyzePolicy(writer http.ResponseWriter, request *http.Request) {
	if s.Policies == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.policy", "policy service is not configured"))
		return
	}
	analysis, err := s.Policies.Analyze(request.Context(), policyScope(request, request.URL.Query().Get("sandbox")), request.PathValue("revision"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, analysis)
}

type settingRequest struct {
	Value           string `json:"value"`
	ExpectedVersion uint64 `json:"expected_version"`
}

func (s *Server) setSetting(writer http.ResponseWriter, request *http.Request) {
	if s.Settings == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.settings", "settings service is not configured"))
		return
	}
	var body settingRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	setting, replayed, err := s.Settings.Set(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("key"), []byte(body.Value), body.ExpectedVersion, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed || body.ExpectedVersion > 0 {
		status = http.StatusOK
	}
	writeJSON(writer, status, settingResponse(setting))
}

func settingResponse(setting settings.Setting) map[string]any {
	return map[string]any{
		"workspace": setting.Workspace, "key": setting.Key, "value": string(setting.Value),
		"version": setting.Version, "updated_at": setting.UpdatedAt,
	}
}

func (s *Server) getSetting(writer http.ResponseWriter, request *http.Request) {
	if s.Settings == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.settings", "settings service is not configured"))
		return
	}
	setting, err := s.Settings.Get(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("key"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, settingResponse(setting))
}

func (s *Server) listSettings(writer http.ResponseWriter, request *http.Request) {
	if s.Settings == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.settings", "settings service is not configured"))
		return
	}
	items, err := s.Settings.List(request.Context(), domain.WorkspaceID(request.PathValue("workspace")))
	if err != nil {
		writeError(writer, err)
		return
	}
	response := make([]map[string]any, 0, len(items))
	for _, item := range items {
		response = append(response, settingResponse(item))
	}
	writeJSON(writer, http.StatusOK, map[string]any{"settings": response})
}

func (s *Server) deleteSetting(writer http.ResponseWriter, request *http.Request) {
	if s.Settings == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.settings", "settings service is not configured"))
		return
	}
	if err := s.Settings.Delete(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("key"), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type templateRequest struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Spec     json.RawMessage `json:"spec"`
	Revision uint64          `json:"revision"`
}

func (s *Server) createTemplate(writer http.ResponseWriter, request *http.Request) {
	if s.Templates == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.templates", "template service is not configured"))
		return
	}
	var body templateRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	created, replayed, err := s.Templates.Create(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), body.ID, body.Name, body.Spec, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, created)
}

func (s *Server) updateTemplate(writer http.ResponseWriter, request *http.Request) {
	if s.Templates == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.templates", "template service is not configured"))
		return
	}
	var body templateRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	updated, err := s.Templates.Update(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("template"), body.Name, body.Spec, body.Revision, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, updated)
}

func (s *Server) getTemplate(writer http.ResponseWriter, request *http.Request) {
	if s.Templates == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.templates", "template service is not configured"))
		return
	}
	item, err := s.Templates.Get(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("template"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, item)
}

func (s *Server) listTemplates(writer http.ResponseWriter, request *http.Request) {
	if s.Templates == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.templates", "template service is not configured"))
		return
	}
	items, err := s.Templates.List(request.Context(), domain.WorkspaceID(request.PathValue("workspace")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"templates": items})
}

func (s *Server) deleteTemplate(writer http.ResponseWriter, request *http.Request) {
	if s.Templates == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.templates", "template service is not configured"))
		return
	}
	if err := s.Templates.Delete(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), request.PathValue("template"), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type quotaRequest struct {
	Limits          *quota.Limits `json:"limits"`
	ExpectedVersion uint64        `json:"expected_version"`
	Usage           *quota.Limits `json:"usage"`
}

func (s *Server) setQuota(writer http.ResponseWriter, request *http.Request) {
	if s.Quotas == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.quota", "quota service is not configured"))
		return
	}
	var body quotaRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	if body.Limits == nil {
		writeError(writer, domain.Invalidf("http.quota", "limits are required"))
		return
	}
	setting, err := s.Quotas.Set(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), *body.Limits, body.ExpectedVersion)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, setting)
}

func (s *Server) getQuota(writer http.ResponseWriter, request *http.Request) {
	if s.Quotas == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.quota", "quota service is not configured"))
		return
	}
	value, found, err := s.Quotas.Get(request.Context(), domain.WorkspaceID(request.PathValue("workspace")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"found": found, "quota": value})
}

func (s *Server) checkQuota(writer http.ResponseWriter, request *http.Request) {
	if s.Quotas == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.quota", "quota service is not configured"))
		return
	}
	var body quotaRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	if body.Usage == nil {
		writeError(writer, domain.Invalidf("http.quota", "usage is required"))
		return
	}
	if err := s.Quotas.Check(request.Context(), domain.WorkspaceID(request.PathValue("workspace")), *body.Usage); err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"allowed": true})
}

type providerRequest struct {
	Provider string          `json:"provider"`
	Revision uint64          `json:"revision"`
	Config   json.RawMessage `json:"config"`
}

type profileRequest struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Config json.RawMessage `json:"config,omitempty"`
}

type providerDefRequest struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Driver           string           `json:"driver"`
	Config           json.RawMessage  `json:"config,omitempty"`
	Profiles         []profileRequest `json:"profiles,omitempty"`
	ExpectedRevision uint64           `json:"expected_revision"`
	IdempotencyKey   string           `json:"idempotency_key"`
}

func profileInputs(requests []profileRequest) []provider.ProfileInput {
	inputs := make([]provider.ProfileInput, 0, len(requests))
	for _, request := range requests {
		inputs = append(inputs, provider.ProfileInput{ID: request.ID, Name: request.Name, Config: request.Config})
	}
	return inputs
}

func (s *Server) providerRegistry(writer http.ResponseWriter) bool {
	if s.ProviderDefs == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider registry is not configured"))
		return false
	}
	return true
}

func (s *Server) createProviderDef(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	var body providerDefRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	created, replayed, err := s.ProviderDefs.Create(request.Context(), provider.CreateRequest{
		ID: domain.ProviderID(body.ID), Name: body.Name, Driver: body.Driver, Config: body.Config,
		Profiles: profileInputs(body.Profiles), IdempotencyKey: domain.OperationID(body.IdempotencyKey),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"provider": created, "replayed": replayed})
}

func (s *Server) listProviderDefs(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	providers, err := s.ProviderDefs.List(request.Context())
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"providers": providers})
}

func (s *Server) getProviderDef(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	providerRecord, err := s.ProviderDefs.Get(request.Context(), domain.ProviderID(request.PathValue("provider")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, providerRecord)
}

func (s *Server) updateProviderDef(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	var body providerDefRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	updated, err := s.ProviderDefs.Update(request.Context(), provider.UpdateRequest{
		ID: domain.ProviderID(request.PathValue("provider")), Name: body.Name, Driver: body.Driver,
		Config: body.Config, ExpectedRevision: body.ExpectedRevision, IdempotencyKey: domain.OperationID(body.IdempotencyKey),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, updated)
}

func (s *Server) deleteProviderDef(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	if err := s.ProviderDefs.Delete(request.Context(), domain.ProviderID(request.PathValue("provider")), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) listProviderProfiles(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	profiles, err := s.ProviderDefs.ListProfiles(request.Context(), domain.ProviderID(request.PathValue("provider")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"profiles": profiles})
}

type profilesRequest struct {
	Profiles       []profileRequest `json:"profiles"`
	IdempotencyKey string           `json:"idempotency_key"`
}

func (s *Server) importProviderProfiles(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	var body profilesRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	profiles, replayed, err := s.ProviderDefs.ImportProfiles(request.Context(), domain.ProviderID(request.PathValue("provider")), profileInputs(body.Profiles), domain.OperationID(body.IdempotencyKey))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"profiles": profiles, "replayed": replayed})
}

func (s *Server) lintProviderProfiles(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	var body profilesRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	issues, err := s.ProviderDefs.LintProfiles(request.Context(), domain.ProviderID(request.PathValue("provider")), profileInputs(body.Profiles))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"issues": issues})
}

func (s *Server) getProviderProfile(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	profile, err := s.ProviderDefs.GetProfile(request.Context(), domain.ProviderID(request.PathValue("provider")), request.PathValue("profile"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, profile)
}

func (s *Server) deleteProviderProfile(writer http.ResponseWriter, request *http.Request) {
	if !s.providerRegistry(writer) {
		return
	}
	if err := s.ProviderDefs.DeleteProfile(request.Context(), domain.ProviderID(request.PathValue("provider")), request.PathValue("profile"), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) bindProvider(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	var body providerRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	binding, replayed, err := s.Providers.Bind(request.Context(), provider.BindRequest{
		Sandbox: sandboxRef(request), Provider: domain.ProviderID(body.Provider), Revision: body.Revision,
		Config: body.Config, IdempotencyKey: domain.OperationID(request.Header.Get("Idempotency-Key")),
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, binding)
}

func (s *Server) listProviders(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	items, err := s.Providers.List(request.Context(), sandboxRef(request))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"providers": items})
}

func (s *Server) getProvider(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	binding, err := s.Providers.Get(request.Context(), sandboxRef(request), domain.ProviderID(request.PathValue("provider")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, binding)
}

type providerAckRequest struct {
	Revision uint64 `json:"revision"`
	Reason   string `json:"reason"`
}

func (s *Server) ackProvider(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	var body providerAckRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	binding, err := s.Providers.Ack(request.Context(), sandboxRef(request), domain.ProviderID(request.PathValue("provider")), body.Revision)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, binding)
}

func (s *Server) failProvider(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	var body providerAckRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	binding, err := s.Providers.Fail(request.Context(), sandboxRef(request), domain.ProviderID(request.PathValue("provider")), body.Revision, body.Reason)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, binding)
}

func (s *Server) unbindProvider(writer http.ResponseWriter, request *http.Request) {
	if s.Providers == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.providers", "provider service is not configured"))
		return
	}
	if err := s.Providers.Unbind(request.Context(), sandboxRef(request), domain.ProviderID(request.PathValue("provider")), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type serviceRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	URL      string `json:"url"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	AuthMode string `json:"auth_mode"`
}

func (s *Server) exposeService(writer http.ResponseWriter, request *http.Request) {
	if s.Services == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.services", "service registry is not configured"))
		return
	}
	var body serviceRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	service, replayed, err := s.Services.Expose(request.Context(), sandboxRef(request), body.ID, body.Name, body.URL, body.Port, body.Protocol, body.AuthMode, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, service)
}

func (s *Server) listServices(writer http.ResponseWriter, request *http.Request) {
	if s.Services == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.services", "service registry is not configured"))
		return
	}
	items, err := s.Services.List(request.Context(), sandboxRef(request))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"services": items})
}

func (s *Server) getService(writer http.ResponseWriter, request *http.Request) {
	if s.Services == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.services", "service registry is not configured"))
		return
	}
	service, err := s.Services.Get(request.Context(), sandboxRef(request), request.PathValue("service"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, service)
}

func (s *Server) deleteService(writer http.ResponseWriter, request *http.Request) {
	if s.Services == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.services", "service registry is not configured"))
		return
	}
	if err := s.Services.Delete(request.Context(), sandboxRef(request), request.PathValue("service"), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

type forwardRequest struct {
	ID         string `json:"id"`
	LocalPort  uint16 `json:"local_port"`
	RemoteHost string `json:"remote_host"`
	RemotePort uint16 `json:"remote_port"`
	Protocol   string `json:"protocol"`
}

func (s *Server) createForward(writer http.ResponseWriter, request *http.Request) {
	if s.Forwards == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.forwards", "forward registry is not configured"))
		return
	}
	var body forwardRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	forward, replayed, err := s.Forwards.Create(request.Context(), sandboxRef(request), body.ID, body.LocalPort, body.RemoteHost, body.RemotePort, body.Protocol, domain.OperationID(request.Header.Get("Idempotency-Key")))
	if err != nil {
		writeError(writer, err)
		return
	}
	status := http.StatusCreated
	if replayed {
		status = http.StatusOK
	}
	writeJSON(writer, status, forward)
}

func (s *Server) listForwards(writer http.ResponseWriter, request *http.Request) {
	if s.Forwards == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.forwards", "forward registry is not configured"))
		return
	}
	items, err := s.Forwards.List(request.Context(), sandboxRef(request))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"forwards": items})
}

func (s *Server) getForward(writer http.ResponseWriter, request *http.Request) {
	if s.Forwards == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.forwards", "forward registry is not configured"))
		return
	}
	forward, err := s.Forwards.Get(request.Context(), sandboxRef(request), request.PathValue("forward"))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, forward)
}

func (s *Server) deleteForward(writer http.ResponseWriter, request *http.Request) {
	if s.Forwards == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.forwards", "forward registry is not configured"))
		return
	}
	if err := s.Forwards.Delete(request.Context(), sandboxRef(request), request.PathValue("forward"), domain.OperationID(request.Header.Get("Idempotency-Key"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) gatewayInfo(writer http.ResponseWriter, _ *http.Request) {
	name := s.GatewayName
	if name == "" {
		name = "quarshell"
	}
	capabilities := s.Capabilities
	if capabilities == nil {
		capabilities = []string{}
	}
	writeJSON(writer, http.StatusOK, map[string]any{"name": name, "capabilities": capabilities})
}

func (s *Server) whoami(writer http.ResponseWriter, _ *http.Request) {
	principal := s.Principal
	if principal == "" {
		principal = "gateway-client"
	}
	writeJSON(writer, http.StatusOK, map[string]string{"id": principal})
}

func (s *Server) genericEvents(writer http.ResponseWriter, request *http.Request) {
	if s.Events == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.events", "event stream is not configured"))
		return
	}
	stream := request.URL.Query().Get("stream")
	cursor := eventlog.Cursor(request.Header.Get("Last-Event-ID"))
	if cursor == "" {
		cursor = eventlog.Cursor(request.URL.Query().Get("cursor"))
	}
	if _, _, err := s.Events.After(request.Context(), cursor, 1); err != nil {
		writeError(writer, err)
		return
	}
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.events", "streaming is unavailable"))
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	writer.WriteHeader(http.StatusOK)
	flusher.Flush()
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		events, _, err := s.Events.After(request.Context(), cursor, 100)
		if err != nil {
			return
		}
		wrote := false
		for _, event := range events {
			cursor = eventlog.Cursor(strconv.FormatUint(event.ID, 10))
			if stream != "" && event.Stream != stream {
				continue
			}
			payload, err := json.Marshal(event)
			if err != nil {
				continue
			}
			_, _ = fmt.Fprintf(writer, "id: %d\ndata: %s\n\n", event.ID, payload)
			wrote = true
		}
		if wrote {
			flusher.Flush()
			continue
		}
		select {
		case <-request.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

type tokenRequest struct {
	Subject    string `json:"subject"`
	TTLSeconds int64  `json:"ttl_seconds"`
	Token      string `json:"token"`
}

func (s *Server) issueSandboxToken(writer http.ResponseWriter, request *http.Request) {
	if s.Tokens == nil || s.Sandboxes == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.tokens", "token service is not configured"))
		return
	}
	var body tokenRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	ref := domain.SandboxRef{
		Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(request.PathValue("sandbox")),
	}
	current, err := s.Sandboxes.Get(request.Context(), ref)
	if err != nil {
		writeError(writer, err)
		return
	}
	raw, claims, err := s.Tokens.IssueForAudienceEpoch(ref, current.RuntimeGenerationOrInitial(), current.CredentialEpochOrInitial(), "gateway", body.Subject, time.Duration(body.TTLSeconds)*time.Second)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"token": raw, "claims": s.Tokens.OpenShellClaims(claims)})
}

func (s *Server) refreshSandboxToken(writer http.ResponseWriter, request *http.Request) {
	if s.Tokens == nil || s.Sandboxes == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.tokens", "token service is not configured"))
		return
	}
	var body tokenRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	oldClaims, err := s.Tokens.Verify(body.Token)
	if err != nil {
		writeError(writer, err)
		return
	}
	current, err := s.Sandboxes.GetBySandboxID(request.Context(), oldClaims.Sandbox)
	if err != nil {
		writeError(writer, err)
		return
	}
	if oldClaims.Generation == 0 || oldClaims.Generation != current.RuntimeGenerationOrInitial() || oldClaims.CredentialEpoch != current.CredentialEpochOrInitial() {
		writeError(writer, domain.New(domain.CodeUnauthorized, "http.tokens", "sandbox token belongs to a stale generation"))
		return
	}
	ref := domain.SandboxRef{Workspace: current.Workspace, Sandbox: current.Sandbox}
	raw, claims, err := s.Tokens.RefreshForSandbox(request.Context(), ref, body.Token, time.Duration(body.TTLSeconds)*time.Second)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, map[string]any{"token": raw, "claims": s.Tokens.OpenShellClaims(claims)})
}

type credentialRequest struct {
	ID        string                      `json:"id"`
	Provider  string                      `json:"provider"`
	Material  string                      `json:"material"`
	Endpoint  credentials.EndpointBinding `json:"endpoint"`
	ExpiresAt time.Time                   `json:"expires_at"`
}

func (s *Server) createCredential(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	var body credentialRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	if err := secrets.ValidateMaterialLen([]byte(body.Material), 1<<20); err != nil {
		writeError(writer, err)
		return
	}
	metadata, err := s.Secrets.Create(request.Context(), domain.CredentialID(body.ID), domain.ProviderID(body.Provider), []byte(body.Material), body.Endpoint, body.ExpiresAt)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, metadata)
}

func (s *Server) getCredential(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	metadata, err := s.Secrets.Get(request.Context(), domain.CredentialID(request.PathValue("credential")))
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, metadata)
}

func (s *Server) deleteCredential(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	if err := s.Secrets.Delete(request.Context(), domain.CredentialID(request.PathValue("credential"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) rotateCredential(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	var body credentialRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	if err := secrets.ValidateMaterialLen([]byte(body.Material), 1<<20); err != nil {
		writeError(writer, err)
		return
	}
	metadata, err := s.Secrets.Rotate(request.Context(), domain.CredentialID(request.PathValue("credential")), []byte(body.Material), body.ExpiresAt)
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, metadata)
}

type handleRequest struct {
	Workspace  string                      `json:"workspace"`
	Sandbox    string                      `json:"sandbox"`
	Endpoint   credentials.EndpointBinding `json:"endpoint"`
	StableKey  string                      `json:"stable_key"`
	TTLSeconds int64                       `json:"ttl_seconds"`
}

func (s *Server) issueHandle(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	var body handleRequest
	if err := s.decode(writer, request, &body); err != nil {
		writeError(writer, err)
		return
	}
	handle, info, err := s.Secrets.Issue(request.Context(), credentials.IssueRequest{
		Credential: domain.CredentialID(request.PathValue("credential")),
		Sandbox:    domain.SandboxRef{Workspace: domain.WorkspaceID(body.Workspace), Sandbox: domain.SandboxID(body.Sandbox)},
		Endpoint:   body.Endpoint, StableKey: body.StableKey, TTL: time.Duration(body.TTLSeconds) * time.Second,
	})
	if err != nil {
		writeError(writer, err)
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]any{"handle": handle, "info": info})
}

func (s *Server) revokeHandle(writer http.ResponseWriter, request *http.Request) {
	if s.Secrets == nil {
		writeError(writer, domain.New(domain.CodeUnavailable, "http.secrets", "secrets service is not configured"))
		return
	}
	if err := s.Secrets.Revoke(request.Context(), credentials.Handle(request.PathValue("handle"))); err != nil {
		writeError(writer, err)
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) decode(writer http.ResponseWriter, request *http.Request, destination any) error {
	maxBytes := s.MaxBodyBytes
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		if errors.Is(err, io.EOF) {
			return domain.Invalidf("http.body", "request body is required")
		}
		return domain.Invalidf("http.body", "invalid request body")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return domain.Invalidf("http.body", "unexpected trailing data")
	}
	return nil
}

func sandboxRef(request *http.Request) domain.SandboxRef {
	return domain.SandboxRef{Workspace: domain.WorkspaceID(request.PathValue("workspace")), Sandbox: domain.SandboxID(request.PathValue("sandbox"))}
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
	case domain.CodeUnauthorized:
		status = http.StatusUnauthorized
	case domain.CodePermissionDenied:
		status = http.StatusForbidden
	case domain.CodeUnavailable:
		status = http.StatusServiceUnavailable
	case domain.CodeDeadlineExceeded:
		status = http.StatusGatewayTimeout
	case domain.CodeCanceled:
		status = http.StatusRequestTimeout
	}
	writeJSON(writer, status, map[string]string{"code": string(domain.CodeOf(err)), "message": domain.SafeMessage(err)})
}
