// Package api is the Omni-SAG control-plane HTTP API: list/inspect/terminate
// live sessions, read the compiled policy, and health. It runs on a listener
// SEPARATE from the SSH data path, so stopping the API never drops SSH sessions
// and never blocks new ones (control-plane-out-of-band). It reads live sessions
// via internal/sessions; the data path (dialer/session) never imports this
// package.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

// Server serves the control-plane API.
type Server struct {
	reg       *sessions.Registry
	policy    func() policy.Policy
	authz     Authorizer
	approvals approval.Store
	ready     func() bool
	mux       *http.ServeMux
}

// Config configures a Server.
type Config struct {
	Registry   *sessions.Registry
	Policy     func() policy.Policy // reads the current (hot-reloadable) policy
	Authorizer Authorizer
	Approvals  approval.Store // optional; enables the approvals endpoints
	Ready      func() bool    // readiness probe; nil ⇒ always ready
}

// NewServer builds the API server and registers its routes.
func NewServer(cfg Config) *Server {
	s := &Server{
		reg:       cfg.Registry,
		policy:    cfg.Policy,
		authz:     cfg.Authorizer,
		approvals: cfg.Approvals,
		ready:     cfg.Ready,
		mux:       http.NewServeMux(),
	}
	if s.ready == nil {
		s.ready = func() bool { return true }
	}
	s.routes()
	return s
}

// Handler exposes the API as an http.Handler (for httptest and http.Server).
func (s *Server) Handler() http.Handler { return s.mux }

func (s *Server) routes() {
	// Health endpoints are unauthenticated (probes).
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	s.mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !s.ready() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	s.mux.Handle("GET /api/v1/sessions", s.require(RoleViewer, s.listSessions))
	s.mux.Handle("GET /api/v1/sessions/{id}", s.require(RoleViewer, s.getSession))
	s.mux.Handle("DELETE /api/v1/sessions/{id}", s.require(RoleOperator, s.terminateSession))
	s.mux.Handle("GET /api/v1/sessions/{id}/stream", s.require(RoleViewer, s.streamSession))
	s.mux.Handle("GET /api/v1/policy", s.require(RoleViewer, s.getPolicy))

	// Approvals (four-eyes). Read requires viewer; deciding requires operator and
	// the store enforces approver != requester.
	s.mux.Handle("GET /api/v1/approvals", s.require(RoleViewer, s.listApprovals))
	s.mux.Handle("GET /api/v1/approvals/{id}", s.require(RoleViewer, s.getApproval))
	s.mux.Handle("POST /api/v1/approvals/{id}/approve", s.require(RoleOperator, s.approveApproval))
	s.mux.Handle("POST /api/v1/approvals/{id}/deny", s.require(RoleOperator, s.denyApproval))
}

// idCtxKey carries the authenticated Identity into handlers.
type idCtxKey struct{}

func identityFrom(r *http.Request) Identity {
	id, _ := r.Context().Value(idCtxKey{}).(Identity)
	return id
}

// require wraps h with authentication + a minimum-role check (fail closed).
func (s *Server) require(min Role, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.authz.Authorize(r)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "unauthenticated")
			return
		}
		if !id.Role.atLeast(min) {
			writeError(w, http.StatusForbidden, "forbidden: requires "+string(min))
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), idCtxKey{}, id)))
	})
}

func (s *Server) listSessions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"sessions": s.reg.List()})
}

func (s *Server) getSession(w http.ResponseWriter, r *http.Request) {
	info, ok := s.reg.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	writeJSON(w, http.StatusOK, info)
}

func (s *Server) terminateSession(w http.ResponseWriter, r *http.Request) {
	err := s.reg.Terminate(r.PathValue("id"))
	switch {
	case errors.Is(err, sessions.ErrNotFound):
		writeError(w, http.StatusNotFound, "session not found")
	case errors.Is(err, sessions.ErrNotTerminable):
		writeError(w, http.StatusConflict, "session cannot be terminated")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "terminate failed")
	default:
		writeJSON(w, http.StatusOK, map[string]string{"status": "terminated"})
	}
}

func (s *Server) getPolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, policyView(s.policy()))
}

// --- policy view DTOs (match openapi.yaml) ---

type RuleView struct {
	Host            string `json:"host"`
	Ports           []int  `json:"ports,omitempty"`
	Record          string `json:"record,omitempty"`
	Credential      string `json:"credential,omitempty"`
	RequireApproval bool   `json:"require_approval,omitempty"`
}

type RoleView struct {
	Name   string     `json:"name"`
	Groups []string   `json:"groups,omitempty"`
	Allow  []RuleView `json:"allow,omitempty"`
}

type PolicyView struct {
	Roles []RoleView `json:"roles"`
}

func policyView(p policy.Policy) PolicyView { return PolicyToView(p) }

// PolicyToView converts a compiled policy to its API view. Exported so the
// omnictl rule-trace can round-trip the view back to a policy and evaluate it
// with policy.Decide, keeping the explanation consistent with real decisions.
func PolicyToView(p policy.Policy) PolicyView {
	pv := PolicyView{Roles: make([]RoleView, 0, len(p.Roles))}
	for _, r := range p.Roles {
		rv := RoleView{Name: r.Name, Groups: r.Groups}
		for _, rule := range r.Allow {
			rv.Allow = append(rv.Allow, RuleView{
				Host: rule.Host, Ports: rule.Ports,
				Record: string(rule.Record), Credential: rule.Credential,
				RequireApproval: rule.RequireApproval,
			})
		}
		pv.Roles = append(pv.Roles, rv)
	}
	return pv
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
