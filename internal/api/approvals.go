package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
)

func (s *Server) listApprovals(w http.ResponseWriter, _ *http.Request) {
	if s.approvals == nil {
		writeJSON(w, http.StatusOK, map[string]any{"approvals": []approval.Request{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"approvals": s.approvals.List()})
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) {
	if s.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals not enabled")
		return
	}
	req, ok := s.approvals.Get(r.PathValue("id"))
	if !ok {
		writeError(w, http.StatusNotFound, "approval not found")
		return
	}
	writeJSON(w, http.StatusOK, req)
}

func (s *Server) approveApproval(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, true)
}

func (s *Server) denyApproval(w http.ResponseWriter, r *http.Request) {
	s.decideApproval(w, r, false)
}

// decideApproval applies a decision using the AUTHENTICATED caller as the
// approver, so four-eyes is enforced against a verified identity — never a
// client-supplied name.
func (s *Server) decideApproval(w http.ResponseWriter, r *http.Request, approve bool) {
	if s.approvals == nil {
		writeError(w, http.StatusServiceUnavailable, "approvals not enabled")
		return
	}
	approver := identityFrom(r).Subject
	id := r.PathValue("id")
	var (
		req approval.Request
		err error
	)
	if approve {
		req, err = s.approvals.Approve(id, approver)
	} else {
		req, err = s.approvals.Deny(id, approver)
	}
	switch {
	case errors.Is(err, approval.ErrNotFound):
		writeError(w, http.StatusNotFound, "approval not found")
	case errors.Is(err, approval.ErrFourEyes):
		writeError(w, http.StatusForbidden, "four-eyes: you may not decide your own request")
	case errors.Is(err, approval.ErrNotPending):
		writeError(w, http.StatusConflict, "approval is not pending")
	case errors.Is(err, approval.ErrStoreUnavailable):
		writeError(w, http.StatusServiceUnavailable, "approval store unavailable")
	case err != nil:
		writeError(w, http.StatusInternalServerError, "decision failed")
	default:
		writeJSON(w, http.StatusOK, req)
	}
}

// streamSession is a Server-Sent Events stream of a session's live supervision
// events. A supervisor uses it to watch a session; the kill switch is the
// existing DELETE /sessions/{id}.
func (s *Server) streamSession(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, ok := s.reg.Get(id); !ok {
		writeError(w, http.StatusNotFound, "session not found")
		return
	}
	ch, cancel := s.reg.Subscribe(id)
	defer cancel()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher, _ := w.(http.Flusher)
	fmt.Fprintf(w, ": attached to session %s\n\n", id)
	if flusher != nil {
		flusher.Flush()
	}

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			b, _ := json.Marshal(ev)
			fmt.Fprintf(w, "data: %s\n\n", b)
			if flusher != nil {
				flusher.Flush()
			}
		case <-r.Context().Done():
			return
		}
	}
}
