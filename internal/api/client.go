package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

// Client is a Go SDK for the control-plane API. It matches api/openapi.yaml.
// Supply an *http.Client configured for TLS/mTLS as needed; a bearer token is
// sent when non-empty.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// NewClient returns a client for baseURL (e.g. "https://gw:8443"). hc may be nil
// (http.DefaultClient is used). token, if set, is sent as a bearer token.
func NewClient(baseURL, token string, hc *http.Client) *Client {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), token: token, http: hc}
}

func (c *Client) do(ctx context.Context, method, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("api %s %s: %s: %s", method, path, resp.Status, strings.TrimSpace(string(body)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Health checks liveness.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/healthz", nil)
}

// ListSessions returns all live sessions.
func (c *Client) ListSessions(ctx context.Context) ([]sessions.Info, error) {
	var out struct {
		Sessions []sessions.Info `json:"sessions"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/sessions", &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}

// GetSession inspects one session.
func (c *Client) GetSession(ctx context.Context, id string) (sessions.Info, error) {
	var info sessions.Info
	err := c.do(ctx, http.MethodGet, "/api/v1/sessions/"+id, &info)
	return info, err
}

// TerminateSession kills one session (requires operator+).
func (c *Client) TerminateSession(ctx context.Context, id string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/sessions/"+id, nil)
}

// GetPolicy returns the compiled policy.
func (c *Client) GetPolicy(ctx context.Context) (PolicyView, error) {
	var pv PolicyView
	err := c.do(ctx, http.MethodGet, "/api/v1/policy", &pv)
	return pv, err
}

// ListApprovals returns all approval requests.
func (c *Client) ListApprovals(ctx context.Context) ([]approval.Request, error) {
	var out struct {
		Approvals []approval.Request `json:"approvals"`
	}
	if err := c.do(ctx, http.MethodGet, "/api/v1/approvals", &out); err != nil {
		return nil, err
	}
	return out.Approvals, nil
}

// ApproveApproval approves a pending request (requires operator+, four-eyes).
func (c *Client) ApproveApproval(ctx context.Context, id string) (approval.Request, error) {
	var req approval.Request
	err := c.do(ctx, http.MethodPost, "/api/v1/approvals/"+id+"/approve", &req)
	return req, err
}

// DenyApproval denies a pending request (requires operator+).
func (c *Client) DenyApproval(ctx context.Context, id string) (approval.Request, error) {
	var req approval.Request
	err := c.do(ctx, http.MethodPost, "/api/v1/approvals/"+id+"/deny", &req)
	return req, err
}
