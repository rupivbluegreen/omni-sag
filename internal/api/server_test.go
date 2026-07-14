package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

func testServer(t *testing.T) (*httptest.Server, *sessions.Registry) {
	t.Helper()
	reg := sessions.NewRegistry()
	pol := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: "db1", Ports: []int{5432}, Record: policy.RecordFull, Credential: "inject"}},
	}}}
	authz := NewTokenAuthorizer(map[string]Identity{
		"view-tok": {Subject: "v", Role: RoleViewer},
		"op-tok":   {Subject: "o", Role: RoleOperator},
	})
	srv := NewServer(Config{Registry: reg, Policy: func() policy.Policy { return pol }, Authorizer: authz})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, reg
}

func req(t *testing.T, method, url, token string) *http.Response {
	t.Helper()
	r, _ := http.NewRequest(method, url, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func TestAPI_HealthUnauthenticated(t *testing.T) {
	ts, _ := testServer(t)
	if resp := req(t, "GET", ts.URL+"/healthz", ""); resp.StatusCode != 200 {
		t.Fatalf("healthz = %d, want 200", resp.StatusCode)
	}
}

func TestAPI_AuthAndRBAC(t *testing.T) {
	ts, reg := testServer(t)
	killed := false
	id, _ := reg.Register(sessions.Info{User: "alice", SourceIP: "1.2.3.4"}, func() error { killed = true; return nil })

	// No token -> 401.
	if resp := req(t, "GET", ts.URL+"/api/v1/sessions", ""); resp.StatusCode != 401 {
		t.Fatalf("no token = %d, want 401", resp.StatusCode)
	}
	// Bad token -> 401.
	if resp := req(t, "GET", ts.URL+"/api/v1/sessions", "nope"); resp.StatusCode != 401 {
		t.Fatalf("bad token = %d, want 401", resp.StatusCode)
	}
	// Viewer can list.
	if resp := req(t, "GET", ts.URL+"/api/v1/sessions", "view-tok"); resp.StatusCode != 200 {
		t.Fatalf("viewer list = %d, want 200", resp.StatusCode)
	}
	// Viewer CANNOT terminate -> 403.
	if resp := req(t, "DELETE", ts.URL+"/api/v1/sessions/"+id, "view-tok"); resp.StatusCode != 403 {
		t.Fatalf("viewer terminate = %d, want 403", resp.StatusCode)
	}
	// Operator CAN terminate -> 200, and the terminate hook fires (the session
	// goroutine deregisters when the closed connection is observed).
	if resp := req(t, "DELETE", ts.URL+"/api/v1/sessions/"+id, "op-tok"); resp.StatusCode != 200 {
		t.Fatalf("operator terminate = %d, want 200", resp.StatusCode)
	}
	if !killed {
		t.Fatal("terminate hook was not invoked")
	}
}

func TestAPI_ClientRoundTrip(t *testing.T) {
	ts, reg := testServer(t)
	reg.Register(sessions.Info{User: "alice", SourceIP: "1.2.3.4", Target: "db1:5432"}, nil)

	c := NewClient(ts.URL, "view-tok", nil)
	ctx := context.Background()
	if err := c.Health(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := c.ListSessions(ctx)
	if err != nil || len(list) != 1 || list[0].User != "alice" {
		t.Fatalf("list = %+v err=%v", list, err)
	}
	pv, err := c.GetPolicy(ctx)
	if err != nil || len(pv.Roles) != 1 || pv.Roles[0].Allow[0].Credential != "inject" {
		t.Fatalf("policy = %+v err=%v", pv, err)
	}
}
