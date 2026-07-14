package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

func approvalServer(t *testing.T) (*httptest.Server, *approval.FileStore, *sessions.Registry) {
	t.Helper()
	store, err := approval.NewFileStore(filepath.Join(t.TempDir(), "a.json"))
	if err != nil {
		t.Fatal(err)
	}
	reg := sessions.NewRegistry()
	authz := NewTokenAuthorizer(map[string]Identity{
		"view":  {Subject: "vera", Role: RoleViewer},
		"alice": {Subject: "alice", Role: RoleOperator}, // the requester
		"bob":   {Subject: "bob", Role: RoleOperator},   // the second human
	})
	srv := NewServer(Config{
		Registry:   reg,
		Policy:     func() policy.Policy { return policy.Policy{} },
		Authorizer: authz,
		Approvals:  store,
	})
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return ts, store, reg
}

func TestAPI_ApprovalFourEyesAndRBAC(t *testing.T) {
	ts, store, _ := approvalServer(t)
	ctx := context.Background()

	// A session-access request made by "alice".
	reqObj, _ := store.Create(approval.Request{Kind: approval.KindSession, Requester: "alice", Subject: "crown:22"}, time.Hour)

	// viewer cannot approve (RBAC: needs operator).
	if got := req(t, http.MethodPost, ts.URL+"/api/v1/approvals/"+reqObj.ID+"/approve", "view"); got.StatusCode != http.StatusForbidden {
		t.Fatalf("viewer approve: want 403, got %d", got.StatusCode)
	}
	// alice (the requester) cannot approve her own request (four-eyes).
	if got := req(t, http.MethodPost, ts.URL+"/api/v1/approvals/"+reqObj.ID+"/approve", "alice"); got.StatusCode != http.StatusForbidden {
		t.Fatalf("self-approve: want 403 four-eyes, got %d", got.StatusCode)
	}
	// bob (a distinct operator) can approve.
	c := NewClient(ts.URL, "bob", nil)
	out, err := c.ApproveApproval(ctx, reqObj.ID)
	if err != nil {
		t.Fatalf("bob approve: %v", err)
	}
	if out.Status != approval.StatusApproved || out.Approver != "bob" {
		t.Fatalf("expected approved by bob, got %+v", out)
	}
	// unauthenticated read is 401.
	if got := req(t, http.MethodGet, ts.URL+"/api/v1/approvals", ""); got.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauth list: want 401, got %d", got.StatusCode)
	}
	// viewer can list.
	list, err := NewClient(ts.URL, "view", nil).ListApprovals(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("viewer list: err=%v n=%d", err, len(list))
	}
}

func TestAPI_SupervisionStreamReceivesEvents(t *testing.T) {
	_, _, reg := approvalServer(t)
	// Register a session so it is streamable, then stream via the handler.
	id, dereg := reg.Register(sessions.Info{User: "alice", SourceIP: "10.0.0.1"}, func() error { return nil })
	defer dereg()

	// Subscribe directly (the SSE handler wraps exactly this).
	ch, cancel := reg.Subscribe(id)
	defer cancel()
	reg.Publish(id, sessions.Event{Kind: "channel_open", Target: "crown:22"})

	select {
	case ev := <-ch:
		if ev.Kind != "channel_open" || ev.Target != "crown:22" {
			t.Fatalf("unexpected event: %+v", ev)
		}
	case <-time.After(time.Second):
		t.Fatal("supervisor did not receive the published event")
	}
}
