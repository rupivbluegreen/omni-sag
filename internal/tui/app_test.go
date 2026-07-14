package tui

import (
	"context"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

type fakeClient struct {
	sessions   []sessions.Info
	approvals  []approval.Request
	policy     api.PolicyView
	terminated []string
	approved   []string
	denied     []string
	events     chan sessions.Event
}

func (f *fakeClient) Health(context.Context) error                          { return nil }
func (f *fakeClient) ListSessions(context.Context) ([]sessions.Info, error) { return f.sessions, nil }
func (f *fakeClient) TerminateSession(_ context.Context, id string) error {
	f.terminated = append(f.terminated, id)
	return nil
}
func (f *fakeClient) GetPolicy(context.Context) (api.PolicyView, error) { return f.policy, nil }
func (f *fakeClient) ListApprovals(context.Context) ([]approval.Request, error) {
	return f.approvals, nil
}
func (f *fakeClient) ApproveApproval(_ context.Context, id string) (approval.Request, error) {
	f.approved = append(f.approved, id)
	return approval.Request{ID: id, Status: approval.StatusApproved}, nil
}
func (f *fakeClient) DenyApproval(_ context.Context, id string) (approval.Request, error) {
	f.denied = append(f.denied, id)
	return approval.Request{ID: id, Status: approval.StatusDenied}, nil
}
func (f *fakeClient) StreamSession(context.Context, string) (<-chan sessions.Event, error) {
	return f.events, nil
}

func upd(m Model, msg tea.Msg) (Model, tea.Cmd) {
	nm, cmd := m.Update(msg)
	return nm.(Model), cmd
}

func key(s string) tea.KeyMsg {
	switch s {
	case "tab":
		return tea.KeyMsg{Type: tea.KeyTab}
	default:
		return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
	}
}

func newTestModel(f *fakeClient) Model {
	return New(context.Background(), f, Options{})
}

func TestModel_LoadsSessions(t *testing.T) {
	f := &fakeClient{sessions: []sessions.Info{{ID: "s1", User: "alice"}, {ID: "s2", User: "bob"}}}
	m := newTestModel(f)
	m, _ = upd(m, sessionsMsg{items: f.sessions})
	if len(m.sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(m.sessions))
	}
}

func TestModel_TabSwitch(t *testing.T) {
	m := newTestModel(&fakeClient{})
	if m.tab != tabSessions {
		t.Fatal("should start on sessions")
	}
	m, _ = upd(m, key("tab"))
	if m.tab != tabPolicy {
		t.Fatalf("tab did not advance: %v", m.tab)
	}
}

func TestModel_KillSelectedSession(t *testing.T) {
	f := &fakeClient{sessions: []sessions.Info{{ID: "s1"}, {ID: "s2"}}}
	m := newTestModel(f)
	m, _ = upd(m, sessionsMsg{items: f.sessions})
	// select the second, then kill
	m, _ = upd(m, key("j"))
	_, cmd := upd(m, key("K"))
	if cmd == nil {
		t.Fatal("kill should return a command")
	}
	cmd() // executes TerminateSession
	if len(f.terminated) != 1 || f.terminated[0] != "s2" {
		t.Fatalf("terminated = %v, want [s2]", f.terminated)
	}
}

func TestModel_ApproveSelected(t *testing.T) {
	f := &fakeClient{approvals: []approval.Request{{ID: "a1", Status: approval.StatusPending}}}
	m := newTestModel(f)
	m, _ = upd(m, approvalsMsg{items: f.approvals})
	m.tab = tabApprovals
	_, cmd := upd(m, key("a"))
	if cmd == nil {
		t.Fatal("approve should return a command")
	}
	cmd()
	if len(f.approved) != 1 || f.approved[0] != "a1" {
		t.Fatalf("approved = %v, want [a1]", f.approved)
	}
}

func TestModel_SupervisionStreamsEvents(t *testing.T) {
	f := &fakeClient{sessions: []sessions.Info{{ID: "s1"}}, events: make(chan sessions.Event, 1)}
	m := newTestModel(f)
	m, _ = upd(m, sessionsMsg{items: f.sessions})
	nm, cmd := upd(m, key("s")) // start supervision
	m = nm
	if !m.superOn || cmd == nil {
		t.Fatal("supervision should start and return a read command")
	}
	f.events <- sessions.Event{Kind: "channel_open", Detail: "db:5432"}
	msg := cmd() // reads one event
	ev, ok := msg.(superEventMsg)
	if !ok || ev.ev.Kind != "channel_open" {
		t.Fatalf("expected a supervision event, got %#v", msg)
	}
	m, _ = upd(m, ev)
	if len(m.superEvents) != 1 {
		t.Fatalf("event not recorded: %v", m.superEvents)
	}
}

func TestModel_PlayerSeekAndPause(t *testing.T) {
	c := Cast{Frames: []Frame{{0, "o", "A"}, {0.5, "o", "B"}}}
	m := New(context.Background(), &fakeClient{}, Options{Cast: &c})
	if m.tab != tabPlayer || !m.hasCast {
		t.Fatal("cast option should open the player")
	}
	m, _ = upd(m, key(" ")) // pause
	if m.player.playing {
		t.Fatal("space should pause")
	}
	m, _ = upd(m, key("]")) // seek forward 3s -> past end
	if m.player.out != "AB" {
		t.Fatalf("seek should render output: %q", m.player.out)
	}
}
