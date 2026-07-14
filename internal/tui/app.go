package tui

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/rupivbluegreen/omni-sag/internal/api"
	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/sessions"
)

// ClientAPI is the subset of the control-plane SDK the TUI uses. *api.Client
// satisfies it; tests supply a fake.
type ClientAPI interface {
	Health(ctx context.Context) error
	ListSessions(ctx context.Context) ([]sessions.Info, error)
	TerminateSession(ctx context.Context, id string) error
	GetPolicy(ctx context.Context) (api.PolicyView, error)
	ListApprovals(ctx context.Context) ([]approval.Request, error)
	ApproveApproval(ctx context.Context, id string) (approval.Request, error)
	DenyApproval(ctx context.Context, id string) (approval.Request, error)
	StreamSession(ctx context.Context, id string) (<-chan sessions.Event, error)
}

type tab int

const (
	tabSessions tab = iota
	tabPolicy
	tabApprovals
	tabHealth
	tabPlayer
	numTabs
)

var tabNames = map[tab]string{
	tabSessions: "Sessions", tabPolicy: "Policy", tabApprovals: "Approvals",
	tabHealth: "Health", tabPlayer: "Replay",
}

// Model is the root Bubble Tea model.
type Model struct {
	client ClientAPI
	ctx    context.Context

	tab    tab
	width  int
	height int
	status string

	sessions []sessions.Info
	selSess  int

	policy   api.PolicyView
	trace    Explanation
	hasTrace bool

	approvals []approval.Request
	selAppr   int

	healthOK bool

	// supervision
	superChan   <-chan sessions.Event
	superEvents []sessions.Event
	superOn     bool
	superCancel context.CancelFunc // stops the current stream's goroutine + HTTP conn
	superGen    int                // stream generation; drops events from a superseded stream

	// player
	player  player
	hasCast bool
}

// SetTrace computes and stores the "why can X reach Y?" rule trace so the Policy
// tab shows it. Exported so the CLI and tests can drive it.
func (m *Model) SetTrace(user string, groups []string, host string, port int) {
	m.trace = Explain(m.policy, user, groups, host, port)
	m.hasTrace = true
}

// Options configure the TUI.
type Options struct {
	// Cast, if set, opens the replay tab with this recording.
	Cast *Cast
}

// New builds the root model.
func New(ctx context.Context, client ClientAPI, opts Options) Model {
	m := Model{client: client, ctx: ctx, status: "loading…"}
	if opts.Cast != nil {
		m.player = newPlayer(*opts.Cast)
		m.hasCast = true
		m.tab = tabPlayer
	}
	return m
}

// --- messages ---

type sessionsMsg struct {
	items []sessions.Info
	err   error
}
type policyMsg struct {
	pv  api.PolicyView
	err error
}
type approvalsMsg struct {
	items []approval.Request
	err   error
}
type healthMsg struct{ err error }
type actionMsg struct {
	what string
	err  error
}
type superEventMsg struct {
	gen int
	ev  sessions.Event
}
type superClosedMsg struct{ gen int }
type tickMsg time.Time

// --- commands ---

func (m Model) loadSessions() tea.Cmd {
	return func() tea.Msg {
		items, err := m.client.ListSessions(m.ctx)
		return sessionsMsg{items, err}
	}
}
func (m Model) loadPolicy() tea.Cmd {
	return func() tea.Msg {
		pv, err := m.client.GetPolicy(m.ctx)
		return policyMsg{pv, err}
	}
}
func (m Model) loadApprovals() tea.Cmd {
	return func() tea.Msg {
		items, err := m.client.ListApprovals(m.ctx)
		return approvalsMsg{items, err}
	}
}
func (m Model) loadHealth() tea.Cmd {
	return func() tea.Msg { return healthMsg{m.client.Health(m.ctx)} }
}

func playerTick() tea.Cmd {
	return tea.Tick(100*time.Millisecond, func(t time.Time) tea.Msg { return tickMsg(t) })
}

// Init loads the first tab's data.
func (m Model) Init() tea.Cmd {
	cmds := []tea.Cmd{m.loadSessions(), m.loadPolicy(), m.loadApprovals(), m.loadHealth()}
	if m.hasCast {
		cmds = append(cmds, playerTick())
	}
	return tea.Batch(cmds...)
}

// Update handles messages.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tea.KeyMsg:
		return m.handleKey(msg)
	case sessionsMsg:
		if msg.err != nil {
			m.status = "sessions: " + msg.err.Error()
		} else {
			m.sessions = msg.items
			m.clampSel()
			m.status = fmt.Sprintf("%d live sessions", len(m.sessions))
		}
	case policyMsg:
		if msg.err != nil {
			m.status = "policy: " + msg.err.Error()
		} else {
			m.policy = msg.pv
		}
	case approvalsMsg:
		if msg.err != nil {
			m.status = "approvals: " + msg.err.Error()
		} else {
			m.approvals = pendingFirst(msg.items)
			if m.selAppr >= len(m.approvals) {
				m.selAppr = 0
			}
		}
	case healthMsg:
		m.healthOK = msg.err == nil
	case actionMsg:
		if msg.err != nil {
			m.status = msg.what + ": " + msg.err.Error()
		} else {
			m.status = msg.what + ": ok"
		}
		return m, tea.Batch(m.loadSessions(), m.loadApprovals())
	case superEventMsg:
		if msg.gen != m.superGen {
			return m, nil // event from a superseded stream; drop, do not re-arm
		}
		m.superEvents = append(m.superEvents, msg.ev)
		return m, m.readSuper(m.superGen)
	case superClosedMsg:
		if msg.gen != m.superGen {
			return m, nil
		}
		m.superOn = false
		m.status = "supervision stream ended"
	case tickMsg:
		if m.hasCast && m.player.playing && !m.player.done() {
			m.player = m.player.advanceTo(m.player.elapsed + 0.1)
			return m, playerTick()
		}
		if m.hasCast && m.player.playing {
			return m, playerTick() // keep ticking so play can resume after seek
		}
	}
	return m, nil
}

func (m Model) handleKey(k tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch k.String() {
	case "q", "ctrl+c":
		return m, tea.Quit
	case "tab", "right":
		m.tab = (m.tab + 1) % numTabs
		return m, nil
	case "shift+tab", "left":
		m.tab = (m.tab + numTabs - 1) % numTabs
		return m, nil
	case "r":
		m.status = "refreshing…"
		return m, tea.Batch(m.loadSessions(), m.loadPolicy(), m.loadApprovals(), m.loadHealth())
	case "up", "k":
		m.moveSel(-1)
	case "down", "j":
		m.moveSel(1)
	}
	// tab-specific
	switch m.tab {
	case tabSessions:
		if k.String() == "K" && len(m.sessions) > 0 {
			id := m.sessions[m.selSess].ID
			return m, func() tea.Msg { return actionMsg{"terminate " + id, m.client.TerminateSession(m.ctx, id)} }
		}
		if k.String() == "s" && len(m.sessions) > 0 {
			return m.startSupervision(m.sessions[m.selSess].ID)
		}
	case tabApprovals:
		if len(m.approvals) > 0 {
			id := m.approvals[m.selAppr].ID
			switch k.String() {
			case "a":
				return m, func() tea.Msg {
					_, err := m.client.ApproveApproval(m.ctx, id)
					return actionMsg{"approve " + id, err}
				}
			case "d":
				return m, func() tea.Msg {
					_, err := m.client.DenyApproval(m.ctx, id)
					return actionMsg{"deny " + id, err}
				}
			}
		}
	case tabPlayer:
		if m.hasCast {
			switch k.String() {
			case " ", "p":
				m.player = m.player.toggle()
			case "[":
				m.player = m.player.seek(m.player.elapsed - 3)
			case "]":
				m.player = m.player.seek(m.player.elapsed + 3)
			case "0":
				m.player = m.player.seek(0)
			}
		}
	}
	return m, nil
}

func (m Model) startSupervision(id string) (tea.Model, tea.Cmd) {
	// Stop any previous stream's goroutine + HTTP/SSE connection before opening
	// a new one, so switching supervised sessions does not leak per switch.
	if m.superCancel != nil {
		m.superCancel()
	}
	ctx, cancel := context.WithCancel(m.ctx)
	ch, err := m.client.StreamSession(ctx, id)
	if err != nil {
		cancel()
		m.status = "supervise: " + err.Error()
		return m, nil
	}
	m.superCancel = cancel
	m.superChan = ch
	m.superGen++
	m.superOn = true
	m.superEvents = nil
	m.status = "supervising " + id
	return m, m.readSuper(m.superGen)
}

func (m Model) readSuper(gen int) tea.Cmd {
	ch := m.superChan
	return func() tea.Msg {
		ev, ok := <-ch
		if !ok {
			return superClosedMsg{gen}
		}
		return superEventMsg{gen, ev}
	}
}

func (m *Model) moveSel(d int) {
	switch m.tab {
	case tabSessions:
		m.selSess += d
	case tabApprovals:
		m.selAppr += d
	}
	m.clampSel()
}

func (m *Model) clampSel() {
	if m.selSess < 0 {
		m.selSess = 0
	}
	if m.selSess >= len(m.sessions) && len(m.sessions) > 0 {
		m.selSess = len(m.sessions) - 1
	}
	if m.selAppr < 0 {
		m.selAppr = 0
	}
	if m.selAppr >= len(m.approvals) && len(m.approvals) > 0 {
		m.selAppr = len(m.approvals) - 1
	}
}

func pendingFirst(items []approval.Request) []approval.Request {
	out := append([]approval.Request(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		pi, pj := out[i].Status == approval.StatusPending, out[j].Status == approval.StatusPending
		if pi != pj {
			return pi
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	return out
}

var (
	titleStyle  = lipgloss.NewStyle().Bold(true)
	activeTab   = lipgloss.NewStyle().Bold(true).Underline(true)
	dimStyle    = lipgloss.NewStyle().Faint(true)
	selectStyle = lipgloss.NewStyle().Reverse(true)
)

// View renders the current tab.
func (m Model) View() string {
	var b strings.Builder
	// tab bar
	var tabs []string
	for t := tab(0); t < numTabs; t++ {
		name := tabNames[t]
		if t == m.tab {
			tabs = append(tabs, activeTab.Render(name))
		} else {
			tabs = append(tabs, dimStyle.Render(name))
		}
	}
	b.WriteString(titleStyle.Render("omni-sag") + "  " + strings.Join(tabs, " · ") + "\n\n")

	switch m.tab {
	case tabSessions:
		b.WriteString(m.viewSessions())
	case tabPolicy:
		b.WriteString(m.viewPolicy())
	case tabApprovals:
		b.WriteString(m.viewApprovals())
	case tabHealth:
		b.WriteString(m.viewHealth())
	case tabPlayer:
		b.WriteString(m.viewPlayer())
	}
	b.WriteString("\n" + dimStyle.Render("[tab] switch  [r] refresh  [q] quit") + "\n")
	b.WriteString(dimStyle.Render("status: "+m.status) + "\n")
	return b.String()
}

func (m Model) viewSessions() string {
	if len(m.sessions) == 0 {
		return dimStyle.Render("no live sessions\n")
	}
	var b strings.Builder
	b.WriteString(dimStyle.Render("[↑/↓] select  [K] kill  [s] supervise\n"))
	for i, s := range m.sessions {
		line := fmt.Sprintf("%-14s %-10s %-18s %-20s ch=%d", s.ID, s.User, s.SourceIP, s.Target, s.Channels)
		if i == m.selSess {
			line = selectStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	if m.superOn || len(m.superEvents) > 0 {
		b.WriteString("\n" + titleStyle.Render("supervision") + "\n")
		for _, ev := range lastN(m.superEvents, 8) {
			b.WriteString(fmt.Sprintf("  %s %s %s\n", ev.Time.Format("15:04:05"), ev.Kind, ev.Detail))
		}
	}
	return b.String()
}

func (m Model) viewPolicy() string {
	var b strings.Builder
	for _, r := range m.policy.Roles {
		b.WriteString(titleStyle.Render(r.Name) + " " + dimStyle.Render("groups="+strings.Join(r.Groups, ",")) + "\n")
		for _, ru := range r.Allow {
			extra := ""
			if ru.Record != "" {
				extra += " record=" + ru.Record
			}
			if ru.Credential != "" {
				extra += " cred=" + ru.Credential
			}
			if ru.RequireApproval {
				extra += " four-eyes"
			}
			b.WriteString(fmt.Sprintf("  %s ports=%v%s\n", ru.Host, ru.Ports, extra))
		}
	}
	if m.hasTrace {
		b.WriteString("\n" + titleStyle.Render("why-can trace") + "\n")
		for _, l := range m.trace.Lines {
			b.WriteString("  " + l + "\n")
		}
	} else {
		b.WriteString("\n" + dimStyle.Render("(rule-trace: call SetTrace or use omnictl trace)\n"))
	}
	return b.String()
}

func (m Model) viewApprovals() string {
	if len(m.approvals) == 0 {
		return dimStyle.Render("no approval requests\n")
	}
	var b strings.Builder
	b.WriteString(dimStyle.Render("[↑/↓] select  [a] approve  [d] deny (four-eyes enforced by API)\n"))
	for i, a := range m.approvals {
		line := fmt.Sprintf("%-14s %-16s %-22s by=%-8s %s", a.ID, a.Kind, a.Subject, a.Requester, a.Status)
		if i == m.selAppr {
			line = selectStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	return b.String()
}

func (m Model) viewHealth() string {
	var b strings.Builder
	if m.healthOK {
		b.WriteString("API health: OK\n")
	} else {
		b.WriteString("API health: UNREACHABLE\n")
	}
	b.WriteString("\n" + dimStyle.Render("panels not yet exposed by the API (shown honestly as unavailable):\n"))
	for _, p := range []string{"credential coverage", "quarantine", "evidence summary"} {
		b.WriteString("  " + p + ": not available (no API endpoint yet)\n")
	}
	return b.String()
}

func (m Model) viewPlayer() string {
	if !m.hasCast {
		return dimStyle.Render("no recording loaded (open with: omnictl tui -play <file.cast>)\n")
	}
	var b strings.Builder
	state := "playing"
	if !m.player.playing {
		state = "paused"
	}
	b.WriteString(fmt.Sprintf("%s  %.1fs / %.1fs   [space] play/pause  [ / ] seek  [0] restart\n\n",
		state, m.player.elapsed, m.player.cast.Duration()))
	b.WriteString(m.player.out)
	return b.String()
}

func lastN[T any](s []T, n int) []T {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

// Run starts the TUI program against client.
func Run(ctx context.Context, client ClientAPI, opts Options) error {
	p := tea.NewProgram(New(ctx, client, opts), tea.WithAltScreen(), tea.WithContext(ctx))
	_, err := p.Run()
	return err
}
