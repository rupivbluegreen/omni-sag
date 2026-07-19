package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/release"
)

// eicarInspector blocks any content containing "EICAR"; everything else is clean.
type eicarInspector struct{}

func (eicarInspector) Inspect(_ context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	data, _ := io.ReadAll(body)
	if bytes.Contains(data, []byte("EICAR")) {
		return inspect.Result{Verdict: inspect.VerdictBlocked, Reason: "X-Infection-Found: EICAR", ICAPStatus: 200}, nil
	}
	return inspect.Result{Verdict: inspect.VerdictClean, ICAPStatus: 204}, nil
}

// memQuarantine is an in-memory inspectgate.BlobStore.
type memQuarantine struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newMemQuarantine() *memQuarantine { return &memQuarantine{objs: map[string][]byte{}} }
func (m *memQuarantine) Put(_ context.Context, key, _ string, r io.Reader, _ int64) error {
	d, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.objs[key] = d
	m.mu.Unlock()
	return nil
}
func (m *memQuarantine) Get(_ context.Context, key string) (io.ReadCloser, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return io.NopCloser(strings.NewReader(string(m.objs[key]))), nil
}
func (m *memQuarantine) Delete(_ context.Context, key string) error {
	m.mu.Lock()
	delete(m.objs, key)
	m.mu.Unlock()
	return nil
}
func (m *memQuarantine) count() int { m.mu.Lock(); defer m.mu.Unlock(); return len(m.objs) }

// startInspectingServer wires a server with content inspection, a real
// quarantine-release approval store, and (Task 6) a real release store so an
// approved upload can actually complete (record a release), and a fake real
// target for runSFTP's remoteFS to proxy to (SFTP is no longer served from an
// in-memory stand-in). Returns the gateway address, the target host to
// select via "user%host" (see splitTargetUser), the quarantine store, the
// approval store, and the release store so tests can drive pending release
// requests to a decision and inspect what got recorded.
func startInspectingServer(t *testing.T, sink evidence.Sink) (addr, targetHost string, q *memQuarantine, store *approval.FileStore, releases *release.FileStore) {
	t.Helper()
	q = newMemQuarantine()
	gate, err := inspectgate.New(inspectgate.Config{Inspector: eicarInspector{}, Quarantine: q, Threshold: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	store, err = approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatal(err)
	}
	releases, err = release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatal(err)
	}
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	hostKey, _ := NewEphemeralHostKey()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	d := dialer.New(policy.Policy{}, sink)
	opts := append([]Option{WithInspection(gate), WithApprovals(store, 5*time.Second), WithReleases(releases, 6*time.Hour), WithSCPEnabled(true)}, targetOpts...)
	srv := New(hostKey, auth, d, sink, opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String(), targetHost, q, store, releases
}

// approveRelease polls store for a pending KindQuarantineRelease request and
// approves it as approver (a distinct identity from the uploader — four-eyes
// is enforced server-side), the way the TUI/API would. Fails the test if no
// pending request shows up in time.
func approveRelease(t *testing.T, store *approval.FileStore, approver string) {
	t.Helper()
	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range store.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		if reqID == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if reqID == "" {
		t.Fatal("no pending KindQuarantineRelease request was created")
	}
	if _, err := store.Approve(reqID, approver); err != nil {
		t.Fatalf("Approve: %v", err)
	}
}

func sftpPut(t *testing.T, client *sftp.Client, name string, data []byte) error {
	t.Helper()
	f, err := client.Create(name)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close() // the server surfaces a blocked/refused upload here
}

func TestSFTP_InspectionBlocksAndQuarantines(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, q, store, releases := startInspectingServer(t, sink)

	ssh := sshClient(t, addr, "alice%"+targetHost)
	client, err := sftp.NewClient(ssh)
	if err != nil {
		t.Fatal(err)
	}

	// Clean upload: Close() now blocks (Task 11) until a distinct human
	// releases it from quarantine, so drive that concurrently with the put.
	// Approval records a release (Task 6) rather than delivering to the
	// target — the put still succeeds from the client's point of view.
	putErr := make(chan error, 1)
	go func() { putErr <- sftpPut(t, client, "/clean.txt", []byte("totally benign content")) }()
	approveRelease(t, store, "bob")
	if err := <-putErr; err != nil {
		t.Fatalf("clean upload must succeed once released, got %v", err)
	}
	if list := releases.ListFor("alice", time.Now()); len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release", list)
	}

	// EICAR upload is refused outright — blocked content never reaches the
	// release step, so this stays a plain synchronous call.
	if err := sftpPut(t, client, "/virus.txt", []byte("prefix X5O!P%@AP EICAR test string")); err == nil {
		t.Fatal("EICAR upload must be refused")
	}

	// Quarantine holds a byte-level evidentiary copy of every upload now
	// (Task 10: unconditional quarantine on clean, not only blocked content),
	// so both the clean and the blocked upload land in quarantine.
	if q.count() != 2 {
		t.Fatalf("expected 2 quarantined objects (clean + blocked), got %d", q.count())
	}

	// Inspection evidence is now emitted per-upload at write-handle Close()
	// (quarantineWriteHandle.Close(), Task 11), not batched at session end —
	// closing here is just normal cleanup.
	_ = client.Close()

	// Evidence: one clean allow, one blocked deny. Both must carry the
	// client's SourceIP — restored in Close() alongside the disconnect-
	// cancellation fix; the pre-Task-11 runSFTP always included it, and the
	// first draft of remoteFS/quarantineWriteHandle silently dropped it for
	// every emission (inspection, approval, transfer), for both the clean
	// and blocked/unscannable cases.
	deadline := time.Now().Add(2 * time.Second)
	var clean, blocked bool
	var cleanSrcIP, blockedSrcIP string
	for time.Now().Before(deadline) {
		clean, blocked = false, false
		for _, e := range sink.Events() {
			if e.Type != evidence.TypeInspection {
				continue
			}
			if e.Verdict == "clean" && e.Allow != nil && *e.Allow {
				clean, cleanSrcIP = true, e.SourceIP
			}
			if e.Verdict == "blocked" && e.Allow != nil && !*e.Allow && e.ObjectKey != "" {
				blocked, blockedSrcIP = true, e.SourceIP
			}
		}
		if clean && blocked {
			if cleanSrcIP == "" {
				t.Fatal("clean inspection evidence is missing SourceIP")
			}
			if blockedSrcIP == "" {
				t.Fatal("blocked inspection evidence is missing SourceIP")
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected clean+blocked inspection evidence (clean=%v blocked=%v)", clean, blocked)
}

// TestSFTP_ClientDisconnectDuringApprovalWaitUnblocksPromptly is a regression
// test for the connection-scoped disconnect-cancellation fix (handleConn's
// connCtx, threaded through handleSession/runSFTP into remoteFS.ctx): if the
// client's underlying SSH connection to the GATEWAY goes away while a write
// handle's Close() is parked in approvals.Wait — waiting on a human release
// decision that never comes — the gateway must notice promptly, not ride out
// the full approval TTL. startInspectingServer configures a 5s TTL
// specifically so "promptly" (asserted well under that) is distinguishable
// from "the TTL happened to expire".
func TestSFTP_ClientDisconnectDuringApprovalWaitUnblocksPromptly(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, _, store, _ := startInspectingServer(t, sink) // 5s approval TTL

	client := sshClient(t, addr, "alice%"+targetHost)
	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}

	f, err := sc.Create("/upload.txt")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := f.Write([]byte("clean content")); err != nil {
		t.Fatalf("write: %v", err)
	}

	// f.Close() sends FXP_CLOSE; the gateway's quarantineWriteHandle.Close()
	// creates the KindQuarantineRelease request and blocks in approvals.Wait.
	// The client-side call blocks too, waiting for the FXP_STATUS reply that
	// only comes once the gateway's Close() returns — closing the connection
	// below makes this error out on its own; its return value isn't asserted.
	clientCloseErr := make(chan error, 1)
	go func() { clientCloseErr <- f.Close() }()

	// Wait for the pending release request to show up: only past this point
	// do we know the gateway's Close() is actually inside approvals.Wait.
	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range store.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		if reqID == "" {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if reqID == "" {
		t.Fatal("no pending release request was created")
	}

	// Deliberately do NOT approve or deny: sever the client's connection to
	// the GATEWAY instead, simulating the client vanishing while the request
	// is still undecided. If connCtx weren't wired to sconn.Wait(), the
	// gateway's Close() would keep blocking regardless, for up to the full
	// 5s TTL.
	killedAt := time.Now()
	if err := client.Close(); err != nil {
		t.Fatalf("client.Close: %v", err)
	}

	// The gateway must refuse the request well before the 5s TTL elapses —
	// proving Close() reacted to the disconnect, not the TTL.
	var refused bool
	watchDeadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(watchDeadline) && !refused {
		for _, e := range sink.Events() {
			if e.Type == evidence.TypeApproval && e.ObjectKey == reqID && e.Outcome == "refused" {
				refused = true
			}
		}
		if !refused {
			time.Sleep(10 * time.Millisecond)
		}
	}
	elapsed := time.Since(killedAt)
	if !refused {
		t.Fatalf("gateway did not refuse the release within %s of the client disconnecting (approval TTL is 5s) — Close() appears to be riding out the TTL instead of reacting to the disconnect", elapsed)
	}
	if elapsed >= 4*time.Second {
		t.Fatalf("release was refused %s after the disconnect — too close to the 5s TTL to prove the disconnect (not the TTL expiring) unblocked Close()", elapsed)
	}
	t.Logf("Close() unblocked %s after the client disconnected (TTL was 5s)", elapsed)
	<-clientCloseErr // drain; the client-side call errors once the conn is closed
}
