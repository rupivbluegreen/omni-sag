package session

import (
	"context"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

// fakeChannel is a minimal in-memory ssh.Channel backed by a net.Pipe, enough
// to drive runRecordedShell's Read/Write/Close without a real network
// connection. ssh.Channel is an interface with no in-memory test double
// shipped by golang.org/x/crypto/ssh, unlike a full SSH connection (see
// fakeTargetPipe in target_test.go, which exists for exactly that reason at
// the transport level). No SSH handshake happens over this pipe — it only
// carries the bytes runRecordedShell reads/writes on the client's channel —
// so net.Pipe()'s fully-synchronous behavior is not a problem here.
type fakeChannel struct {
	io.Reader
	io.Writer
	closed bool
}

func (f *fakeChannel) Close() error                                   { f.closed = true; return nil }
func (f *fakeChannel) CloseWrite() error                              { return nil }
func (f *fakeChannel) SendRequest(string, bool, []byte) (bool, error) { return true, nil }
func (f *fakeChannel) Stderr() io.ReadWriter                          { return nil }

var _ ssh.Channel = (*fakeChannel)(nil)

func TestRunRecordedShell_NoTargetRefusesCleanly(t *testing.T) {
	s := &Server{sink: noopSink{}}
	// pr with no TargetHost set (plain "ssh alice@gw" — no "%host" suffix).
	pr := policy.Principal{User: "alice"}

	gwConn, clientConn := net.Pipe()
	gwSide := &fakeChannel{Reader: gwConn, Writer: gwConn}
	defer clientConn.Close()

	done := make(chan struct{})
	go func() {
		s.runRecordedShell(context.Background(), gwSide, 80, 24, pr, "", nil, &targetConnCache{}, "", nil)
		close(done)
	}()

	buf := make([]byte, 256)
	n, _ := clientConn.Read(buf)
	if n == 0 {
		t.Fatal("expected an error message on the channel, got nothing")
	}
	<-done
}

// TestRunRecordedShell_ForwardsWindowChangeToTarget drives a real shell
// session through the full server (real dial via wireFakeTarget) and proves
// handleSession's resizeCh plumbing and runRecordedShell's resize-forwarding
// goroutine actually reach the target: a client-side WindowChange call must
// result in the target observing a "window-change" request with the same
// rows/cols.
func TestRunRecordedShell_ForwardsWindowChangeToTarget(t *testing.T) {
	resizeObserved := make(chan [2]int, 4)
	targetHost, targetOpts := wireFakeTarget(t, "targetpw", resizeObserved)
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, targetOpts...)
	client := sshClient(t, addr, "alice%"+targetHost)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// StdinPipe (not leaving sess.Stdin nil) matters here: with Stdin unset,
	// golang.org/x/crypto/ssh's Session.start() feeds an empty bytes.Buffer
	// into the stdin copy-func, which reaches EOF instantly and sends
	// CloseWrite on the channel right after Shell() — racing (and often
	// beating) runRecordedShell's "either direction closing ends the
	// session" pipe logic, ending the session before WindowChange below is
	// even forwarded. StdinPipe defers the close to us (never called here),
	// keeping the channel open for the duration of this test.
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	sess.Stdout = &nopWriter{}
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	if err := sess.WindowChange(50, 200); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-resizeObserved:
		if got != [2]int{50, 200} {
			t.Fatalf("target observed window-change %v, want [50 200]", got)
		}
	case <-time.After(2 * time.Second):
		for _, e := range sink.Events() {
			t.Logf("evidence: type=%s detail=%q reason=%q", e.Type, e.Detail, e.Reason)
		}
		t.Fatal("target never observed the forwarded window-change request")
	}
}

// TestHandleSession_PtyReqAfterShellDoesNotRace is a regression test for a
// data race found in review: the "shell" case used to launch runRecordedShell
// from a closure that captured handleSession's cols/rows variables BY
// REFERENCE. Because handleSession's request loop keeps running after
// dispatching the shell (precisely so it can keep forwarding window-change —
// see handleSession's doc comment), a further "pty-req" arriving on the same
// channel after "shell" wrote to those same variables concurrently with
// runRecordedShell's goroutine reading them. The fix passes cols/rows as
// arguments to the goroutine, evaluated at the `go` statement (in the
// request-loop goroutine, strictly before the new goroutine starts), so the
// new goroutine only ever sees its own local copies.
//
// This test only has teeth under the race detector: run it with
// `go test -race`. Confirmed (see task-8-report.md) that reverting the fix to
// closure-capture makes this test fail with a reported DATA RACE.
func TestHandleSession_PtyReqAfterShellDoesNotRace(t *testing.T) {
	targetHost, targetOpts := wireFakeTarget(t, "targetpw", nil)
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, targetOpts...)
	client := sshClient(t, addr, "alice%"+targetHost)

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	// StdinPipe, not a nil sess.Stdin: see the comment in the resize test
	// above for why leaving Stdin nil ends the session almost immediately.
	if _, err := sess.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	sess.Stdout = &nopWriter{}
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}

	// A burst of further pty-req requests after the shell has already been
	// dispatched: each one mutates handleSession's cols/rows while the shell
	// goroutine may be concurrently reading them (dialing the target,
	// requesting its PTY, or already bridging).
	for i := 0; i < 50; i++ {
		if err := sess.RequestPty("xterm", 20+i, 90+i, nil); err != nil {
			t.Fatal(err)
		}
	}
}

// TestHandleSession_ShellPanicIsContained is a regression test for a
// panic-containment gap found in review: moving runRecordedShell into its own
// goroutine (to fix window-change forwarding — see handleSession's doc
// comment) took it outside handleConn's per-channel recover (session.go),
// which exists specifically so a panic in one channel's handler cannot crash
// the whole gateway and drop every other live session. Without a matching
// recover on the new goroutine, a panic inside runRecordedShell propagated
// unrecovered and crashed the entire process.
//
// This drives a real panic through the full server (via a WithDialerPeek
// callback that panics on its second call — the first call is
// passwordCallback's own pre-existing, unrelated dialerPeek invocation at
// auth time for prompt-mode chaining; the second is runRecordedShell's) and
// then proves the server is still alive by driving a second, independent
// session through it. If the panic had escaped the recover, the whole
// process — including this test binary — would be gone, not just this one
// connection.
func TestHandleSession_ShellPanicIsContained(t *testing.T) {
	var calls int32
	peek := func(policy.Principal, string) policy.Decision {
		if atomic.AddInt32(&calls, 1) >= 2 {
			panic("boom: injected panic for TestHandleSession_ShellPanicIsContained")
		}
		return policy.Decision{Allow: true, CredentialMode: "inject"}
	}
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, WithDialerPeek(peek))

	client := sshClient(t, addr, "alice%doesnotmatter.lab.local")
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	sess.Stdout = &nopWriter{}
	if err := sess.RequestPty("xterm", 24, 80, nil); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	// The panicking shell session ends one way or another; we don't assert
	// how — the point is that it doesn't take the process down with it.
	_ = sess.Wait()
	_ = sess.Close()

	// Prove the server is still alive by driving a second, independent
	// session through it. If the panic had escaped the recover and crashed
	// the process, this dial (and this whole test binary) would be gone.
	client2 := sshClient(t, addr, "alice")
	sess2, err := client2.NewSession()
	if err != nil {
		t.Fatalf("server did not survive the panic in the shell goroutine: %v", err)
	}
	_ = sess2.Close()
}
