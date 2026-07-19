package session

import (
	"bytes"
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func TestTunnelAnnouncer_BuffersUntilDrained(t *testing.T) {
	a := newTunnelAnnouncer()
	// Announced before a keeper drains → buffered in order, drained FIFO.
	a.announce("one\r\n")
	a.announce("two\r\n")
	if got := <-a.notices; got != "one\r\n" {
		t.Fatalf("first drained notice = %q, want %q", got, "one\r\n")
	}
	if got := <-a.notices; got != "two\r\n" {
		t.Fatalf("second drained notice = %q, want %q", got, "two\r\n")
	}
}

func TestTunnelAnnouncer_NonBlockingAndBounded(t *testing.T) {
	a := newTunnelAnnouncer()
	// No keeper is draining. Announcing far past capacity must neither block
	// (this test would hang) nor grow beyond the buffer — excess is dropped.
	for i := 0; i < maxPendingTunnelNotices*3; i++ {
		a.announce("x\r\n")
	}
	if got := len(a.notices); got != maxPendingTunnelNotices {
		t.Fatalf("buffered notices should cap at %d, got %d", maxPendingTunnelNotices, got)
	}
}

func TestTunnelOpenNotice(t *testing.T) {
	got := tunnelOpenNotice("alice", "192.0.2.10", 22)
	if !strings.Contains(got, "alice") || !strings.Contains(got, "192.0.2.10:22") || !strings.HasSuffix(got, "\r\n") {
		t.Fatalf("unexpected notice: %q", got)
	}
}

// TestRunTunnelKeeper_BannerAnnounceAndClose drives the keeper over a
// fakeChannel: it prints its banner, relays a live tunnel notice, and returns
// when the client closes the channel.
func TestRunTunnelKeeper_BannerAnnounceAndClose(t *testing.T) {
	s := &Server{sink: noopSink{}}
	pr := policy.Principal{User: "alice"}
	a := newTunnelAnnouncer()

	gwConn, clientConn := net.Pipe()
	gwSide := &fakeChannel{Reader: gwConn, Writer: gwConn}

	// Continuously drain whatever the client would see into a buffer.
	var mu sync.Mutex
	var seen bytes.Buffer
	go func() {
		b := make([]byte, 256)
		for {
			n, err := clientConn.Read(b)
			if n > 0 {
				mu.Lock()
				seen.Write(b[:n])
				mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		s.runTunnelKeeper(context.Background(), gwSide, pr, "", a)
		close(done)
	}()

	waitForContains(t, &mu, &seen, "no shell target selected")
	waitForContains(t, &mu, &seen, "keep this window open")

	// A tunnel authorizing after the keeper attached shows up live. Announce in
	// its own goroutine: the write blocks on net.Pipe until the reader drains it.
	go a.announce(tunnelOpenNotice("alice", "192.0.2.10", 22))
	waitForContains(t, &mu, &seen, "192.0.2.10:22")

	// Client closing the window ends the keeper.
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keeper did not return after the client closed the channel")
	}
}

// TestRunTunnelKeeper_CtrlCEnds proves Ctrl-C (ETX, forwarded as a byte under a
// PTY) ends the keeper — otherwise the user has no in-band way to close it.
func TestRunTunnelKeeper_CtrlCEnds(t *testing.T) {
	s := &Server{sink: noopSink{}}
	a := newTunnelAnnouncer()
	gwConn, clientConn := net.Pipe()
	gwSide := &fakeChannel{Reader: gwConn, Writer: gwConn}

	// Drain the banner so the keeper's writes don't block on net.Pipe.
	go func() {
		b := make([]byte, 256)
		for {
			if _, err := clientConn.Read(b); err != nil {
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() {
		s.runTunnelKeeper(context.Background(), gwSide, policy.Principal{User: "alice"}, "", a)
		close(done)
	}()

	if _, err := clientConn.Write([]byte{0x03}); err != nil { // Ctrl-C
		t.Fatalf("write ctrl-c: %v", err)
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("keeper did not end on Ctrl-C")
	}
}

func waitForContains(t *testing.T, mu *sync.Mutex, buf *bytes.Buffer, want string) {
	t.Helper()
	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		got := buf.String()
		mu.Unlock()
		if strings.Contains(got, want) {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for %q; got %q", want, got)
		case <-time.After(10 * time.Millisecond):
		}
	}
}
