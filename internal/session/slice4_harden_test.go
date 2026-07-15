package session

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// failStore is a recording.Store whose Create always fails.
type failStore struct{}

func (failStore) Create(context.Context, string) (io.WriteCloser, error) {
	return nil, errors.New("recording store down")
}

// Fix #4: when recording is required but unavailable, the interactive session
// fails closed (refused) and the failure is evidenced.
func TestRecording_FailsClosedWhenStoreUnavailable(t *testing.T) {
	sink := evidence.NewMemSink()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	targetHost, targetOpts := wireFakeTarget(t, "targetpw", nil)
	opts := append([]Option{WithRecording(failStore{})}, targetOpts...)
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, fakeAuth{users: map[string][]string{"alice": {"dba"}}}, d, sink, opts...)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)

	client := sshClient(t, ln.Addr().String(), "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	out, err := sess.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(out) // server closes the channel after refusing
	if !strings.Contains(string(data), "recording unavailable") {
		t.Fatalf("expected a refusal message, got %q", data)
	}

	// A recording-failure event (allow=false) must be evidenced.
	deadline := time.Now().Add(2 * time.Second)
	found := false
	for time.Now().Before(deadline) && !found {
		for _, e := range sink.Events() {
			if e.Type == evidence.TypeRecording && e.Allow != nil && !*e.Allow {
				found = true
			}
		}
		if !found {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if !found {
		t.Fatal("expected a recording-failure evidence event (allow=false)")
	}
}
