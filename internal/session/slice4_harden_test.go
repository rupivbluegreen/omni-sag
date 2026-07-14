package session

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// Fix #1: a client-controlled offset must never size an allocation.
func TestMemFile_RejectsBadOffsets(t *testing.T) {
	f := &memFile{name: "/x"}
	if _, err := f.WriteAt([]byte("a"), -1); err == nil {
		t.Fatal("negative write offset must error, not panic/alloc")
	}
	if _, err := f.WriteAt([]byte("a"), maxMemFileSize+1); err == nil {
		t.Fatal("over-limit write offset must error")
	}
	if _, err := f.WriteAt([]byte("a"), math.MaxInt64); err == nil {
		t.Fatal("overflowing write offset must error")
	}
	if _, err := f.ReadAt(make([]byte, 1), -1); err == nil {
		t.Fatal("negative read offset must error")
	}
	// A sane write still works.
	if _, err := f.WriteAt([]byte("hello"), 0); err != nil {
		t.Fatalf("valid write must succeed: %v", err)
	}
}

// Fix #3: the upload manifest is captured at handle-close and survives a later
// rename or remove (no evidence evasion).
func TestSFTP_ManifestSurvivesRename(t *testing.T) {
	m := newMemFS(nil, context.Background(), "alice")
	wh, err := m.Filewrite(&sftp.Request{Filepath: "/tmp/upload.tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := wh.WriteAt([]byte("hello"), 0); err != nil {
		t.Fatal(err)
	}
	if err := wh.(io.Closer).Close(); err != nil {
		t.Fatal(err)
	}
	// Client renames temp -> final (default SFTP client behavior).
	if err := m.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/tmp/upload.tmp", Target: "/final.txt"}); err != nil {
		t.Fatal(err)
	}
	ms := m.manifests()
	if len(ms) != 1 || ms[0].direction != "upload" || ms[0].size != 5 {
		t.Fatalf("upload manifest lost after rename: %+v", ms)
	}
}

func TestSFTP_ManifestSurvivesRemove(t *testing.T) {
	m := newMemFS(nil, context.Background(), "alice")
	wh, _ := m.Filewrite(&sftp.Request{Filepath: "/payload"})
	_, _ = wh.WriteAt([]byte("abcd"), 0)
	_ = wh.(io.Closer).Close()
	// Attacker removes the file before the session ends.
	if err := m.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/payload"}); err != nil {
		t.Fatal(err)
	}
	ms := m.manifests()
	if len(ms) != 1 || ms[0].direction != "upload" {
		t.Fatalf("upload manifest lost after remove: %+v", ms)
	}
}

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
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, fakeAuth{users: map[string][]string{"alice": {"dba"}}}, d, sink, WithRecording(failStore{}))

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)

	client := sshClient(t, ln.Addr().String(), "alice")
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
