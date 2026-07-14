package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/authn"
	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/recording"
)

// startServerWith wires a server with options and returns its address.
func startServerWith(t *testing.T, p policy.Policy, auth authn.Authenticator, sink evidence.Sink, opts ...Option) string {
	t.Helper()
	hostKey, err := NewEphemeralHostKey()
	if err != nil {
		t.Fatal(err)
	}
	d := dialer.New(p, sink)
	srv := New(hostKey, auth, d, sink, opts...)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String()
}

// waitEvent polls the sink for an event matching pred, up to 3s.
func waitEvent(t *testing.T, sink *evidence.MemSink, pred func(evidence.Event) bool) evidence.Event {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, e := range sink.Events() {
			if pred(e) {
				return e
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no matching evidence event")
	return evidence.Event{}
}

func dbaAuth() fakeAuth { return fakeAuth{users: map[string][]string{"alice": {"dba"}}} }

func TestSlice4_ForwardingRefusedOnFullRecordingTarget(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}, Record: policy.RecordFull}},
	}}}
	sink := evidence.NewMemSink()
	addr := startServerWith(t, p, dbaAuth(), sink)

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err == nil {
		conn.Close()
		t.Fatal("forwarding to a full-recording target must be refused")
	}
	e := waitEvent(t, sink, func(e evidence.Event) bool { return e.Type == evidence.TypeTunnelDecision })
	if e.Allow == nil || *e.Allow || e.RecordMode != string(policy.RecordFull) {
		t.Fatalf("expected a full-mode forwarding refusal, got %+v", e)
	}
}

func TestSlice4_ForwardingAllowedMetadataOnly(t *testing.T) {
	echoHost, echoPort := startEcho(t)
	p := policy.Policy{Roles: []policy.Role{{
		Name: "dba", Groups: []string{"dba"},
		Allow: []policy.Rule{{Host: echoHost, Ports: []int{echoPort}, Record: policy.RecordMetadataOnly}},
	}}}
	sink := evidence.NewMemSink()
	addr := startServerWith(t, p, dbaAuth(), sink)

	client := sshClient(t, addr, "alice")
	conn, err := client.Dial("tcp", fmt.Sprintf("%s:%d", echoHost, echoPort))
	if err != nil {
		t.Fatalf("metadata-only forwarding must be allowed: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte("hi"))
	buf := make([]byte, 2)
	conn.Read(buf)

	e := waitEvent(t, sink, func(e evidence.Event) bool { return e.Type == evidence.TypeTunnelDecision })
	if e.Allow == nil || !*e.Allow || e.RecordMode != string(policy.RecordMetadataOnly) {
		t.Fatalf("expected an allowed metadata-only (unrecorded) decision, got %+v", e)
	}
}

func TestSlice4_SFTPTransferManifest(t *testing.T) {
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink)
	client := sshClient(t, addr, "alice")

	sc, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp client: %v", err)
	}
	payload := []byte("the quick brown fox jumps over the lazy dog\n")
	f, err := sc.Create("/upload.txt")
	if err != nil {
		t.Fatalf("sftp create: %v", err)
	}
	if _, err := f.Write(payload); err != nil {
		t.Fatal(err)
	}
	f.Close()
	sc.Close() // closes the channel -> runSFTP emits manifests

	want := sha256.Sum256(payload)
	e := waitEvent(t, sink, func(e evidence.Event) bool { return e.Type == evidence.TypeTransfer })
	if e.Direction != "upload" || e.Path != "/upload.txt" {
		t.Fatalf("manifest path/direction wrong: %+v", e)
	}
	if e.Bytes != int64(len(payload)) {
		t.Fatalf("manifest size %d, want %d", e.Bytes, len(payload))
	}
	if e.SHA256 != hex.EncodeToString(want[:]) {
		t.Fatalf("manifest hash %s, want %s", e.SHA256, hex.EncodeToString(want[:]))
	}
}

func TestSlice4_RecordedShellProducesAsciicastAndManifest(t *testing.T) {
	store, err := recording.NewFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, WithRecording(store))
	client := sshClient(t, addr, "alice")

	sess, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm", 40, 120, nil); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	sess.Stdout = &nopWriter{}
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	stdin.Write([]byte("hello\r"))
	time.Sleep(50 * time.Millisecond)
	stdin.Write([]byte("exit\r"))
	sess.Wait()

	// A recording manifest event with a hash must appear.
	e := waitEvent(t, sink, func(e evidence.Event) bool { return e.Type == evidence.TypeRecording && e.SHA256 != "" })
	if e.ObjectKey == "" || e.Bytes == 0 {
		t.Fatalf("recording manifest incomplete: %+v", e)
	}

	// The stored asciicast must exist and start with a v2 header.
	data, err := os.ReadFile(store.Root + "/" + e.ObjectKey)
	if err != nil {
		t.Fatalf("read recording %s: %v", e.ObjectKey, err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != e.SHA256 {
		t.Fatal("stored cast hash does not match the manifest (tamper-evident link broken)")
	}
	firstLine := strings.SplitN(string(data), "\n", 2)[0]
	var hdr recording.Header
	if err := json.Unmarshal([]byte(firstLine), &hdr); err != nil || hdr.Version != 2 {
		t.Fatalf("recording is not valid asciicast v2: %q", firstLine)
	}
	// A session_end event must also be present.
	waitEvent(t, sink, func(e evidence.Event) bool { return e.Type == evidence.TypeSessionEnd })
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }
