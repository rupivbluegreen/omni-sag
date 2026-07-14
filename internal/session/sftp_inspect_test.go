package session

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/dialer"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
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

func startInspectingServer(t *testing.T, sink evidence.Sink) (string, *memQuarantine) {
	t.Helper()
	q := newMemQuarantine()
	gate, err := inspectgate.New(inspectgate.Config{Inspector: eicarInspector{}, Quarantine: q, Threshold: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	hostKey, _ := NewEphemeralHostKey()
	auth := fakeAuth{users: map[string][]string{"alice": {"dba"}}}
	d := dialer.New(policy.Policy{}, sink)
	srv := New(hostKey, auth, d, sink, WithInspection(gate))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.Serve(ctx, ln)
	return ln.Addr().String(), q
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
	addr, q := startInspectingServer(t, sink)

	ssh := sshClient(t, addr, "alice")
	client, err := sftp.NewClient(ssh)
	if err != nil {
		t.Fatal(err)
	}

	// Clean upload succeeds.
	if err := sftpPut(t, client, "/clean.txt", []byte("totally benign content")); err != nil {
		t.Fatalf("clean upload must succeed, got %v", err)
	}
	// EICAR upload is refused.
	if err := sftpPut(t, client, "/virus.txt", []byte("prefix X5O!P%@AP EICAR test string")); err == nil {
		t.Fatal("EICAR upload must be refused")
	}

	// Quarantine holds a byte-level evidentiary copy of every upload now
	// (Task 10: unconditional quarantine on clean, not only blocked content),
	// so both the clean and the blocked upload land in quarantine.
	if q.count() != 2 {
		t.Fatalf("expected 2 quarantined objects (clean + blocked), got %d", q.count())
	}

	// End the SFTP session so the gateway emits the batched inspection evidence.
	_ = client.Close()

	// Evidence: one clean allow, one blocked deny.
	deadline := time.Now().Add(2 * time.Second)
	var clean, blocked bool
	for time.Now().Before(deadline) {
		clean, blocked = false, false
		for _, e := range sink.Events() {
			if e.Type != evidence.TypeInspection {
				continue
			}
			if e.Verdict == "clean" && e.Allow != nil && *e.Allow {
				clean = true
			}
			if e.Verdict == "blocked" && e.Allow != nil && !*e.Allow && e.ObjectKey != "" {
				blocked = true
			}
		}
		if clean && blocked {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected clean+blocked inspection evidence (clean=%v blocked=%v)", clean, blocked)
}
