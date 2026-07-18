package session

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
)

func TestParseSCPCommand(t *testing.T) {
	cases := []struct {
		name     string
		cmd      string
		wantDir  scpDirection
		wantPath string
		wantErr  string // substring, "" means no error expected
	}{
		{"upload", "scp -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"download", "scp -f /download.txt", scpDownload, "/download.txt", ""},
		{"upload with -p", "scp -p -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"upload with -v -d", "scp -v -d -t /upload.txt", scpUpload, "/upload.txt", ""},
		{"recursive rejected", "scp -r -t /dir", 0, "", "-r"},
		{"missing direction", "scp /path", 0, "", "missing -t or -f"},
		{"conflicting direction", "scp -t -f /path", 0, "", "conflicting"},
		{"not scp", "ls -la", 0, "", "unsupported command"},
		{"unsupported flag", "scp -t -X /path", 0, "", "unsupported flag"},
		{"path with space", "scp -t /path with space", 0, "", "multiple paths"},
		{"path with quote", "scp -t /path'; rm -rf /", 0, "", "unsupported path"},
		{"no path", "scp -t", 0, "", "missing"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir, path, err := parseSCPCommand(c.cmd)
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("parseSCPCommand(%q) error = %v, want nil", c.cmd, err)
				}
				if dir != c.wantDir || path != c.wantPath {
					t.Fatalf("parseSCPCommand(%q) = (%v, %q), want (%v, %q)", c.cmd, dir, path, c.wantDir, c.wantPath)
				}
				return
			}
			if err == nil {
				t.Fatalf("parseSCPCommand(%q) = nil error, want containing %q", c.cmd, c.wantErr)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("parseSCPCommand(%q) error = %q, want containing %q", c.cmd, err.Error(), c.wantErr)
			}
		})
	}
}

func TestScpSendOK(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendOK(&buf); err != nil {
		t.Fatalf("scpSendOK: %v", err)
	}
	if buf.Bytes()[0] != 0 {
		t.Fatalf("scpSendOK wrote %v, want [0]", buf.Bytes())
	}
}

func TestScpSendFatal(t *testing.T) {
	var buf bytes.Buffer
	if err := scpSendFatal(&buf, "boom"); err != nil {
		t.Fatalf("scpSendFatal: %v", err)
	}
	got := buf.Bytes()
	if got[0] != 2 {
		t.Fatalf("scpSendFatal status byte = %d, want 2", got[0])
	}
	if string(got[1:]) != "boom\n" {
		t.Fatalf("scpSendFatal message = %q, want %q", got[1:], "boom\n")
	}
}

func TestScpReadAck(t *testing.T) {
	t.Run("ok", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader([]byte{0}))
		if err := scpReadAck(r); err != nil {
			t.Fatalf("scpReadAck = %v, want nil", err)
		}
	})
	t.Run("fatal with message", func(t *testing.T) {
		r := bufio.NewReader(bytes.NewReader(append([]byte{2}, []byte("no such file\n")...)))
		err := scpReadAck(r)
		if err == nil || !strings.Contains(err.Error(), "no such file") {
			t.Fatalf("scpReadAck = %v, want error containing %q", err, "no such file")
		}
	})
}

func TestScpReadControlLine(t *testing.T) {
	t.Run("plain C line", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("C0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Perm != "0644" || cl.Size != 5 || cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want {0644 5 test.txt}", cl)
		}
		if acked.Len() != 0 {
			t.Fatalf("no T line present, expected no ack written, got %v", acked.Bytes())
		}
	})
	t.Run("T line is acked then C line parsed", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("T1000000000 0 1000000000 0\nC0644 5 test.txt\n"))
		var acked bytes.Buffer
		cl, err := scpReadControlLine(r, &acked)
		if err != nil {
			t.Fatalf("scpReadControlLine: %v", err)
		}
		if cl.Name != "test.txt" {
			t.Fatalf("scpReadControlLine = %+v, want Name test.txt", cl)
		}
		if acked.Len() != 1 || acked.Bytes()[0] != 0 {
			t.Fatalf("T line ack = %v, want single [0] byte", acked.Bytes())
		}
	})
	t.Run("directory record rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("D0755 0 subdir\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil || !strings.Contains(err.Error(), "recursive") {
			t.Fatalf("scpReadControlLine = %v, want error containing %q", err, "recursive")
		}
	})
	t.Run("malformed line rejected", func(t *testing.T) {
		r := bufio.NewReader(strings.NewReader("garbage\n"))
		var acked bytes.Buffer
		_, err := scpReadControlLine(r, &acked)
		if err == nil {
			t.Fatal("scpReadControlLine = nil error, want error on garbage input")
		}
	})
}

// scpExecUpload obtains sess's stdin/stdout pipes, starts cmd (an
// exec-channel "scp -t <path>" invocation — pipes MUST be obtained before
// Start(), per ssh.Session's contract: calling StdinPipe/StdoutPipe after
// Start returns an error), then drives one client-side legacy-protocol
// upload and returns any error the server signalled (nil on success). The
// caller is responsible for sess.Wait() afterward.
func scpExecUpload(t *testing.T, sess *ssh.Session, cmd string, content []byte, name string) error {
	t.Helper()
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.Start(cmd); err != nil {
		return err
	}
	r := bufio.NewReader(stdout)
	// The gateway (sink) sends an initial 0x00 ready byte first — read it
	// before sending our control line, mirroring a real scp source.
	if err := scpReadAck(r); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdin, "C0644 %d %s\n", len(content), name); err != nil {
		return err
	}
	if err := scpReadAck(r); err != nil {
		return err
	}
	if _, err := stdin.Write(content); err != nil {
		return err
	}
	if _, err := stdin.Write([]byte{0}); err != nil {
		return err
	}
	if err := scpReadAck(r); err != nil {
		return err
	}
	return stdin.Close()
}

// scpExecDownload obtains sess's stdin/stdout pipes, starts cmd (an
// exec-channel "scp -f <path>" invocation — same before-Start ordering
// constraint as scpExecUpload), then drives one client-side legacy-protocol
// download and returns the received content. The caller is responsible for
// sess.Wait() afterward.
func scpExecDownload(t *testing.T, sess *ssh.Session, cmd string) []byte {
	t.Helper()
	stdin, err := sess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe: %v", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe: %v", err)
	}
	if err := sess.Start(cmd); err != nil {
		t.Fatalf("Start: %v", err)
	}
	r := bufio.NewReader(stdout)
	// A real scp sink sends its initial 0x00 ready byte first; do the same so
	// the gateway source's handshake read is satisfied.
	if err := scpSendOK(stdin); err != nil {
		t.Fatalf("send initial ready ack: %v", err)
	}
	cl, err := scpReadControlLine(r, stdin)
	if err != nil {
		t.Fatalf("scpExecDownload control line: %v", err)
	}
	if err := scpSendOK(stdin); err != nil {
		t.Fatalf("ack control line: %v", err)
	}
	buf := make([]byte, cl.Size)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("read body: %v", err)
	}
	if _, err := r.ReadByte(); err != nil { // trailing terminator
		t.Fatalf("read trailer: %v", err)
	}
	if err := scpSendOK(stdin); err != nil {
		t.Fatalf("send final ack: %v", err)
	}
	return buf
}

func TestRunSCP_UploadThenDownloadRoundTripsThroughRealTarget(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append([]Option{WithSCPEnabled(true)}, targetOpts...)
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)

	client := sshClient(t, addr, "alice%"+targetHost)

	uploadSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (upload): %v", err)
	}
	content := []byte("hello via legacy scp protocol\n")
	if err := scpExecUpload(t, uploadSess, "scp -t /roundtrip.txt", content, "roundtrip.txt"); err != nil {
		t.Fatalf("scpExecUpload: %v", err)
	}
	if err := uploadSess.Wait(); err != nil {
		t.Fatalf("upload Wait: %v", err)
	}
	uploadSess.Close()

	downloadSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (download): %v", err)
	}
	got := scpExecDownload(t, downloadSess, "scp -f /roundtrip.txt")
	if err := downloadSess.Wait(); err != nil {
		t.Fatalf("download Wait: %v", err)
	}
	downloadSess.Close()

	if string(got) != string(content) {
		t.Fatalf("round-tripped content = %q, want %q", got, content)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeSessionStart && e.User == "alice" && e.Detail == "scp"
	})
}

func TestRunSCP_DisabledByDefaultRefusesExec(t *testing.T) {
	// No WithSCPEnabled option: legacy scp is opt-in and OFF by default, so
	// the exec request must be refused even though policy would allow the
	// target.
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, targetOpts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	if err := sess.Start("scp -t /blocked.txt"); err == nil {
		t.Fatal("Start = nil, want error: scp is opt-in and must be refused unless enable_scp is set")
	}
}

func TestRunSCP_RefusedSessionEmitsExactlyOneSessionEnd(t *testing.T) {
	// A target-resolution refusal (here: policy-deny) must emit exactly one
	// SessionEnd event carrying the refusal reason — not a detailed one from
	// runSCPTransfer plus a second bare one from runSCP. Wire a target via
	// wireFakeSFTPTarget (which supplies its own allowing WithDialerPeek),
	// then override it with a denying WithDialerPeek applied afterward —
	// options are applied in order in New, so the later one wins.
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append([]Option{WithSCPEnabled(true)}, targetOpts...)
	opts = append(opts, WithDialerPeek(func(policy.Principal, string) policy.Decision {
		return policy.Decision{Allow: false, Reason: "denied for test"}
	}))
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	if err := sess.Start("scp -t /denied.txt"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// The refusal is signalled via the classic-SCP fatal status byte, not an
	// SSH-level Start error, so Wait returns the exec's exit-status (1) as an
	// *ssh.ExitError rather than nil — that's expected here.
	_ = sess.Wait()
	sess.Close()

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeSessionEnd && e.Detail == "scp refused: denied for test"
	})

	count := 0
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeSessionEnd {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("SessionEnd event count = %d, want exactly 1 (events: %+v)", count, sink.Events())
	}
}

func TestRunSCP_RecursiveFlagRefused(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, nil)
	sink := evidence.NewMemSink()
	opts := append([]Option{WithSCPEnabled(true)}, targetOpts...)
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, opts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	// scp IS enabled here, so this exercises the parser's -r rejection, not
	// the enable gate: the exec request is refused because parseSCPCommand
	// rejects -r, not because scp is off.
	if err := sess.Start("scp -r -t /dir"); err == nil {
		t.Fatal("Start = nil, want error: -r must be refused")
	}
}

func TestRunSCP_CleanUploadQuarantinedAndReleasedNotPushed(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, q, store, releases := startInspectingServer(t, sink)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	uploadErr := make(chan error, 1)
	go func() {
		uploadErr <- scpExecUpload(t, sess, "scp -t /clean.txt", []byte("totally benign content"), "clean.txt")
	}()
	approveRelease(t, store, "bob")
	if err := <-uploadErr; err != nil {
		t.Fatalf("clean upload must succeed once released, got %v", err)
	}
	if err := sess.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	sess.Close()

	if list := releases.ListFor("alice", time.Now()); len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release", list)
	}
	if q.count() != 1 {
		t.Fatalf("quarantine object count = %d, want 1", q.count())
	}

	// Never pushed to the target: reading it back via a fresh scp -f must
	// fail (the file was never written there).
	getSess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession (verify): %v", err)
	}
	defer getSess.Close()
	stdout, err := getSess.StdoutPipe()
	if err != nil {
		t.Fatalf("StdoutPipe (verify): %v", err)
	}
	stdin, err := getSess.StdinPipe()
	if err != nil {
		t.Fatalf("StdinPipe (verify): %v", err)
	}
	if err := getSess.Start("scp -f /clean.txt"); err != nil {
		t.Fatalf("Start (verify): %v", err)
	}
	r := bufio.NewReader(stdout)
	if _, err := scpReadControlLine(r, stdin); err == nil {
		t.Fatal("scp -f /clean.txt succeeded — upload must never reach the target")
	}
}

func TestRunSCP_BlockedUploadRefusedNeverReleased(t *testing.T) {
	sink := evidence.NewMemSink()
	addr, targetHost, q, store, _ := startInspectingServer(t, sink)

	client := sshClient(t, addr, "alice%"+targetHost)
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	defer sess.Close()
	err = scpExecUpload(t, sess, "scp -t /virus.txt", []byte("prefix X5O!P%@AP EICAR test string"), "virus.txt")
	if err == nil {
		t.Fatal("scpExecUpload = nil error, want refusal for EICAR content")
	}

	if q.count() != 1 {
		t.Fatalf("quarantine object count = %d, want 1 (blocked content is still quarantined for evidence)", q.count())
	}
	for _, r := range store.List() {
		if r.Kind == approval.KindQuarantineRelease {
			t.Fatalf("blocked upload must never create a release request, found: %+v", r)
		}
	}
}
