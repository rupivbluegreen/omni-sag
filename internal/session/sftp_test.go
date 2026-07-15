package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/credential"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/release"
)

// startFakeSFTPTarget runs an in-process SSH server that serves the "sftp"
// subsystem with a real github.com/pkg/sftp request server backed by
// sftp.InMemHandler(), seeded with the given files, and returns a client-side
// net.Conn to dial (a fresh connection, independent of the one used to seed
// the files below — see the deviation note). It runs until the test ends.
//
// Two deliberate deviations from a naive first draft of this helper, found
// while implementing this task:
//
//  1. It listens on TCP loopback and dials it (like Task 7's
//     target_test.go's fakeTargetPipe helper), not net.Pipe(): a raw
//     net.Pipe() is fully synchronous with zero internal buffering, and the
//     SSH transport's version exchange has both sides write their
//     identification line before reading the peer's — over net.Pipe that
//     deadlocks every time (see fakeTargetPipe's doc comment for the full
//     explanation). A listener is used here, rather than fakeTargetPipe
//     itself, because this helper needs a second, internal connection to
//     seed files (deviation 2 below) in addition to the one returned to the
//     caller.
//
//  2. It backs the fake server with sftp.InMemHandler() (a pure in-memory
//     virtual filesystem), not sftp.NewServer(ch, sftp.WithServerWorkingDirectory(dir))
//     over a real temp dir. sftp.NewServer's workDir option only rewrites
//     *relative* request paths (see server_unix.go: "if s.workDir != "" &&
//     !path.IsAbs(p)"); every request this package's remoteFS/memFS sends is
//     made absolute first by cleanPath (path.Clean("/"+p)), so workDir never
//     applies and sftp.NewServer instead serves the real OS filesystem
//     rooted at "/". Confirmed the hard way: an earlier version of this test
//     requesting "/etc/motd" silently returned the *test runner's own*
//     /etc/motd instead of the seeded temp-dir file, and only failed because
//     the content happened to differ. sftp.InMemHandler() cannot leak host
//     files at all, for any path, so it is used instead — it is still a real
//     wire-protocol SFTP server (sftp.NewRequestServer + Handlers, the same
//     shape production runSFTP uses), just backed by memory instead of disk.
func startFakeSFTPTarget(t *testing.T, files map[string][]byte) net.Conn {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	cfg.AddHostKey(testHostKey(t))

	// Shared across every connection this fake target accepts, so a
	// seeding connection (below) and the caller's own connection observe
	// the same virtual filesystem.
	handlers := sftp.InMemHandler()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	serveConn := func(conn net.Conn) {
		sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
		if err != nil {
			return
		}
		defer sconn.Close()
		go ssh.DiscardRequests(reqs)
		for newCh := range chans {
			if newCh.ChannelType() != "session" {
				_ = newCh.Reject(ssh.UnknownChannelType, "")
				continue
			}
			ch, reqs, err := newCh.Accept()
			if err != nil {
				continue
			}
			go func() {
				// The request server does not close ch itself when Serve
				// returns (only conn-level errors trigger that internally):
				// closing here is required so the client's sftp.Client.Close
				// (which waits for the channel's read side to reach EOF)
				// doesn't block forever after Serve exits.
				defer ch.Close()
				for req := range reqs {
					isSubsystem := req.Type == "subsystem"
					req.Reply(isSubsystem, nil)
					if isSubsystem {
						_ = sftp.NewRequestServer(ch, handlers).Serve()
						return
					}
				}
			}()
		}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed on test cleanup
			}
			go serveConn(conn)
		}
	}()

	// Seed the requested files over a throwaway connection/client, before
	// handing the caller their own connection to the same shared handlers.
	seedConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: seed dial: %v", err)
	}
	// seedClient.Close() below only closes the SFTP subsystem session, not
	// the underlying ssh.Client/net.Conn (pkg/sftp's Client.Close tears down
	// its own session but doesn't own the transport it was built over) — so
	// the raw conn needs its own cleanup or its server- and client-side
	// transport goroutines leak for the life of the test binary.
	t.Cleanup(func() { seedConn.Close() })
	seedClient, err := sftp.NewClient(sshClientOver(t, seedConn))
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: seed sftp client: %v", err)
	}
	for name, content := range files {
		if dir := path.Dir(name); dir != "/" && dir != "." {
			if err := seedClient.MkdirAll(dir); err != nil {
				t.Fatalf("seed file %s: mkdir %s: %v", name, dir, err)
			}
		}
		f, err := seedClient.Create(name)
		if err != nil {
			t.Fatalf("seed file %s: create: %v", name, err)
		}
		if _, err := f.Write(content); err != nil {
			t.Fatalf("seed file %s: write: %v", name, err)
		}
		if err := f.Close(); err != nil {
			t.Fatalf("seed file %s: close: %v", name, err)
		}
	}
	if err := seedClient.Close(); err != nil {
		t.Fatalf("startFakeSFTPTarget: seed client close: %v", err)
	}

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("startFakeSFTPTarget: dial: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })
	return clientConn
}

// wireFakeSFTPTarget seeds a fake target's (in-memory, wire-protocol-real)
// SFTP filesystem via startFakeSFTPTarget, then — like target_test.go's
// wireFakeTarget, but for an SFTP target instead of a shell one — overrides
// the package-level dialNet seam so the gateway's real second-leg dial to
// targetHost hands back that one fake connection, and returns the Options a
// Server needs to reach it (inject-mode credential with a throwaway fetcher,
// since the fake target's ssh.ServerConfig{NoClientAuth: true} accepts any
// credential; and WithInsecureTargetHostKey, since the fake target has no
// real host key to verify against).
func wireFakeSFTPTarget(t *testing.T, files map[string][]byte) (targetHost string, opts []Option) {
	t.Helper()
	fakeConn := startFakeSFTPTarget(t, files)
	orig := dialNet
	dialNet = func(network, addr string, timeout time.Duration) (net.Conn, error) { return fakeConn, nil }
	t.Cleanup(func() { dialNet = orig })

	prov := credential.NewProvider(credential.Config{
		Fetcher: fakeFetcher{secret: []byte("unused")},
		Query:   func(credential.Request) credential.Query { return credential.Query{} },
	})
	return "fake-sftp-target.lab.local", []Option{
		WithCredentialProvider(prov),
		WithDialerPeek(func(policy.Principal, string) policy.Decision {
			return policy.Decision{Allow: true, CredentialMode: "inject"}
		}),
		WithInsecureTargetHostKey(),
	}
}

// sshClientOver completes an ssh.ClientConfig handshake over conn for test
// use (no auth, insecure host key check — the fake target above requires
// neither).
func sshClientOver(t *testing.T, conn net.Conn) *ssh.Client {
	t.Helper()
	clientConn, chans, reqs, err := ssh.NewClientConn(conn, "target", &ssh.ClientConfig{
		User: "test", Auth: nil, HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	})
	if err != nil {
		t.Fatalf("ssh.NewClientConn: %v", err)
	}
	return ssh.NewClient(clientConn, chans, reqs)
}

// cleanInspector always returns a clean verdict, consuming the whole body —
// used by the quarantine-release tests below, where the inspection verdict
// itself is not what's under test (only what happens after a clean verdict).
type cleanInspector struct{}

func (cleanInspector) Inspect(_ context.Context, _ inspect.TransferMeta, body io.Reader) (inspect.Result, error) {
	_, _ = io.Copy(io.Discard, body)
	return inspect.Result{Verdict: inspect.VerdictClean, ICAPStatus: 204}, nil
}

// newFakeBlobStore is a small alias so the tests below read the way the task
// brief describes them; memQuarantine (sftp_inspect_test.go, same package)
// already implements inspectgate.BlobStore.
func newFakeBlobStore() *memQuarantine { return newMemQuarantine() }

func TestWithReleases_SetsFieldsOnServer(t *testing.T) {
	store, err := release.NewFileStore(filepath.Join(t.TempDir(), "r.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	s := &Server{}
	WithReleases(store, 6*time.Hour)(s)
	if s.releases != store {
		t.Fatal("WithReleases did not set s.releases")
	}
	if s.releaseTTL != 6*time.Hour {
		t.Fatalf("s.releaseTTL = %v, want 6h", s.releaseTTL)
	}
}

// TestQuarantineWriteHandle_AutoDeniedWithNoApprovalStoreFailsClosed: even a
// clean-verdict upload must never reach the target when there is no approval
// store to release it from quarantine — fail closed, not fail open.
func TestQuarantineWriteHandle_AutoDeniedWithNoApprovalStoreFailsClosed(t *testing.T) {
	quar := newFakeBlobStore()
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	s := &Server{sink: noopSink{}, inspect: g} // s.approvals is nil
	fs := &remoteFS{client: targetClient, gate: g, srv: s}
	h, err := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})
	if err != nil {
		t.Fatalf("Filewrite: %v", err)
	}
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}
	if err := h.(io.Closer).Close(); err == nil {
		t.Fatal("Close must fail closed when inspection is enabled but no approval store is configured")
	}
	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("content must never reach the target when there is no approval store")
	}
}

// TestQuarantineWriteHandle_ApprovedRecordsReleaseNotPush: a clean upload
// blocks on Close() until a distinct human approves the
// KindQuarantineRelease request, then (and only then) a release is recorded
// — the bytes are never pushed to the target (supersedes the old
// ApprovedDeliversToTarget behavior from before this task).
func TestQuarantineWriteHandle_ApprovedRecordsReleaseNotPush(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	approvals, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("approval.NewFileStore: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	s := &Server{sink: noopSink{}, inspect: g, approvals: approvals, approvalTTL: 5 * time.Second, releases: releases, releaseTTL: 6 * time.Hour}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice", matchedGroups: []string{"dba"}, releases: releases, releaseTTL: 6 * time.Hour}

	h, _ := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range approvals.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending release request")
	}
	if _, err := approvals.Approve(reqID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := <-closeErr; err != nil {
		t.Fatalf("Close after approval: %v", err)
	}

	// The target must NEVER have received the file — this is the core
	// behavior change: pull, not push.
	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("approved upload must NOT be delivered to the target — pull-download model, not push")
	}
	// A release must exist for alice, listing the original filename.
	list := releases.ListFor("alice", time.Now())
	if len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release", list)
	}
	if list[0].OriginalFilename != "/upload.txt" {
		t.Fatalf("release.OriginalFilename = %q, want /upload.txt", list[0].OriginalFilename)
	}
}

func TestQuarantineWriteHandle_ApprovedButNoReleaseStoreConfiguredFailsClosed(t *testing.T) {
	quar := newFakeBlobStore()
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	approvals, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("approval.NewFileStore: %v", err)
	}
	// No releases store configured — s.releases is nil.
	s := &Server{sink: noopSink{}, inspect: g, approvals: approvals, approvalTTL: 5 * time.Second}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice"}

	h, _ := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})
	_, _ = h.WriteAt([]byte("clean content"), 0)

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range approvals.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending release request")
	}
	if _, err := approvals.Approve(reqID, "bob"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := <-closeErr; err == nil {
		t.Fatal("Close must fail closed when approved but no release store is configured to record it")
	}
}

// TestQuarantineWriteHandle_DeniedNeverReachesTarget: a denied release must
// error Close() and the content must never land on the target.
func TestQuarantineWriteHandle_DeniedNeverReachesTarget(t *testing.T) {
	quar := newFakeBlobStore()
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	store, _ := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	s := &Server{sink: noopSink{}, inspect: g, approvals: store, approvalTTL: 5 * time.Second}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice"}

	h, _ := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})
	_, _ = h.WriteAt([]byte("clean content"), 0)

	closeErr := make(chan error, 1)
	go func() { closeErr <- h.(io.Closer).Close() }()

	var reqID string
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && reqID == "" {
		for _, r := range store.List() {
			if r.Kind == approval.KindQuarantineRelease && r.Status == approval.StatusPending {
				reqID = r.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if reqID == "" {
		t.Fatal("no pending request")
	}
	if _, err := store.Deny(reqID, "bob"); err != nil {
		t.Fatalf("Deny: %v", err)
	}
	if err := <-closeErr; err == nil {
		t.Fatal("Close must error when the release was denied")
	}
	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("denied content must never reach the target")
	}
}

func TestRemoteFS_FilereadProxiesRealTarget(t *testing.T) {
	fakeConn := startFakeSFTPTarget(t, map[string][]byte{"/etc/motd": []byte("hello from target\n")})
	client, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer client.Close()

	fs := &remoteFS{client: client, gate: nil}
	r, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/etc/motd"})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := r.ReadAt(buf, 0)
	if got := string(buf[:n]); got != "hello from target\n" {
		t.Fatalf("Fileread content = %q, want %q", got, "hello from target\n")
	}
}

// --- Important finding #2: downloads must produce a evidence.TypeTransfer
// manifest (path, size, SHA256, Direction: "download"), like the old
// in-memory memFS.Fileread did — the new remoteFS.Fileread must not
// silently drop that record. ---

func TestRemoteFS_FilereadEmitsDownloadTransferEvidence(t *testing.T) {
	content := []byte("hello from target, this is the full file content\n")
	fakeConn := startFakeSFTPTarget(t, map[string][]byte{"/etc/motd": content})
	client, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer client.Close()

	sink := evidence.NewMemSink()
	s := &Server{sink: sink}
	fs := &remoteFS{client: client, srv: s, user: "alice", srcIP: "10.0.0.1"}

	r, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/etc/motd"})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	// Read in two small chunks (not one buffer sized to fit the whole file)
	// so the manifest reflects genuinely-streamed reads, not a single ReadAt
	// call that happens to slurp everything at once.
	buf := make([]byte, len(content))
	total := 0
	for total < len(content) {
		chunkLen := 8
		if total+chunkLen > len(buf) {
			chunkLen = len(buf) - total
		}
		n, rerr := r.ReadAt(buf[total:total+chunkLen], int64(total))
		total += n
		if rerr != nil {
			if rerr == io.EOF && total == len(content) {
				break
			}
			if rerr != io.EOF {
				t.Fatalf("ReadAt: %v", rerr)
			}
		}
	}
	if string(buf[:total]) != string(content) {
		t.Fatalf("read content = %q, want %q", buf[:total], content)
	}
	closer, ok := r.(io.Closer)
	if !ok {
		t.Fatal("Fileread's returned io.ReaderAt must also implement io.Closer (pkg/sftp's request-server only closes handles that do)")
	}
	if err := closer.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var transfers []evidence.Event
	for _, e := range sink.Events() {
		if e.Type == evidence.TypeTransfer {
			transfers = append(transfers, e)
		}
	}
	if len(transfers) != 1 {
		t.Fatalf("want exactly 1 evidence.TypeTransfer event, got %d: %+v", len(transfers), transfers)
	}
	e := transfers[0]
	if e.Path != "/etc/motd" || e.Direction != "download" {
		t.Fatalf("transfer event path/direction = %+v, want /etc/motd/download", e)
	}
	if e.Bytes != int64(len(content)) {
		t.Fatalf("transfer event bytes = %d, want %d", e.Bytes, len(content))
	}
	wantSum := sha256.Sum256(content)
	if e.SHA256 != hex.EncodeToString(wantSum[:]) {
		t.Fatalf("transfer event sha256 = %s, want %s (must match the actual file content)", e.SHA256, hex.EncodeToString(wantSum[:]))
	}
	if e.User != "alice" || e.SourceIP != "10.0.0.1" {
		t.Fatalf("transfer event user/sourceip = %+v, want alice/10.0.0.1", e)
	}
}

// --- Important finding #3: Filecmd (Remove/Rename/Mkdir/Rmdir) now performs
// real destructive operations on the real target and must leave an evidence
// trail — the old in-memory memFS only mutated a throwaway map, so it never
// needed one. ---

func TestRemoteFS_FilecmdEmitsEvidenceForDestructiveOps(t *testing.T) {
	fakeConn := startFakeSFTPTarget(t, map[string][]byte{"/file.txt": []byte("content")})
	client, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer client.Close()

	sink := evidence.NewMemSink()
	s := &Server{sink: sink}
	fs := &remoteFS{client: client, srv: s, user: "alice", srcIP: "10.0.0.1"}

	if err := fs.Filecmd(&sftp.Request{Method: "Mkdir", Filepath: "/newdir"}); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.Filecmd(&sftp.Request{Method: "Rename", Filepath: "/file.txt", Target: "/renamed.txt"}); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if err := fs.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/renamed.txt"}); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if err := fs.Filecmd(&sftp.Request{Method: "Rmdir", Filepath: "/newdir"}); err != nil {
		t.Fatalf("Rmdir: %v", err)
	}

	wantPath := map[string]string{
		"mkdir":  "/newdir",
		"rename": "/file.txt",
		"remove": "/renamed.txt",
		"rmdir":  "/newdir",
	}
	gotPath := map[string]string{}
	var renameDetail string
	for _, e := range sink.Events() {
		if e.Type != evidence.TypeTransfer {
			continue
		}
		gotPath[e.Direction] = e.Path
		if e.Direction == "rename" {
			renameDetail = e.Detail
		}
		if e.User != "alice" || e.SourceIP != "10.0.0.1" {
			t.Fatalf("filecmd evidence missing user/sourceip: %+v", e)
		}
		if e.Allow == nil || !*e.Allow {
			t.Fatalf("filecmd evidence for a successful op must have Allow=true: %+v", e)
		}
	}
	for op, wantP := range wantPath {
		if gotPath[op] != wantP {
			t.Fatalf("filecmd evidence for %q: path = %q, want %q (recorded: %+v)", op, gotPath[op], wantP, gotPath)
		}
	}
	if !strings.Contains(renameDetail, "/renamed.txt") {
		t.Fatalf("rename evidence detail = %q, want it to mention the destination /renamed.txt", renameDetail)
	}
}

// --- Minor finding #5: quarantineWriteHandle.Close() must be idempotent —
// a second call must not re-emit inspection evidence, create a second
// KindQuarantineRelease request, or record a second release. ---

func TestQuarantineWriteHandle_CloseIsIdempotent(t *testing.T) {
	quar := newFakeBlobStore()
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	fakeConn := startFakeSFTPTarget(t, nil)
	targetClient, err := sftp.NewClient(sshClientOver(t, fakeConn))
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	defer targetClient.Close()

	store, err := approval.NewFileStore(filepath.Join(t.TempDir(), "approvals.json"))
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	s := &Server{sink: noopSink{}, inspect: g, approvals: store, approvalTTL: 5 * time.Second, releases: releases, releaseTTL: 6 * time.Hour}
	fs := &remoteFS{client: targetClient, gate: g, srv: s, user: "alice", releases: releases, releaseTTL: 6 * time.Hour}

	h, err := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/upload.txt"})
	if err != nil {
		t.Fatalf("Filewrite: %v", err)
	}
	if _, err := h.WriteAt([]byte("clean content"), 0); err != nil {
		t.Fatalf("WriteAt: %v", err)
	}

	firstErr := make(chan error, 1)
	go func() { firstErr <- h.(io.Closer).Close() }()
	approveRelease(t, store, "bob")
	first := <-firstErr
	if first != nil {
		t.Fatalf("first Close: %v", first)
	}

	// A second Close() must return immediately — reusing the cached result,
	// not re-entering the approval-wait machinery (which would otherwise
	// create a second request and hang this goroutine on an approval that
	// will never come).
	secondDone := make(chan error, 1)
	go func() { secondDone <- h.(io.Closer).Close() }()
	select {
	case second := <-secondDone:
		if second != nil {
			t.Fatalf("second Close = %v, want nil (same as first)", second)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("second Close() did not return promptly — Close is not idempotent")
	}

	releaseReqs := 0
	for _, r := range store.List() {
		if r.Kind == approval.KindQuarantineRelease {
			releaseReqs++
		}
	}
	if releaseReqs != 1 {
		t.Fatalf("want exactly 1 KindQuarantineRelease request created across both Close() calls, got %d", releaseReqs)
	}

	if _, err := targetClient.Open("/upload.txt"); err == nil {
		t.Fatal("approved upload must NOT be delivered to the target — pull-download model, not push")
	}
	list := releases.ListFor("alice", time.Now())
	if len(list) != 1 {
		t.Fatalf("releases.ListFor(alice) = %v, want exactly one release (not duplicated by a second Close)", list)
	}
}

// --- Minor finding #4: a successful SFTP session must emit
// TypeSessionStart/TypeSessionEnd, not just the refusal branches. ---

func TestRunSFTP_EmitsSessionStartAndEndOnNormalCompletion(t *testing.T) {
	targetHost, targetOpts := wireFakeSFTPTarget(t, map[string][]byte{"/etc/motd": []byte("hi\n")})
	sink := evidence.NewMemSink()
	addr := startServerWith(t, policy.Policy{}, dbaAuth(), sink, targetOpts...)

	client := sshClient(t, addr, "alice%"+targetHost)
	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("sftp.NewClient: %v", err)
	}
	if _, err := sftpClient.ReadDir("/"); err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if err := sftpClient.Close(); err != nil {
		t.Fatalf("sftpClient.Close: %v", err)
	}

	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeSessionStart && e.User == "alice" && e.Detail == "sftp"
	})
	waitEvent(t, sink, func(e evidence.Event) bool {
		return e.Type == evidence.TypeSessionEnd && e.User == "alice" && e.Detail == ""
	})
}

// --- Task 7: the /releases virtual SFTP directory ---

func TestRemoteFS_ReleasesDirectory_ListsOwnReleasesOnly(t *testing.T) {
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	if _, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := releases.Create(release.Release{QuarantineKey: "q/k2", Requester: "bob", OriginalFilename: "secret.txt"}, time.Hour); err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases}
	listing, err := fs.Filelist(&sftp.Request{Method: "List", Filepath: "/releases"})
	if err != nil {
		t.Fatalf("Filelist: %v", err)
	}
	infos := make([]os.FileInfo, 8)
	n, _ := listing.ListAt(infos, 0)
	if n != 1 {
		t.Fatalf("got %d entries, want exactly 1 (alice's own release, not bob's)", n)
	}
}

func TestRemoteFS_ReleasesDirectory_ReadStreamsFromQuarantine(t *testing.T) {
	quar := newFakeBlobStore()
	if err := quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret report"), -1); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	r, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/releases/" + rel.ID})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	n, _ := r.ReadAt(buf, 0)
	if got := string(buf[:n]); got != "secret report" {
		t.Fatalf("got %q, want %q", got, "secret report")
	}
}

func TestRemoteFS_ReleasesDirectory_WrongUserCannotRead(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "mallory", releases: releases, gate: g, ctx: context.Background()}
	if _, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err == nil {
		t.Fatal("a different user must not be able to read alice's release")
	}
}

func TestRemoteFS_ReleasesDirectory_ExpiredCannotBeRead(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	if _, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err == nil {
		t.Fatal("an expired release must not be readable, even by its own requester")
	}
}

func TestRemoteFS_ReleasesDirectory_UnlimitedReadsWithinWindow(t *testing.T) {
	quar := newFakeBlobStore()
	_ = quar.Put(context.Background(), "q/k1", "application/octet-stream", strings.NewReader("secret"), -1)
	g, _ := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	for i := 0; i < 3; i++ {
		if _, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/releases/" + rel.ID}); err != nil {
			t.Fatalf("read #%d: %v", i, err)
		}
	}
}

func TestRemoteFS_ReleasesDirectory_WriteRefused(t *testing.T) {
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	fs := &remoteFS{user: "alice", releases: releases}
	if _, err := fs.Filewrite(&sftp.Request{Method: "Put", Filepath: "/releases/anything"}); err == nil {
		t.Fatal("writing under /releases must be refused — it's a read-only virtual namespace")
	}
}

func TestRemoteFS_ReleasesDirectory_FilecmdRefused(t *testing.T) {
	releases, _ := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	fs := &remoteFS{user: "alice", releases: releases}
	if err := fs.Filecmd(&sftp.Request{Method: "Remove", Filepath: "/releases/anything"}); err == nil {
		t.Fatal("Filecmd under /releases must be refused")
	}
}

// TestRemoteFS_ReleasesDirectory_StatOwnReleaseReturnsFileInfo: a real SFTP
// client typically Stat/Lstat's a path before Get — Filelist's Stat branch on
// /releases/<id> must resolve to the owning release, not the bare-directory
// placeholder, or clients will refuse to download it ("not a regular file").
func TestRemoteFS_ReleasesDirectory_StatOwnReleaseReturnsFileInfo(t *testing.T) {
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice", OriginalFilename: "report.csv"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases}
	listing, err := fs.Filelist(&sftp.Request{Method: "Stat", Filepath: "/releases/" + rel.ID})
	if err != nil {
		t.Fatalf("Filelist Stat: %v", err)
	}
	infos := make([]os.FileInfo, 1)
	n, _ := listing.ListAt(infos, 0)
	if n != 1 {
		t.Fatalf("got %d entries, want 1", n)
	}
	if infos[0].IsDir() {
		t.Fatal("Stat on /releases/<id> must report IsDir()=false — it's a regular file, not the /releases directory")
	}
}

// TestRemoteFS_ReleasesDirectory_StatWrongUserOrExpiredErrors: Stat must use
// the same identity+expiry check as Fileread/readRelease, with the same
// error for both failure reasons — no oracle that would let a caller
// distinguish "not yours" from "expired" from "doesn't exist".
func TestRemoteFS_ReleasesDirectory_StatWrongUserOrExpiredErrors(t *testing.T) {
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	rel, err := releases.Create(release.Release{QuarantineKey: "q/k1", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	expired, err := releases.Create(release.Release{QuarantineKey: "q/k2", Requester: "alice"}, time.Millisecond)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	time.Sleep(10 * time.Millisecond)

	wrongUser := &remoteFS{user: "mallory", releases: releases}
	_, err = wrongUser.Filelist(&sftp.Request{Method: "Stat", Filepath: "/releases/" + rel.ID})
	if err == nil {
		t.Fatal("Stat on another user's release must be refused")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("wrong-user Stat error = %v, want os.ErrNotExist (same as Fileread's)", err)
	}

	owner := &remoteFS{user: "alice", releases: releases}
	err = func() error {
		_, err := owner.Filelist(&sftp.Request{Method: "Stat", Filepath: "/releases/" + expired.ID})
		return err
	}()
	if err == nil {
		t.Fatal("Stat on an expired release must be refused, even for its own requester")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired Stat error = %v, want os.ErrNotExist (same as Fileread's)", err)
	}
}

// TestRemoteFS_ReleasesDirectory_ReadRefusesOversizedObject: readCloserAtAdapter
// buffers a quarantined object fully into memory to satisfy io.ReaderAt — a
// release larger than maxReleaseReadBytes must be refused outright rather
// than silently buffered without bound (a resource-exhaustion risk on a
// gateway process, since inspectgate's small/large split only bounds
// inspection-time memory, not the eventual quarantined object's size).
func TestRemoteFS_ReleasesDirectory_ReadRefusesOversizedObject(t *testing.T) {
	quar := newFakeBlobStore()
	if err := quar.Put(context.Background(), "q/big", "application/octet-stream", &zeroReader{n: maxReleaseReadBytes + 1}, -1); err != nil {
		t.Fatalf("seed quarantine: %v", err)
	}
	g, err := inspectgate.New(inspectgate.Config{Inspector: cleanInspector{}, Quarantine: quar})
	if err != nil {
		t.Fatalf("inspectgate.New: %v", err)
	}
	releases, err := release.NewFileStore(filepath.Join(t.TempDir(), "releases.json"))
	if err != nil {
		t.Fatalf("release.NewFileStore: %v", err)
	}
	rel, err := releases.Create(release.Release{QuarantineKey: "q/big", Requester: "alice"}, time.Hour)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	fs := &remoteFS{user: "alice", releases: releases, gate: g, ctx: context.Background()}
	r, err := fs.Fileread(&sftp.Request{Method: "Get", Filepath: "/releases/" + rel.ID})
	if err != nil {
		t.Fatalf("Fileread: %v", err)
	}
	buf := make([]byte, 32)
	if _, err := r.ReadAt(buf, 0); err == nil {
		t.Fatal("a release larger than maxReleaseReadBytes must be refused, not silently truncated or served")
	}
}

// zeroReader emits n zero bytes without allocating a buffer of that size up
// front — used to seed an oversized quarantine object cheaply in the test
// above.
type zeroReader struct{ n int64 }

func (z *zeroReader) Read(p []byte) (int, error) {
	if z.n <= 0 {
		return 0, io.EOF
	}
	if int64(len(p)) > z.n {
		p = p[:z.n]
	}
	for i := range p {
		p[i] = 0
	}
	z.n -= int64(len(p))
	return len(p), nil
}
