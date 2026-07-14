package session

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// runSFTP serves the SFTP subsystem over channel by proxying to a real
// *sftp.Client connected to pr's target (dialed via tch, the same
// per-connection cache the interactive shell uses). Terminating SFTP at the
// gateway (rather than blind-proxying the wire protocol) is deliberate: it is
// the point at which content inspection (ICAP) is interposed. When an
// inspection gate is configured, each upload is streamed through inspection
// before it is accepted, quarantined unconditionally, and then held for a
// human release decision (remoteFS.Filewrite/quarantineWriteHandle) —
// blocked/unscannable content is refused outright and never reaches that
// release step.
//
// connCtx (handleConn's connection-scoped context — see its doc comment) is
// what remoteFS uses for the quarantine-release approval wait, not ctx: a
// quarantine-release approval can block a write handle's Close() for as long
// as the configured approval TTL, and connCtx (unlike ctx, which is only
// cancelled on whole-gateway shutdown) is ALSO cancelled the moment this
// specific client connection goes away (sconn.Wait, in handleConn) — e.g.
// the client vanishes mid-upload after the final write+close but before a
// human acts on the release request. Without that, a stuck Close() would
// hold its pkg/sftp packetWorker goroutine (and the pending release request)
// open for the full TTL even though nobody is listening anymore:
// pkg/sftp's own Serve() cannot return (and so cannot run its own
// per-request cleanup) until every packetWorker, including the one blocked
// in Close(), returns — the two are circular, so external cancellation is
// the only way out short of the TTL.
func (s *Server) runSFTP(ctx, connCtx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache) {
	if pr.TargetHost == "" {
		_ = channel.Close()
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: no target selected",
		})
		return
	}
	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, pr.TargetHost)
	}
	// decision.Port is DecideHost's resolved real-target port (the client's
	// auth username carries no port at all — see its doc comment); fall back
	// to 22 if unset (e.g. a test double that doesn't populate it).
	targetPort := decision.Port
	if targetPort <= 0 {
		targetPort = 22
	}
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, decision, pr.TargetHost, targetPort, pr.TargetSecretToken)
	})
	if err != nil {
		_ = channel.Close()
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: " + err.Error(),
		})
		return
	}
	sftpClient, err := sftp.NewClient(targetClient)
	if err != nil {
		_ = channel.Close()
		return
	}
	defer sftpClient.Close()

	fs := &remoteFS{client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx}
	server := sftp.NewRequestServer(channel, sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	})
	_ = server.Serve()
	_ = server.Close()
	_ = channel.Close()
}

func cleanPath(p string) string { return path.Clean("/" + p) }

// remoteFS serves the SFTP subsystem by proxying to a real *sftp.Client
// connected to the target, replacing the in-memory stand-in (memFS) for
// reads and (as of Task 11) writes. A clean-verdict upload does not deliver
// to the target immediately — Filewrite's returned handle blocks on Close()
// until a human approves its release from quarantine.
type remoteFS struct {
	client *sftp.Client
	gate   *inspectgate.Gate // set when inspection is configured; used by Filewrite
	srv    *Server           // for approvals/evidence; nil only in Task 9's read-only tests
	user   string
	srcIP  string // source IP of the client connection; threaded into every evidence event Close() emits
	ctx    context.Context
}

// ctxOrBackground returns fs.ctx, falling back to context.Background() for
// tests that construct a remoteFS directly without one.
func (fs *remoteFS) ctxOrBackground() context.Context {
	if fs.ctx != nil {
		return fs.ctx
	}
	return context.Background()
}

// Fileread (FileGet) proxies directly from the real target file — downloads
// are not content-inspected or quarantined, matching the existing in-memory
// stand-in's behavior and the design spec's explicit scope decision.
func (fs *remoteFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	f, err := fs.client.Open(cleanPath(r.Filepath))
	if err != nil {
		return nil, err
	}
	return f, nil // *sftp.File implements io.ReaderAt directly
}

// Filelist proxies List/Stat to the real target.
func (fs *remoteFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	switch r.Method {
	case "List":
		infos, err := fs.client.ReadDir(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		out := make([]os.FileInfo, len(infos))
		copy(out, infos)
		return listerAt(out), nil
	case "Stat":
		info, err := fs.client.Stat(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return listerAt{info}, nil
	}
	return nil, fmt.Errorf("sftp: unsupported list method %q", r.Method)
}

// Filecmd proxies Remove/Rename/Mkdir/Rmdir to the real target.
func (fs *remoteFS) Filecmd(r *sftp.Request) error {
	switch r.Method {
	case "Remove":
		return fs.client.Remove(cleanPath(r.Filepath))
	case "Rename":
		return fs.client.Rename(cleanPath(r.Filepath), cleanPath(r.Target))
	case "Mkdir":
		return fs.client.Mkdir(cleanPath(r.Filepath))
	case "Rmdir":
		return fs.client.RemoveDirectory(cleanPath(r.Filepath))
	case "Setstat", "Symlink":
		return nil // no-ops, matching the prior in-memory stand-in's scope
	}
	return nil
}

// Filewrite (FilePut): every upload streams through inspection exactly as
// memFS's inspectUpload already did (that machinery is unchanged — see
// newInspectUpload in this file), but Close no longer decides delivery by
// verdict alone. A clean upload is quarantined (Task 10 made that
// unconditional) and then requires a KindQuarantineRelease approval before
// the gateway delivers it to the real target file. Blocked/unscannable
// content was already fail-closed before this task and still never creates
// a release request.
func (fs *remoteFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if fs.gate == nil {
		// No inspection configured: deliver straight through, no quarantine
		// step — matches the project's existing "inspection is opt-in"
		// posture (session.WithInspection's doc comment).
		f, err := fs.client.Create(cleanPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return f, nil
	}
	p := cleanPath(r.Filepath)
	iu := newInspectUpload(fs.ctxOrBackground(), fs.gate, p)
	return &quarantineWriteHandle{iu: iu, fs: fs, path: p}, nil
}

// quarantineWriteHandle wraps an inspectUpload (Task 10's now-unconditional
// quarantine) and, on Close, blocks for a KindQuarantineRelease approval
// before delivering the quarantined bytes to the real target file.
type quarantineWriteHandle struct {
	iu   *inspectUpload
	fs   *remoteFS
	path string
}

func (h *quarantineWriteHandle) WriteAt(p []byte, off int64) (int, error) {
	return h.iu.WriteAt(p, off)
}

// Close blocks (potentially for a long time — up to the configured approval
// TTL) waiting for a human to release the quarantined upload. It uses
// fs.ctxOrBackground(), which in production is the SFTP session's context —
// derived in runSFTP from a context that is cancelled both on gateway
// shutdown AND when the client's underlying SSH connection goes away (see
// runSFTP's sessCtx), so a client that disconnects mid-wait does not pin
// this goroutine (and the approval request it is waiting on) for the full
// TTL. See runSFTP for the derivation and why that matters.
func (h *quarantineWriteHandle) Close() error {
	inspErr := h.iu.Close()
	dec := h.iu.dec
	// Emit the inspection verdict for every upload — clean, blocked, and
	// fail-closed-unscannable alike — exactly as the pre-Task-11 memFS path
	// did (runSFTP's old per-session loop over fs.inspections()). Without
	// this, a BLOCKED upload would leave no audit trail at all: its bytes
	// still land in quarantine (Task 10, inside h.iu.Close() above) but
	// nothing downstream of that would ever say so. Emitted before the error
	// check below so the blocked/unscannable case is evidenced too, not only
	// the clean case that goes on to request a release.
	if h.fs.srv != nil {
		h.fs.srv.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeInspection,
			User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "upload",
			Bytes: dec.Bytes, SHA256: dec.SHA256,
			Verdict: dec.Verdict, ICAPStatus: dec.ICAPStatus,
			ObjectKey: dec.QuarantineKey, Allow: evidence.BoolPtr(dec.Allow),
			Reason: dec.Reason, Detail: "sftp content inspection",
		})
	}
	if inspErr != nil {
		return inspErr // blocked/unscannable — already refused, no release request
	}
	if h.fs.srv == nil || h.fs.srv.approvals == nil {
		return fmt.Errorf("sftp: upload quarantined (key=%s) but no approval store is configured to release it", dec.QuarantineKey)
	}
	req, err := h.fs.srv.approvals.Create(approval.Request{
		Kind:      approval.KindQuarantineRelease,
		Requester: h.fs.user,
		Subject:   dec.QuarantineKey,
		Reason:    fmt.Sprintf("release %s to %s", dec.QuarantineKey, h.path),
	}, h.fs.srv.approvalTTL)
	if err != nil {
		return fmt.Errorf("sftp: create release request: %w", err)
	}
	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, SourceIP: h.fs.srcIP, Target: h.path, ObjectKey: req.ID,
		Outcome: "requested", Reason: "quarantine release pending",
	})

	final, werr := h.fs.srv.approvals.Wait(h.fs.ctxOrBackground(), req.ID)
	approved := werr == nil && final.Approved(time.Now())
	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, SourceIP: h.fs.srcIP, Target: h.path, ObjectKey: req.ID,
		Allow:   evidence.BoolPtr(approved),
		Outcome: map[bool]string{true: "granted", false: "refused"}[approved],
		Reason:  "quarantine release " + string(final.EffectiveStatus(time.Now())),
	})
	if !approved {
		return fmt.Errorf("sftp: upload to %s denied: quarantine release %s", h.path, final.EffectiveStatus(time.Now()))
	}

	src, err := h.fs.srv.inspect.QuarantineReader(h.fs.ctxOrBackground(), dec.QuarantineKey)
	if err != nil {
		return fmt.Errorf("sftp: read quarantined content %s: %w", dec.QuarantineKey, err)
	}
	defer src.Close()
	dst, err := h.fs.client.Create(h.path)
	if err != nil {
		return fmt.Errorf("sftp: open target %s: %w", h.path, err)
	}
	defer dst.Close()
	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("sftp: deliver %s to target: %w", h.path, err)
	}

	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "upload",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: "sftp transfer (released from quarantine)",
	})
	return nil
}

// inspectUpload is an io.WriterAt+io.Closer that streams an SFTP upload through
// the inspection gate. pkg/sftp may deliver writes concurrently and out of
// order, so WriteAt reassembles them in offset order (bounded) before streaming
// to inspection. Close blocks for the verdict and returns an error when the
// content is blocked or unscannable, which the SFTP layer surfaces to the
// client as a failed transfer.
type inspectUpload struct {
	ctx  context.Context
	gate *inspectgate.Gate
	path string

	once    sync.Once
	pw      *io.PipeWriter
	done    chan struct{}
	dec     inspectgate.Decision
	inspErr error

	// pkg/sftp dispatches SSH_FXP_WRITE across concurrent workers with no
	// per-handle ordering, so writes may arrive concurrently and out of order.
	// Reassemble them in offset order under mu before streaming to inspection.
	mu           sync.Mutex
	expOff       int64
	pending      map[int64][]byte
	pendingBytes int64

	closeOnce sync.Once
	closeErr  error
}

// maxReorderBytes bounds how many out-of-order upload bytes are buffered while
// waiting for the missing offset, so a malicious client cannot force unbounded
// memory by writing far-ahead offsets.
const maxReorderBytes = 32 << 20

func newInspectUpload(ctx context.Context, gate *inspectgate.Gate, p string) *inspectUpload {
	return &inspectUpload{ctx: ctx, gate: gate, path: p, done: make(chan struct{})}
}

func (u *inspectUpload) start() {
	pr, pw := io.Pipe()
	u.pw = pw
	go func() {
		defer close(u.done)
		meta := inspect.TransferMeta{Filename: path.Base(u.path), Method: inspect.REQMOD}
		dec, err := u.gate.Inspect(u.ctx, meta, pr)
		// Ensure the writer side is unblocked if inspection returned early.
		_ = pr.CloseWithError(err)
		u.dec, u.inspErr = dec, err
	}()
}

func (u *inspectUpload) WriteAt(p []byte, off int64) (int, error) {
	u.once.Do(u.start)
	if off < 0 {
		return 0, fmt.Errorf("sftp: negative write offset %d", off)
	}
	// pkg/sftp may reuse p after WriteAt returns and calls it from multiple
	// workers, so copy the bytes and serialize under the lock.
	buf := append([]byte(nil), p...)

	u.mu.Lock()
	defer u.mu.Unlock()
	if off < u.expOff {
		return 0, fmt.Errorf("sftp: overlapping/rewind write at %d (stream already at %d)", off, u.expOff)
	}
	if u.pending == nil {
		u.pending = make(map[int64][]byte)
	}
	if _, dup := u.pending[off]; !dup {
		u.pendingBytes += int64(len(buf))
	}
	if u.pendingBytes > maxReorderBytes {
		return 0, fmt.Errorf("sftp: out-of-order write window exceeded (%d bytes buffered)", u.pendingBytes)
	}
	u.pending[off] = buf

	// Flush contiguous chunks starting at the expected offset, in order.
	for {
		chunk, ok := u.pending[u.expOff]
		if !ok {
			break
		}
		delete(u.pending, u.expOff)
		u.pendingBytes -= int64(len(chunk))
		if _, err := u.pw.Write(chunk); err != nil {
			return 0, err
		}
		u.expOff += int64(len(chunk))
	}
	return len(p), nil
}

func (u *inspectUpload) Close() error {
	u.closeOnce.Do(func() {
		if u.pw == nil {
			// No bytes were ever written: inspect an empty body so a zero-byte
			// upload still gets a verdict.
			u.once.Do(u.start)
		}
		_ = u.pw.Close()
		<-u.done
		// Fail closed on a non-contiguous upload: bytes the client wrote past an
		// unfilled offset gap stayed in `pending` and were NEVER presented to the
		// inspector, so the content was not fully scanned. Grading the contiguous
		// prefix as clean would bypass the AV/DLP gate — refuse instead.
		u.mu.Lock()
		gapped := u.pendingBytes > 0
		u.mu.Unlock()
		if gapped {
			u.dec.Allow = false
			u.dec.Verdict = "error"
			u.dec.Reason = "upload not contiguous: content could not be fully inspected"
			u.closeErr = fmt.Errorf("upload refused: incomplete/gapped stream not fully inspected")
			return
		}
		if u.inspErr != nil {
			u.closeErr = fmt.Errorf("upload refused: %w", u.inspErr)
			return
		}
		if !u.dec.Allow {
			u.closeErr = fmt.Errorf("upload refused: content %s (%s)", u.dec.Verdict, u.dec.Reason)
		}
	})
	return u.closeErr
}

// listerAt adapts a slice of FileInfo to sftp.ListerAt.
type listerAt []os.FileInfo

func (l listerAt) ListAt(f []os.FileInfo, off int64) (int, error) {
	if off >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(f, l[off:])
	if n < len(f) {
		return n, io.EOF
	}
	return n, nil
}
