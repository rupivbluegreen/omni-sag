package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/pkg/sftp"

	"github.com/rupivbluegreen/omni-sag/internal/approval"
	"github.com/rupivbluegreen/omni-sag/internal/evidence"
	"github.com/rupivbluegreen/omni-sag/internal/inspect"
	"github.com/rupivbluegreen/omni-sag/internal/inspectgate"
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"github.com/rupivbluegreen/omni-sag/internal/release"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
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
	ctx, sftpSpan := tracer.Start(ctx, "omnisag.sftp")
	defer sftpSpan.End()

	s.emit(ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionStart,
		User: pr.User, SourceIP: srcIP, Detail: "sftp",
	})
	if pr.TargetHost == "" {
		_ = channel.Close()
		s.emit(ctx, evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: no target selected",
		})
		return
	}
	decision := policy.Decision{}
	if s.dialerPeek != nil {
		decision = s.dialerPeek(pr, pr.TargetHost)
	}
	// Re-check Allow here — see runRecordedShell's identical check for why:
	// DecideHost fails closed (Allow: false) on an ambiguous host match
	// instead of guessing, and nothing upstream refuses the session on that.
	if !decision.Allow {
		_ = channel.Close()
		reason := decision.Reason
		if reason == "" {
			reason = "no policy decision available for this target"
		}
		s.emit(ctx, evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: " + reason,
		})
		return
	}
	// decision.Port is DecideHost's resolved real-target port (the client's
	// auth username carries no port at all — see its doc comment); fall back
	// to 22 if unset (e.g. a test double that doesn't populate it).
	targetPort := decision.Port
	if targetPort <= 0 {
		targetPort = 22
	}
	targetClient, err := tch.getOrDial(func() (*ssh.Client, error) {
		return s.dialTarget(ctx, sconn, pr, srcIP, decision, pr.TargetHost, targetPort, pr.TargetSecretToken)
	})
	if err != nil {
		_ = channel.Close()
		s.emit(ctx, evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: " + err.Error(),
		})
		return
	}
	sftpClient, err := sftp.NewClient(targetClient)
	if err != nil {
		_ = channel.Close()
		s.emit(ctx, evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
			User: pr.User, SourceIP: srcIP, Detail: "sftp refused: target sftp client: " + err.Error(),
		})
		return
	}
	defer sftpClient.Close()

	fs := &remoteFS{
		client: sftpClient, gate: s.inspect, srv: s, user: pr.User, srcIP: srcIP, ctx: connCtx, traceCtx: ctx,
		matchedGroups: decision.MatchedGroups, releases: s.releases, releaseTTL: s.releaseTTL,
	}
	server := sftp.NewRequestServer(channel, sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	})
	_ = server.Serve()
	_ = server.Close()
	_ = channel.Close()
	s.emit(ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeSessionEnd,
		User: pr.User, SourceIP: srcIP,
	})
}

func cleanPath(p string) string { return path.Clean("/" + p) }

// releasesPrefix is the virtual SFTP directory serving approved
// pull-download releases — see remoteFS.Fileread/Filelist.
const releasesPrefix = "/releases"

func isReleasesPath(p string) bool {
	return p == releasesPrefix || strings.HasPrefix(p, releasesPrefix+"/")
}

// releaseIDFrom extracts the release ID from a /releases/<id> path. Returns
// "" for the bare /releases directory itself.
func releaseIDFrom(p string) string {
	if p == releasesPrefix {
		return ""
	}
	return strings.TrimPrefix(p, releasesPrefix+"/")
}

// remoteFS serves the SFTP subsystem by proxying to a real *sftp.Client
// connected to the target, replacing the in-memory stand-in (memFS) for
// reads and (as of Task 11) writes. A clean-verdict upload is never pushed to
// the target — Filewrite's returned handle blocks on Close() until a human
// approves its release from quarantine, then records a release for the
// uploader to pull down themselves (Task 6).
type remoteFS struct {
	client *sftp.Client
	gate   *inspectgate.Gate // set when inspection is configured; used by Filewrite
	srv    *Server           // for approvals/evidence; nil only in Task 9's read-only tests
	user   string
	srcIP  string // source IP of the client connection; threaded into every evidence event Close() emits
	ctx    context.Context
	// traceCtx is the omnisag.sftp-span-bearing context (set by runSFTP),
	// used only to parent per-file omnisag.transfer/omnisag.inspect spans and
	// to correlate their evidence events — never for cancellation, which
	// stays on ctx (connCtx) above.
	traceCtx      context.Context
	matchedGroups []string      // decision.MatchedGroups for this session's target — snapshotted onto release requests for group-scoped four-eyes
	releases      release.Store // for recording approved releases and serving /releases; nil disables the pull-download flow
	releaseTTL    time.Duration
}

// ctxOrBackground returns fs.ctx, falling back to context.Background() for
// tests that construct a remoteFS directly without one.
func (fs *remoteFS) ctxOrBackground() context.Context {
	if fs.ctx != nil {
		return fs.ctx
	}
	return context.Background()
}

// traceCtxOrBackground returns fs.traceCtx, falling back to
// context.Background() for tests (or scp.go callers) that construct a
// remoteFS without one — spans then simply have no parent instead of
// panicking or nesting incorrectly.
func (fs *remoteFS) traceCtxOrBackground() context.Context {
	if fs.traceCtx != nil {
		return fs.traceCtx
	}
	return context.Background()
}

// Fileread (FileGet) proxies directly from the real target file — downloads
// are not content-inspected or quarantined, matching the existing in-memory
// stand-in's behavior and the design spec's explicit scope decision. The
// returned handle is wrapped in a downloadTap so the transfer still produces
// a evidence.TypeTransfer manifest (path, size, SHA256, Direction:
// "download") once pkg/sftp is done with it — the old in-memory memFS made
// exactly this record (see downloadTap's doc comment for why it is
// immune to a later Rename/Remove/overwrite of the source file).
func (fs *remoteFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	p := cleanPath(r.Filepath)
	if isReleasesPath(p) {
		return fs.readRelease(p)
	}
	f, err := fs.client.Open(p)
	if err != nil {
		return nil, err
	}
	trCtx, trSpan := tracer.Start(fs.traceCtxOrBackground(), "omnisag.transfer", trace.WithAttributes(
		omnisagPath(p), omnisagTransferDirection("download")))
	return newDownloadTap(trCtx, trSpan, f, p, fs), nil
}

// readRelease serves a /releases/<id> read: the release must belong to
// fs.user and not be expired (both checked fresh on every access, per the
// design — a release may be read any number of times within its window from
// any number of separate SFTP sessions), then streams directly from the WORM
// quarantine store via Gate.QuarantineReader.
func (fs *remoteFS) readRelease(p string) (io.ReaderAt, error) {
	if fs.releases == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	id := releaseIDFrom(p)
	if id == "" {
		return nil, fmt.Errorf("sftp: %s is a directory", p)
	}
	rel, ok := fs.releases.Get(fs.user, id, time.Now())
	if !ok {
		return nil, os.ErrNotExist
	}
	if fs.gate == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	rc, err := fs.gate.QuarantineReader(fs.ctxOrBackground(), rel.QuarantineKey)
	if err != nil {
		return nil, fmt.Errorf("sftp: read release %s: %w", id, err)
	}
	return &readCloserAtAdapter{rc: rc}, nil
}

// maxReleaseReadBytes bounds how much of a quarantined object
// readCloserAtAdapter will buffer into memory for one /releases read.
// inspectgate's small/large split (see Gate.Inspect/inspectLarge) only
// bounds memory used DURING inspection — large uploads are streamed through
// via Put(..., -1) rather than buffered whole — it does not cap the eventual
// size of the object sitting in quarantine. Without a cap here, a large
// clean upload that passed inspection with bounded memory could still OOM
// the gateway process the moment its owner reads it back, since the
// Gate/BlobStore has no range-GET support to stream a read instead. Same
// order of magnitude as maxChunkedBodyBytes (internal/inspect/chunk.go) and
// maxReorderBytes above, for the same reason: cap in-memory buffering of
// externally-controlled content.
const maxReleaseReadBytes = 64 << 20 // 64 MiB

// readCloserAtAdapter adapts a sequential io.ReadCloser (an S3 GET stream —
// not seekable) to io.ReaderAt by buffering it into memory on first use, up
// to maxReleaseReadBytes. A release larger than that is refused outright
// (ReadAt returns an error), never silently truncated or partially served.
// This is a pragmatic cap, not a streaming rewrite: serving arbitrarily
// large releases without buffering would need range-GET support in
// Gate/BlobStore that does not exist today — out of scope for this task.
type readCloserAtAdapter struct {
	rc   io.ReadCloser
	buf  []byte
	err  error
	once sync.Once
}

func (a *readCloserAtAdapter) ReadAt(p []byte, off int64) (int, error) {
	a.once.Do(func() {
		a.buf, a.err = io.ReadAll(io.LimitReader(a.rc, maxReleaseReadBytes+1))
		_ = a.rc.Close()
		if a.err == nil && int64(len(a.buf)) > maxReleaseReadBytes {
			a.err = fmt.Errorf("sftp: release exceeds %d byte read limit", maxReleaseReadBytes)
		}
	})
	if a.err != nil {
		return 0, a.err
	}
	if off >= int64(len(a.buf)) {
		return 0, io.EOF
	}
	n := copy(p, a.buf[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// downloadTap wraps a real target file's io.ReaderAt (from Fileread) so a
// download still produces an evidence.TypeTransfer manifest — the old
// in-memory memFS.Fileread computed one (path, size, SHA256, Direction:
// "download") from its fully-buffered content, explicitly commented as
// making the record "immune to a later Rename/Remove/overwrite" of the
// file; remoteFS proxies a real streaming file instead, so there is no
// buffered copy to hash after the fact. Bytes are hashed here as they
// actually pass through, and the manifest is emitted once pkg/sftp closes
// the handle (request.go's r.close() calls Close() on the readerAt if it
// implements io.Closer — the same mechanism Filewrite's quarantineWriteHandle
// already relies on for uploads).
//
// pkg/sftp's request server dispatches SSH_FXP_READ across several worker
// goroutines with no per-handle ordering guarantee (the same is true of
// SSH_FXP_WRITE — see inspectUpload's WriteAt above), so reads are
// reassembled in offset order under a lock before being hashed, bounded by
// maxReorderBytes exactly like the upload path. Unlike uploads, a gap that
// is never filled is not a security concern here — this is a download
// record, not a content-inspection gate — so the manifest simply reflects
// however much of the file was actually observed contiguously from offset 0,
// rather than refusing the transfer.
type downloadTap struct {
	r    io.ReaderAt
	path string
	fs   *remoteFS
	ctx  context.Context // carries the omnisag.transfer span; correlates the emitted evidence event
	span trace.Span

	mu           sync.Mutex
	h            hash.Hash
	expOff       int64
	pending      map[int64][]byte
	pendingBytes int64

	closeOnce sync.Once
	closeErr  error
}

func newDownloadTap(ctx context.Context, span trace.Span, r io.ReaderAt, p string, fs *remoteFS) *downloadTap {
	return &downloadTap{ctx: ctx, span: span, r: r, path: p, fs: fs, h: sha256.New()}
}

// ReadAt proxies straight through to the real target file (the delivered
// bytes to the client are never affected by the tap's bookkeeping below) and
// observes what came back for later hashing.
func (d *downloadTap) ReadAt(p []byte, off int64) (int, error) {
	n, err := d.r.ReadAt(p, off)
	if n > 0 {
		d.observe(p[:n], off)
	}
	return n, err
}

// observe folds a chunk read at off into the running hash once it (and every
// byte before it) has been seen, mirroring inspectUpload.WriteAt's
// reassembly. Out-of-order bytes are buffered, bounded by maxReorderBytes;
// beyond that bound they are simply dropped from the manifest — best-effort,
// not fail-closed (see the type doc comment).
func (d *downloadTap) observe(b []byte, off int64) {
	buf := append([]byte(nil), b...)

	d.mu.Lock()
	defer d.mu.Unlock()
	if off < d.expOff {
		return // already-hashed region re-read (e.g. a retry) — nothing new
	}
	if d.pending == nil {
		d.pending = make(map[int64][]byte)
	}
	if _, dup := d.pending[off]; !dup {
		d.pendingBytes += int64(len(buf))
	}
	if d.pendingBytes > maxReorderBytes {
		return
	}
	d.pending[off] = buf

	for {
		chunk, ok := d.pending[d.expOff]
		if !ok {
			break
		}
		delete(d.pending, d.expOff)
		d.pendingBytes -= int64(len(chunk))
		d.h.Write(chunk)
		d.expOff += int64(len(chunk))
	}
}

// Close closes the underlying target file and — once, via closeOnce, so a
// second Close() from the SFTP layer never double-emits — records the
// download's evidence.TypeTransfer manifest for whatever was actually
// observed via ReadAt.
func (d *downloadTap) Close() error {
	d.closeOnce.Do(func() {
		if c, ok := d.r.(io.Closer); ok {
			d.closeErr = c.Close()
		}
		d.mu.Lock()
		bytesSeen := d.expOff
		sum := hex.EncodeToString(d.h.Sum(nil))
		d.mu.Unlock()
		if d.fs.srv != nil {
			evt := d.fs.srv.emit(d.ctx, evidence.Event{
				Time: time.Now().UTC(), Type: evidence.TypeTransfer,
				User: d.fs.user, SourceIP: d.fs.srcIP, Path: d.path, Direction: "download",
				Bytes: bytesSeen, SHA256: sum, Detail: "sftp transfer",
			})
			d.span.SetAttributes(omnisagTransferBytes(bytesSeen), omnisagEvidenceID(evt.ID))
		}
		d.span.End()
	})
	return d.closeErr
}

// Filelist proxies List/Stat to the real target.
func (fs *remoteFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	p := cleanPath(r.Filepath)
	if isReleasesPath(p) {
		return fs.listReleases(r.Method, p)
	}
	switch r.Method {
	case "List":
		infos, err := fs.client.ReadDir(p)
		if err != nil {
			return nil, err
		}
		out := make([]os.FileInfo, len(infos))
		copy(out, infos)
		return listerAt(out), nil
	case "Stat":
		info, err := fs.client.Stat(p)
		if err != nil {
			return nil, err
		}
		return listerAt{info}, nil
	}
	return nil, fmt.Errorf("sftp: unsupported list method %q", r.Method)
}

// listReleases serves /releases List and Stat requests — scoped to fs.user's
// own non-expired releases only. Stat on the bare /releases directory itself
// returns a synthetic releaseDirInfo; Stat on /releases/<id> runs the exact
// same identity+expiry lookup readRelease uses (fs.releases.Get) and fails
// with the same os.ErrNotExist whether the ID doesn't exist, belongs to
// another user, or has expired — no distinguishing error, so Stat cannot be
// used as an oracle for any of those cases the way Fileread already isn't.
func (fs *remoteFS) listReleases(method, p string) (sftp.ListerAt, error) {
	if fs.releases == nil {
		return nil, fmt.Errorf("sftp: /releases is not enabled")
	}
	if method == "Stat" {
		id := releaseIDFrom(p)
		if id == "" {
			return listerAt{releaseDirInfo{}}, nil
		}
		rel, ok := fs.releases.Get(fs.user, id, time.Now())
		if !ok {
			return nil, os.ErrNotExist
		}
		return listerAt{releaseFileInfo{rel: rel}}, nil
	}
	list := fs.releases.ListFor(fs.user, time.Now())
	infos := make([]os.FileInfo, len(list))
	for i, r := range list {
		infos[i] = releaseFileInfo{rel: r}
	}
	return listerAt(infos), nil
}

// releaseFileInfo presents one Release as an os.FileInfo entry in /releases.
// Name() returns the release ID, not OriginalFilename: Fileread/readRelease
// address entries by ID (releaseIDFrom), and keying the listing on the same
// identifier avoids ambiguity when two releases share a filename.
// OriginalFilename remains available on the Release itself for a future
// listing-detail UX pass.
type releaseFileInfo struct{ rel release.Release }

func (i releaseFileInfo) Name() string       { return i.rel.ID }
func (i releaseFileInfo) Size() int64        { return 0 } // unknown without a HEAD on quarantine; acceptable for a listing
func (i releaseFileInfo) Mode() os.FileMode  { return 0o444 }
func (i releaseFileInfo) ModTime() time.Time { return i.rel.ApprovedAt }
func (i releaseFileInfo) IsDir() bool        { return false }
func (i releaseFileInfo) Sys() interface{}   { return nil }

// releaseDirInfo represents the /releases directory itself for Stat.
type releaseDirInfo struct{}

func (releaseDirInfo) Name() string       { return "releases" }
func (releaseDirInfo) Size() int64        { return 0 }
func (releaseDirInfo) Mode() os.FileMode  { return os.ModeDir | 0o555 }
func (releaseDirInfo) ModTime() time.Time { return time.Time{} }
func (releaseDirInfo) IsDir() bool        { return true }
func (releaseDirInfo) Sys() interface{}   { return nil }

// Filecmd proxies Remove/Rename/Mkdir/Rmdir to the real target. Unlike the
// old in-memory memFS (where these only mutated a throwaway map), these are
// now real, destructive operations on the real target file system, so each
// one that actually mutates the target gets an evidence.TypeTransfer record
// — path(s), operation, user — the same way Filewrite/Fileread already do.
// This is evidence only: no approval-gating for these operations, which is
// a bigger design decision out of scope here.
func (fs *remoteFS) Filecmd(r *sftp.Request) error {
	if isReleasesPath(cleanPath(r.Filepath)) {
		return fmt.Errorf("sftp: /releases is read-only")
	}
	switch r.Method {
	case "Remove":
		p := cleanPath(r.Filepath)
		err := fs.client.Remove(p)
		fs.emitFilecmd("remove", p, "sftp filecmd: remove", err)
		return err
	case "Rename":
		p, target := cleanPath(r.Filepath), cleanPath(r.Target)
		err := fs.client.Rename(p, target)
		fs.emitFilecmd("rename", p, fmt.Sprintf("sftp filecmd: rename to %s", target), err)
		return err
	case "Mkdir":
		p := cleanPath(r.Filepath)
		err := fs.client.Mkdir(p)
		fs.emitFilecmd("mkdir", p, "sftp filecmd: mkdir", err)
		return err
	case "Rmdir":
		p := cleanPath(r.Filepath)
		err := fs.client.RemoveDirectory(p)
		fs.emitFilecmd("rmdir", p, "sftp filecmd: rmdir", err)
		return err
	case "Setstat", "Symlink":
		return nil // no-ops, matching the prior in-memory stand-in's scope
	}
	return nil
}

// emitFilecmd records a destructive Filecmd operation (Remove/Rename/Mkdir/
// Rmdir) as an evidence.TypeTransfer event, reusing Direction for the
// operation name (remove | rename | mkdir | rmdir) since these are as much a
// "transfer" of the target's file-system state as an upload/download is.
// detail carries anything beyond the single path (e.g. a rename's
// destination) — evidence.Event has no second path field, and Detail is
// exactly the "freeform detail for anything not yet promoted to a field"
// escape hatch the type already documents.
func (fs *remoteFS) emitFilecmd(op, p, detail string, err error) {
	if fs.srv == nil {
		return
	}
	trCtx, trSpan := tracer.Start(fs.traceCtxOrBackground(), "omnisag.transfer", trace.WithAttributes(
		omnisagPath(p), omnisagTransferDirection(op)))
	defer trSpan.End()
	reason := ""
	if err != nil {
		reason = err.Error()
		trSpan.SetStatus(codes.Error, reason)
	}
	evt := fs.srv.emit(trCtx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: fs.user, SourceIP: fs.srcIP, Path: p,
		Direction: op, Allow: evidence.BoolPtr(err == nil), Reason: reason,
		Detail: detail,
	})
	trSpan.SetAttributes(omnisagEvidenceID(evt.ID))
}

// Filewrite (FilePut): every upload streams through inspection exactly as
// memFS's inspectUpload already did (that machinery is unchanged — see
// newInspectUpload in this file), but Close no longer decides delivery by
// verdict alone. A clean upload is quarantined (Task 10 made that
// unconditional) and then requires a KindQuarantineRelease approval before
// the gateway records a release for pull-download (Task 6) — it is never
// pushed to the target. Blocked/unscannable content was already fail-closed
// before this task and still never creates a release request.
func (fs *remoteFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	if isReleasesPath(cleanPath(r.Filepath)) {
		return nil, fmt.Errorf("sftp: /releases is read-only")
	}
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
	trCtx, trSpan := tracer.Start(fs.traceCtxOrBackground(), "omnisag.transfer", trace.WithAttributes(
		omnisagPath(p), omnisagTransferDirection("upload")))
	return &quarantineWriteHandle{iu: iu, fs: fs, path: p, ctx: trCtx, span: trSpan}, nil
}

// quarantineWriteHandle wraps an inspectUpload (Task 10's now-unconditional
// quarantine) and, on Close, blocks for a KindQuarantineRelease approval
// before recording a release for the quarantined content (Task 6) — the
// target file is never touched.
type quarantineWriteHandle struct {
	iu   *inspectUpload
	fs   *remoteFS
	path string
	ctx  context.Context // the omnisag.transfer span-bearing ctx; correlates every evidence event this handle emits
	span trace.Span

	// closeOnce guards Close's whole body, mirroring inspectUpload's own
	// closeOnce above: without it, a second Close() call (pkg/sftp is not
	// guaranteed to call Close exactly once per handle in every code path)
	// would re-emit inspection evidence, create a second
	// KindQuarantineRelease approval request, and — on a second approval —
	// record a second, duplicate release.
	closeOnce sync.Once
	closeErr  error
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
	h.closeOnce.Do(func() { h.closeErr = h.doClose() })
	return h.closeErr
}

// doClose is Close's real body, run exactly once via closeOnce above.
func (h *quarantineWriteHandle) doClose() error {
	defer h.span.End()
	inspErr := h.iu.Close()
	dec := h.iu.dec

	// The ICAP verdict brackets an omnisag.inspect child span: it's the point
	// at which the verdict is known and recorded, not the raw async ICAP
	// round-trip inside inspectUpload's own goroutine (which has no access to
	// this span tree) — a lean, surgical choice rather than replumbing that
	// goroutine's context.
	_, inspSpan := tracer.Start(h.ctx, "omnisag.inspect", trace.WithAttributes(omnisagInspectionVerdict(dec.Verdict)))
	// Emit the inspection verdict for every upload — clean, blocked, and
	// fail-closed-unscannable alike — exactly as the pre-Task-11 memFS path
	// did (runSFTP's old per-session loop over fs.inspections()). Without
	// this, a BLOCKED upload would leave no audit trail at all: its bytes
	// still land in quarantine (Task 10, inside h.iu.Close() above) but
	// nothing downstream of that would ever say so. Emitted before the error
	// check below so the blocked/unscannable case is evidenced too, not only
	// the clean case that goes on to request a release.
	if h.fs.srv != nil {
		evt := h.fs.srv.emit(h.ctx, evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeInspection,
			User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "upload",
			Bytes: dec.Bytes, SHA256: dec.SHA256,
			Verdict: dec.Verdict, ICAPStatus: dec.ICAPStatus,
			ObjectKey: dec.QuarantineKey, Allow: evidence.BoolPtr(dec.Allow),
			Reason: dec.Reason, Detail: "sftp content inspection",
		})
		inspSpan.SetAttributes(omnisagEvidenceID(evt.ID))
	}
	if !dec.Allow {
		inspSpan.SetStatus(codes.Error, dec.Reason)
	}
	inspSpan.End()

	if inspErr != nil {
		h.span.SetStatus(codes.Error, inspErr.Error())
		return inspErr // blocked/unscannable — already refused, no release request
	}
	if h.fs.srv == nil || h.fs.srv.approvals == nil {
		h.span.SetStatus(codes.Error, "no approval store configured to release upload")
		return fmt.Errorf("sftp: upload quarantined (key=%s) but no approval store is configured to release it", dec.QuarantineKey)
	}
	req, err := h.fs.srv.approvals.Create(approval.Request{
		Kind:            approval.KindQuarantineRelease,
		Requester:       h.fs.user,
		RequesterGroups: h.fs.matchedGroups,
		Subject:         dec.QuarantineKey,
		Reason:          fmt.Sprintf("release %s to %s", dec.QuarantineKey, h.path),
	}, h.fs.srv.approvalTTL)
	if err != nil {
		h.span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("sftp: create release request: %w", err)
	}
	h.fs.srv.emit(h.ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, SourceIP: h.fs.srcIP, Target: h.path, ObjectKey: req.ID,
		Outcome: "requested", Reason: "quarantine release pending",
	})

	final, werr := h.fs.srv.approvals.Wait(h.fs.ctxOrBackground(), req.ID)
	approved := werr == nil && final.Approved(time.Now())
	evt := h.fs.srv.emit(h.ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, SourceIP: h.fs.srcIP, Target: h.path, ObjectKey: req.ID,
		Allow:   evidence.BoolPtr(approved),
		Outcome: map[bool]string{true: "granted", false: "refused"}[approved],
		Reason:  "quarantine release " + string(final.EffectiveStatus(time.Now())),
	})
	if !approved {
		h.span.SetAttributes(omnisagEvidenceID(evt.ID))
		h.span.SetStatus(codes.Error, "quarantine release "+string(final.EffectiveStatus(time.Now())))
		return fmt.Errorf("sftp: upload to %s denied: quarantine release %s", h.path, final.EffectiveStatus(time.Now()))
	}

	if h.fs.releases == nil {
		h.span.SetStatus(codes.Error, "no release store configured")
		return fmt.Errorf("sftp: upload %s approved for release (key=%s) but no release store is configured", h.path, dec.QuarantineKey)
	}
	rel, err := h.fs.releases.Create(release.Release{
		QuarantineKey:    dec.QuarantineKey,
		Requester:        h.fs.user,
		OriginalFilename: h.path,
	}, h.fs.releaseTTL)
	if err != nil {
		h.span.SetStatus(codes.Error, err.Error())
		return fmt.Errorf("sftp: record release for %s: %w", h.path, err)
	}

	evt2 := h.fs.srv.emit(h.ctx, evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeTransfer,
		User: h.fs.user, SourceIP: h.fs.srcIP, Path: h.path, Direction: "released",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: fmt.Sprintf("released to /releases (id=%s, expires=%s) — pull-download by %s, not pushed to target", rel.ID, rel.ExpiresAt.Format(time.RFC3339), h.fs.user),
	})
	h.span.SetAttributes(omnisagTransferBytes(dec.Bytes), omnisagEvidenceID(evt2.ID))
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
