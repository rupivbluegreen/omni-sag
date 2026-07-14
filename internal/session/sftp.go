package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// runSFTP serves the SFTP subsystem over channel using an in-memory filesystem.
// Terminating SFTP at the gateway (rather than proxying) is deliberate: it is
// the point at which content inspection (ICAP) is interposed. When an inspection
// gate is configured, each upload is streamed through inspection before it is
// accepted — blocked/unscannable content is quarantined and the transfer is
// refused. It then emits an inspection verdict (when inspecting) and a transfer
// manifest for every file put or fetched.
//
// sconn and tch are threaded through so a future slice can proxy SFTP to the
// real target (Task 9/11) using the same per-connection dial cache as the
// interactive shell; unused for now — SFTP still serves an in-memory
// filesystem at the gateway.
func (s *Server) runSFTP(ctx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string, sconn ssh.Conn, tch *targetConnCache) {
	fs := newMemFS(s.inspect, ctx, pr.User)
	server := sftp.NewRequestServer(channel, sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	})
	_ = server.Serve()
	_ = server.Close()
	_ = channel.Close()
	fs.finalizePending() // backstop: finalize any upload whose handle was not closed

	for _, iu := range fs.inspections() {
		allow := iu.dec.Allow
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeInspection,
			User: pr.User, SourceIP: srcIP,
			Path: iu.path, Direction: "upload",
			Bytes: iu.dec.Bytes, SHA256: iu.dec.SHA256,
			Verdict: iu.dec.Verdict, ICAPStatus: iu.dec.ICAPStatus,
			ObjectKey: iu.dec.QuarantineKey, Allow: evidence.BoolPtr(allow),
			Reason: iu.dec.Reason, Detail: "sftp content inspection",
		})
	}
	for _, m := range fs.manifests() {
		s.emit(evidence.Event{
			Time: time.Now().UTC(), Type: evidence.TypeTransfer,
			User: pr.User, SourceIP: srcIP,
			Path: m.path, Direction: m.direction, Bytes: m.size, SHA256: m.sha256,
			Detail: "sftp transfer",
		})
	}
}

// memFS is a minimal in-memory filesystem for the SFTP subsystem. It records
// which paths were written (uploads) and read (downloads) so transfer
// manifests can be emitted when the session ends. When gate is set, uploads are
// streamed through content inspection instead of being buffered.
type memFS struct {
	gate *inspectgate.Gate
	ctx  context.Context
	user string

	mu         sync.Mutex
	files      map[string]*memFile
	uploads    map[string]bool
	inspectUps []*inspectUpload // every inspected upload (keyed by handle, not path)
	completed  []transfer       // upload manifests captured at write-handle close
}

func (m *memFS) recordUpload(t transfer) {
	m.mu.Lock()
	m.completed = append(m.completed, t)
	m.mu.Unlock()
}

func newMemFS(gate *inspectgate.Gate, ctx context.Context, user string) *memFS {
	return &memFS{
		gate:    gate,
		ctx:     ctx,
		user:    user,
		files:   map[string]*memFile{},
		uploads: map[string]bool{},
	}
}

// inspections returns the completed inspect uploads for evidence emission.
func (m *memFS) inspections() []*inspectUpload {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*inspectUpload, 0, len(m.inspectUps))
	for _, iu := range m.inspectUps {
		out = append(out, iu)
	}
	return out
}

// finalizePending closes any inspect upload whose SFTP handle was never closed,
// so its inspection completes and is evidenced.
func (m *memFS) finalizePending() {
	m.mu.Lock()
	ups := make([]*inspectUpload, 0, len(m.inspectUps))
	for _, iu := range m.inspectUps {
		ups = append(ups, iu)
	}
	m.mu.Unlock()
	for _, iu := range ups {
		_ = iu.Close()
	}
}

// maxMemFileSize caps the in-memory SFTP stand-in file size. The write offset
// comes straight from the client's SSH_FXP_WRITE packet, so it must never be
// used to size an allocation unchecked: a huge or negative offset would
// otherwise panic (makeslice / slice bounds) — crashing the whole gateway,
// since pkg/sftp's packet workers have no recover — or OOM the process.
const maxMemFileSize = 64 << 20 // 64 MiB

type memFile struct {
	name    string
	mu      sync.Mutex
	data    []byte
	modTime time.Time
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("sftp: negative write offset %d", off)
	}
	end := off + int64(len(p))
	if end < 0 || end > maxMemFileSize { // end<0 catches int64 overflow
		return 0, fmt.Errorf("sftp: write exceeds %d-byte limit (offset=%d len=%d)", maxMemFileSize, off, len(p))
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if int64(len(f.data)) < end {
		grown := make([]byte, end)
		copy(grown, f.data)
		f.data = grown
	}
	copy(f.data[off:end], p)
	f.modTime = time.Now()
	return len(p), nil
}

func (f *memFile) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fmt.Errorf("sftp: negative read offset %d", off)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if off >= int64(len(f.data)) {
		return 0, io.EOF
	}
	n := copy(p, f.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
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
	if err := h.iu.Close(); err != nil {
		return err // blocked/unscannable — already refused, no release request
	}
	dec := h.iu.dec
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
		User: h.fs.user, Target: h.path, ObjectKey: req.ID,
		Outcome: "requested", Reason: "quarantine release pending",
	})

	final, werr := h.fs.srv.approvals.Wait(h.fs.ctxOrBackground(), req.ID)
	approved := werr == nil && final.Approved(time.Now())
	h.fs.srv.emit(evidence.Event{
		Time: time.Now().UTC(), Type: evidence.TypeApproval,
		User: h.fs.user, Target: h.path, ObjectKey: req.ID,
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
		User: h.fs.user, Path: h.path, Direction: "upload",
		Bytes: dec.Bytes, SHA256: dec.SHA256, ObjectKey: dec.QuarantineKey,
		Detail: "sftp transfer (released from quarantine)",
	})
	return nil
}

// Filewrite (FilePut): when inspection is enabled, stream the upload through
// the inspection gate; otherwise buffer it in memory and record it as an upload.
func (m *memFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.gate != nil {
		iu := newInspectUpload(m.ctx, m.gate, p)
		// Keyed by handle (appended), not path: a second put to the same path
		// must not drop the first upload's inspection evidence.
		m.inspectUps = append(m.inspectUps, iu)
		return iu, nil
	}

	f := m.files[p]
	if f == nil {
		f = &memFile{name: p, modTime: time.Now()}
		m.files[p] = f
	} else {
		f.mu.Lock()
		f.data = nil
		f.mu.Unlock()
	}
	m.uploads[p] = true
	// Return a write handle whose Close captures the transfer manifest at the
	// path used for the upload, so a later Rename/Remove cannot erase the
	// evidence that these bytes passed through the gateway.
	return &memWriteHandle{fs: m, f: f, path: p}, nil
}

// memWriteHandle wraps a memFile for a single SFTP upload. pkg/sftp closes the
// WriterAt when the transfer completes; Close records the manifest then.
type memWriteHandle struct {
	fs   *memFS
	f    *memFile
	path string
}

func (h *memWriteHandle) WriteAt(p []byte, off int64) (int, error) { return h.f.WriteAt(p, off) }

func (h *memWriteHandle) Close() error {
	h.f.mu.Lock()
	sum := sha256.Sum256(h.f.data)
	tr := transfer{path: h.path, direction: "upload", size: int64(len(h.f.data)), sha256: hex.EncodeToString(sum[:])}
	h.f.mu.Unlock()
	h.fs.recordUpload(tr)
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

// Fileread (FileGet): capture the download manifest at read time (the bytes
// actually served) and return a reader over the content. Capturing here — not
// at session end from mutable state — makes the exfiltration record immune to a
// later Rename/Remove/overwrite, mirroring the hardened upload path.
func (m *memFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	f := m.files[p]
	m.mu.Unlock()
	if f == nil {
		return nil, os.ErrNotExist
	}
	f.mu.Lock()
	tr := transfer{path: p, direction: "download", size: int64(len(f.data))}
	sum := sha256.Sum256(f.data)
	tr.sha256 = hex.EncodeToString(sum[:])
	f.mu.Unlock()

	m.mu.Lock()
	m.completed = append(m.completed, tr)
	m.mu.Unlock()
	return f, nil
}

// Filecmd handles metadata operations. Only the essentials are supported.
func (m *memFS) Filecmd(r *sftp.Request) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method {
	case "Remove":
		delete(m.files, cleanPath(r.Filepath))
	case "Rename":
		src, dst := cleanPath(r.Filepath), cleanPath(r.Target)
		if f, ok := m.files[src]; ok {
			f.name = dst
			m.files[dst] = f
			delete(m.files, src)
		}
	case "Mkdir", "Setstat", "Rmdir", "Symlink":
		// no-ops for the in-memory demo FS
	}
	return nil
}

// Filelist handles List and Stat.
func (m *memFS) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	defer m.mu.Unlock()
	switch r.Method {
	case "List":
		var infos []os.FileInfo
		for name, f := range m.files {
			if path.Dir(name) == p {
				infos = append(infos, f.info())
			}
		}
		return listerAt(infos), nil
	case "Stat":
		if p == "/" {
			return listerAt{memFileInfo{name: "/", dir: true, mod: time.Now()}}, nil
		}
		if f, ok := m.files[p]; ok {
			return listerAt{f.info()}, nil
		}
		return nil, os.ErrNotExist
	}
	return nil, fmt.Errorf("sftp: unsupported list method %q", r.Method)
}

func (f *memFile) info() memFileInfo {
	f.mu.Lock()
	defer f.mu.Unlock()
	return memFileInfo{name: path.Base(f.name), size: int64(len(f.data)), mod: f.modTime}
}

type transfer struct {
	path      string
	direction string
	size      int64
	sha256    string
}

// manifests returns a transfer record for every upload and download. Both
// directions are captured at handle time (uploads at write-handle close,
// downloads at read) into m.completed, so the manifests are immune to a later
// Rename/Remove/overwrite and a re-fetch is its own distinct record.
func (m *memFS) manifests() []transfer {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]transfer(nil), m.completed...)
}

// memFileInfo implements os.FileInfo.
type memFileInfo struct {
	name string
	size int64
	dir  bool
	mod  time.Time
}

func (i memFileInfo) Name() string { return i.name }
func (i memFileInfo) Size() int64  { return i.size }
func (i memFileInfo) Mode() os.FileMode {
	if i.dir {
		return os.ModeDir | 0o755
	}
	return 0o644
}
func (i memFileInfo) ModTime() time.Time { return i.mod }
func (i memFileInfo) IsDir() bool        { return i.dir }
func (i memFileInfo) Sys() interface{}   { return nil }

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
