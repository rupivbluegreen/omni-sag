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
func (s *Server) runSFTP(ctx context.Context, channel ssh.Channel, pr policy.Principal, srcIP string) {
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
	downloads  map[string]bool
	inspectUps map[string]*inspectUpload
}

func newMemFS(gate *inspectgate.Gate, ctx context.Context, user string) *memFS {
	return &memFS{
		gate:       gate,
		ctx:        ctx,
		user:       user,
		files:      map[string]*memFile{},
		uploads:    map[string]bool{},
		downloads:  map[string]bool{},
		inspectUps: map[string]*inspectUpload{},
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

type memFile struct {
	name    string
	mu      sync.Mutex
	data    []byte
	modTime time.Time
}

func (f *memFile) WriteAt(p []byte, off int64) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	end := off + int64(len(p))
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

// Filewrite (FilePut): when inspection is enabled, stream the upload through
// the inspection gate; otherwise buffer it in memory and record it as an upload.
func (m *memFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.gate != nil {
		iu := newInspectUpload(m.ctx, m.gate, p)
		m.inspectUps[p] = iu
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
	return f, nil
}

// inspectUpload is an io.WriterAt+io.Closer that streams an SFTP upload through
// the inspection gate. Writes must be sequential (SFTP uploads are); an
// out-of-order write is refused. Close blocks for the verdict and returns an
// error when the content is blocked or unscannable, which the SFTP layer
// surfaces to the client as a failed transfer.
type inspectUpload struct {
	ctx  context.Context
	gate *inspectgate.Gate
	path string

	once    sync.Once
	pw      *io.PipeWriter
	done    chan struct{}
	expOff  int64
	dec     inspectgate.Decision
	inspErr error

	closeOnce sync.Once
	closeErr  error
}

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
	if off != u.expOff {
		return 0, fmt.Errorf("sftp: non-sequential write to inspected upload (got %d want %d)", off, u.expOff)
	}
	n, err := u.pw.Write(p)
	u.expOff += int64(n)
	return n, err
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

// Fileread (FileGet): record a download and return a reader over the content.
func (m *memFS) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	defer m.mu.Unlock()
	f := m.files[p]
	if f == nil {
		return nil, os.ErrNotExist
	}
	m.downloads[p] = true
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

// manifests computes a transfer record for every uploaded/downloaded path.
func (m *memFS) manifests() []transfer {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []transfer
	add := func(p, dir string) {
		f := m.files[p]
		if f == nil {
			return
		}
		f.mu.Lock()
		sum := sha256.Sum256(f.data)
		out = append(out, transfer{path: p, direction: dir, size: int64(len(f.data)), sha256: hex.EncodeToString(sum[:])})
		f.mu.Unlock()
	}
	for p := range m.uploads {
		add(p, "upload")
	}
	for p := range m.downloads {
		if !m.uploads[p] { // a file both put and fetched reports once as upload
			add(p, "download")
		}
	}
	return out
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
