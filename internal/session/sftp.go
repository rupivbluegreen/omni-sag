package session

import (
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
	"github.com/rupivbluegreen/omni-sag/internal/policy"
	"golang.org/x/crypto/ssh"
)

// runSFTP serves the SFTP subsystem over channel using an in-memory filesystem,
// then emits a transfer manifest (path, direction, size, SHA-256) for every
// file put or fetched. Terminating SFTP at the gateway (rather than proxying)
// is deliberate: it is the point at which Slice 5 will interpose content
// inspection (ICAP) before a file reaches a backend.
func (s *Server) runSFTP(channel ssh.Channel, pr policy.Principal, srcIP string) {
	fs := newMemFS()
	server := sftp.NewRequestServer(channel, sftp.Handlers{
		FileGet:  fs,
		FilePut:  fs,
		FileCmd:  fs,
		FileList: fs,
	})
	_ = server.Serve()
	_ = server.Close()
	_ = channel.Close()

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
// manifests can be emitted when the session ends.
type memFS struct {
	mu        sync.Mutex
	files     map[string]*memFile
	uploads   map[string]bool
	downloads map[string]bool
}

func newMemFS() *memFS {
	return &memFS{
		files:     map[string]*memFile{},
		uploads:   map[string]bool{},
		downloads: map[string]bool{},
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

// Filewrite (FilePut): truncate-open the target and record it as an upload.
func (m *memFS) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	p := cleanPath(r.Filepath)
	m.mu.Lock()
	defer m.mu.Unlock()
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
