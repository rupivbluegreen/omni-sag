package eventexport

import (
	"bufio"
	"fmt"
	"os"
	"sync"
)

// fileTransport appends newline-framed payloads to a file — the shape
// filebeat/logbeat expect to tail. Safe to reopen: the file is opened
// append-only, so restarting the process (or a fresh newFileTransport call
// against the same path) never truncates prior events.
type fileTransport struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

func newFileTransport(cfg FileConfig) (*fileTransport, error) {
	if cfg.Path == "" {
		return nil, fmt.Errorf("eventexport: file transport: path required")
	}
	f, err := os.OpenFile(cfg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("eventexport: file transport: %w", err)
	}
	return &fileTransport{f: f, w: bufio.NewWriter(f)}, nil
}

func (t *fileTransport) Write(payload []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, err := t.w.Write(payload); err != nil {
		return err
	}
	return t.w.WriteByte('\n')
}

func (t *fileTransport) Flush() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.w.Flush()
}

func (t *fileTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.w.Flush(); err != nil {
		t.f.Close()
		return err
	}
	return t.f.Close()
}
