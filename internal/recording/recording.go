// Package recording captures interactive terminal sessions as asciicast v2 and
// produces a tamper-evident manifest (object key + SHA-256 + size + duration)
// for the evidence chain. The cast data is streamed to a Store as it is
// produced — never buffered whole in memory — so long sessions do not grow the
// process heap.
package recording

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// Header is the asciicast v2 header line.
type Header struct {
	Version   int    `json:"version"`
	Width     int    `json:"width"`
	Height    int    `json:"height"`
	Timestamp int64  `json:"timestamp"`
	Title     string `json:"title,omitempty"`
}

// Manifest describes a completed recording. It is what the evidence chain
// records; the cast bytes themselves live in the Store.
type Manifest struct {
	Key       string
	SHA256    string
	Bytes     int64
	Duration  time.Duration
	StartedAt time.Time
	Width     int
	Height    int
}

// Recorder encodes an asciicast v2 stream. It is safe for concurrent Output and
// Input calls (a shell writes output while the client sends input).
type Recorder struct {
	mu      sync.Mutex
	w       io.Writer // MultiWriter(dest, hasher)
	dest    io.WriteCloser
	hasher  interface{ Sum([]byte) []byte }
	key     string
	start   time.Time
	now     func() time.Time
	width   int
	height  int
	written int64
	err     error
	closed  bool
}

// NewRecorder starts a recording, writing the asciicast header immediately to
// dest. width/height are the initial terminal dimensions.
func NewRecorder(dest io.WriteCloser, key string, width, height int, now func() time.Time) (*Recorder, error) {
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	h := sha256.New()
	r := &Recorder{
		w:      io.MultiWriter(dest, h),
		dest:   dest,
		hasher: h,
		key:    key,
		start:  now().UTC(),
		now:    now,
		width:  width,
		height: height,
	}
	hdr := Header{Version: 2, Width: width, Height: height, Timestamp: r.start.Unix(), Title: "omni-sag session"}
	line, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	if err := r.writeLine(line); err != nil {
		return nil, err
	}
	return r, nil
}

// Output records terminal output ("o") bytes.
func (r *Recorder) Output(p []byte) { r.event("o", p) }

// Input records client input ("i") bytes.
func (r *Recorder) Input(p []byte) { r.event("i", p) }

func (r *Recorder) event(kind string, p []byte) {
	if len(p) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.err != nil {
		return
	}
	elapsed := r.now().UTC().Sub(r.start).Seconds()
	// asciicast event: [time, kind, data]
	ev := []interface{}{elapsed, kind, string(p)}
	line, err := json.Marshal(ev)
	if err != nil {
		r.err = err
		return
	}
	r.err = r.writeLine(line)
}

// writeLine appends a JSON line; caller holds the lock (or is in construction).
func (r *Recorder) writeLine(line []byte) error {
	n, err := r.w.Write(append(line, '\n'))
	r.written += int64(n)
	return err
}

// Close finalizes the recording: flushes/uploads via the Store and returns the
// manifest. Any deferred write or upload error is returned.
func (r *Recorder) Close() (Manifest, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Manifest{}, fmt.Errorf("recording: already closed")
	}
	r.closed = true
	closeErr := r.dest.Close()
	if r.err != nil {
		return Manifest{}, r.err
	}
	if closeErr != nil {
		return Manifest{}, closeErr
	}
	return Manifest{
		Key:       r.key,
		SHA256:    hex.EncodeToString(r.hasher.Sum(nil)),
		Bytes:     r.written,
		Duration:  r.now().UTC().Sub(r.start),
		StartedAt: r.start,
		Width:     r.width,
		Height:    r.height,
	}, nil
}
