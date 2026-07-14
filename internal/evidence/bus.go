package evidence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Bus is the in-process ordered evidence pipeline. Emitters publish Events; a
// single writer goroutine assigns global order, per-emitter (epoch, seq), and a
// hash-chain link, appends each record to the current segment, and — on segment
// rollover and at Close — seals the segment with a signed Merkle checkpoint.
//
// Emit is synchronous end-to-end (it blocks until the record is durably written
// to the local segment file and returns any error), so evidence is never
// silently dropped and callers get real back-pressure.
type Bus struct {
	dir         string
	segmentSize int
	signer      *Signer
	worm        *WORMUploader
	now         func() time.Time

	ch   chan submission
	done chan struct{}

	mu      sync.Mutex
	closed  bool
	sealErr error // error from sealing the final segment at shutdown, surfaced by Close

	// writer-goroutine-owned state (no external access):
	epoch         uint64
	perEmitterSeq map[string]uint64
	globalSeq     uint64
	chainHead     string
	segmentIndex  uint64
	prevCkptHash  string
	segRecords    []Record
	segFile       *os.File
	segWriter     *bufio.Writer
	firstSeqInSeg uint64
}

// BusConfig configures a Bus.
type BusConfig struct {
	DataDir     string        // local output root (segments/, checkpoints/, epoch)
	SegmentSize int           // records per segment before rollover (default 128)
	Signer      *Signer       // required: signs checkpoints
	WORM        *WORMUploader // optional: uploads sealed segments/checkpoints to Object-Locked S3
	Now         func() time.Time
}

type submission struct {
	emitterID string
	event     Event
	reply     chan error
}

// NewBus opens (creating as needed) the local evidence directory, advances the
// epoch, and starts the writer goroutine.
func NewBus(cfg BusConfig) (*Bus, error) {
	if cfg.Signer == nil {
		return nil, fmt.Errorf("evidence bus: signer is required")
	}
	if cfg.SegmentSize <= 0 {
		cfg.SegmentSize = 128
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	for _, sub := range []string{"segments", "checkpoints"} {
		if err := os.MkdirAll(filepath.Join(cfg.DataDir, sub), 0o700); err != nil {
			return nil, fmt.Errorf("evidence bus: mkdir: %w", err)
		}
	}
	epoch, err := advanceEpoch(filepath.Join(cfg.DataDir, "epoch"))
	if err != nil {
		return nil, err
	}
	// Continue the checkpoint hash-chain across process restarts by linking this
	// run's first checkpoint to the previous run's last one. This makes the
	// checkpoint chain GLOBAL (one linked list across all epochs) rather than
	// restarting per epoch, so deleting an interior segment or a whole epoch
	// breaks a prev-link and is detected offline.
	head, err := lastCheckpointHash(filepath.Join(cfg.DataDir, "checkpoints"))
	if err != nil {
		return nil, err
	}

	b := &Bus{
		dir:           cfg.DataDir,
		segmentSize:   cfg.SegmentSize,
		signer:        cfg.Signer,
		worm:          cfg.WORM,
		now:           cfg.Now,
		ch:            make(chan submission, 256),
		done:          make(chan struct{}),
		epoch:         epoch,
		perEmitterSeq: make(map[string]uint64),
		prevCkptHash:  head,
	}
	// Segments are opened lazily on the first record so a run that seals its
	// last full segment (or emits nothing) leaves no empty, checkpoint-less
	// trailing segment behind.
	go b.run()
	return b, nil
}

// advanceEpoch reads the last epoch from path, returns prev+1, and persists it.
// A fresh directory starts at epoch 1. The epoch increments on every process
// start so a restart cannot silently reuse a per-emitter sequence.
func advanceEpoch(path string) (uint64, error) {
	prev := uint64(0)
	if data, err := os.ReadFile(path); err == nil {
		if v, perr := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); perr == nil {
			prev = v
		}
	} else if !os.IsNotExist(err) {
		return 0, fmt.Errorf("evidence bus: read epoch: %w", err)
	}
	next := prev + 1
	// Durably persist the epoch BEFORE it is used. If this write's page is lost
	// on a crash, a restart would reuse the epoch and O_TRUNC-overwrite prior
	// sealed evidence; fsync (file + parent dir) via atomic rename prevents that.
	if err := writeFileDurable(path, []byte(strconv.FormatUint(next, 10)), 0o600); err != nil {
		return 0, fmt.Errorf("evidence bus: write epoch: %w", err)
	}
	return next, nil
}

// writeFileDurable writes data to path atomically and durably: write to a temp
// file in the same dir, fsync it, rename over path, then fsync the directory so
// both the file contents and the directory entry survive a crash.
func writeFileDurable(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return fsyncDir(dir)
}

func fsyncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lastCheckpointHash returns the HashHex of the highest (epoch, segment) sealed
// checkpoint present, or GenesisPrevCheckpoint if none. It is how a new run
// continues the global checkpoint chain.
func lastCheckpointHash(dir string) (string, error) {
	ckpts, err := loadCheckpoints(dir)
	if err != nil {
		return "", err
	}
	if len(ckpts) == 0 {
		return GenesisPrevCheckpoint, nil
	}
	best := ckpts[0]
	for _, c := range ckpts[1:] {
		if c.Epoch > best.Epoch || (c.Epoch == best.Epoch && c.SegmentIndex > best.SegmentIndex) {
			best = c
		}
	}
	return best.HashHex()
}

// Emitter returns a Sink handle whose events are tagged with emitterID and
// carry a per-emitter monotonic sequence. Different subsystems (dialer,
// session) use distinct ids so each has its own gap-detectable sequence.
func (b *Bus) Emitter(emitterID string) Sink {
	return &emitterHandle{bus: b, id: emitterID}
}

type emitterHandle struct {
	bus *Bus
	id  string
}

func (h *emitterHandle) Emit(e Event) error { return h.bus.emit(h.id, e) }

// Close on an emitter handle is a no-op; the Bus owner closes the Bus.
func (h *emitterHandle) Close() error { return nil }

func (b *Bus) emit(emitterID string, e Event) error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return fmt.Errorf("evidence bus: closed")
	}
	b.mu.Unlock()

	reply := make(chan error, 1)
	b.ch <- submission{emitterID: emitterID, event: e, reply: reply}
	return <-reply
}

func (b *Bus) run() {
	defer close(b.done)
	for sub := range b.ch {
		sub.reply <- b.process(sub)
	}
	// Channel drained and closed: seal whatever remains (sealSegment flushes,
	// closes, and clears the open segment). The final seal is where the last
	// segment+checkpoint are written and uploaded to WORM — its error must NOT
	// be swallowed, or a WORM-upload failure on the last segment would be
	// reported as a clean shutdown. Close surfaces sealErr.
	if len(b.segRecords) > 0 {
		b.sealErr = b.sealSegment()
	}
}

func (b *Bus) process(sub submission) error {
	if b.segFile == nil {
		if err := b.openSegment(); err != nil {
			return err
		}
	}
	seq := b.perEmitterSeq[sub.emitterID] + 1
	b.globalSeq++

	ts := sub.event.Time
	if ts.IsZero() {
		ts = b.now()
	}
	rec := Record{
		EmitterID: sub.emitterID,
		Epoch:     b.epoch,
		Seq:       seq,
		GlobalSeq: b.globalSeq,
		Time:      ts.UTC(),
		Event:     sub.event,
	}
	head, err := rec.seal(b.chainHead)
	if err != nil {
		b.globalSeq-- // roll back so ordering stays contiguous
		return err
	}

	line, err := json.Marshal(rec)
	if err != nil {
		b.globalSeq--
		return err
	}
	if _, err := b.segWriter.Write(append(line, '\n')); err != nil {
		b.globalSeq--
		return fmt.Errorf("evidence bus: write record: %w", err)
	}
	if err := b.segWriter.Flush(); err != nil {
		b.globalSeq--
		return fmt.Errorf("evidence bus: flush: %w", err)
	}
	if err := b.segFile.Sync(); err != nil {
		b.globalSeq--
		return fmt.Errorf("evidence bus: fsync: %w", err)
	}

	// Commit in-memory state only after the record is durable.
	b.perEmitterSeq[sub.emitterID] = seq
	b.chainHead = head
	if len(b.segRecords) == 0 {
		b.firstSeqInSeg = rec.GlobalSeq
	}
	b.segRecords = append(b.segRecords, rec)

	if len(b.segRecords) >= b.segmentSize {
		if err := b.sealSegment(); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bus) segmentBaseName() string {
	return fmt.Sprintf("segment-%d-%d", b.epoch, b.segmentIndex)
}

func (b *Bus) checkpointBaseName() string {
	return fmt.Sprintf("checkpoint-%d-%d", b.epoch, b.segmentIndex)
}

func (b *Bus) openSegment() error {
	path := filepath.Join(b.dir, "segments", b.segmentBaseName()+".jsonl")
	// O_EXCL: refuse to overwrite an existing segment. In normal operation the
	// epoch is fresh so the file is new; a collision means an epoch was reused
	// (durability failure) and we must fail closed rather than O_TRUNC away
	// prior sealed evidence.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("evidence bus: open segment: %w", err)
	}
	b.segFile = f
	b.segWriter = bufio.NewWriter(f)
	b.segRecords = nil
	return nil
}

// sealSegment finalizes the current segment: compute Merkle root, build and
// sign a checkpoint, persist it, upload both to WORM storage, then roll to a
// fresh segment.
func (b *Bus) sealSegment() error {
	if b.segWriter != nil {
		if err := b.segWriter.Flush(); err != nil {
			return err
		}
	}
	if b.segFile != nil {
		if err := b.segFile.Close(); err != nil {
			return err
		}
	}

	leaves := make([][]byte, len(b.segRecords))
	for i, r := range b.segRecords {
		cb, err := r.CanonicalBytes()
		if err != nil {
			return err
		}
		leaves[i] = cb
	}
	root := MerkleRoot(leaves)

	last := b.segRecords[len(b.segRecords)-1]
	ckpt := Checkpoint{
		Epoch:              b.epoch,
		SegmentIndex:       b.segmentIndex,
		FirstGlobalSeq:     b.firstSeqInSeg,
		LastGlobalSeq:      last.GlobalSeq,
		RecordCount:        len(b.segRecords),
		MerkleRoot:         hexBytes(root[:]),
		ChainHead:          last.Hash,
		PrevCheckpointHash: b.prevCkptHash,
		Time:               b.now().UTC(),
	}
	if err := ckpt.signWith(b.signer); err != nil {
		return err
	}
	ckptBytes, err := json.MarshalIndent(ckpt, "", "  ")
	if err != nil {
		return err
	}
	ckptPath := filepath.Join(b.dir, "checkpoints", b.checkpointBaseName()+".json")
	if err := os.WriteFile(ckptPath, ckptBytes, 0o600); err != nil {
		return fmt.Errorf("evidence bus: write checkpoint: %w", err)
	}

	if b.worm != nil {
		segPath := filepath.Join(b.dir, "segments", b.segmentBaseName()+".jsonl")
		if err := b.worm.PutSegment(b.segmentBaseName()+".jsonl", segPath); err != nil {
			return err
		}
		if err := b.worm.PutCheckpoint(b.checkpointBaseName()+".json", ckptBytes); err != nil {
			return err
		}
	}

	h, err := ckpt.HashHex()
	if err != nil {
		return err
	}
	b.prevCkptHash = h
	b.segmentIndex++

	// Clear the open segment; the next record lazily opens a fresh one.
	b.segFile = nil
	b.segWriter = nil
	b.segRecords = nil
	return nil
}

// Close stops accepting events, seals any partial segment, and waits for the
// writer to finish.
func (b *Bus) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	b.mu.Unlock()

	close(b.ch)
	<-b.done
	return b.sealErr
}

// Head returns the hash of the latest sealed checkpoint (the global chain
// head). Safe to call after Close (the writer has stopped). Pin it out of band
// as the next verification's expectedHead to detect trailing truncation.
func (b *Bus) Head() string { return b.prevCkptHash }
