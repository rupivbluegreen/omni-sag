// Package inspectgate interposes content inspection (ICAP, via internal/inspect)
// on file transfers. It is the Slice-5 wiring that connects the inspect leaf to
// storage and a verdict:
//
//   - Small files (<= threshold) are inspected inline from a bounded memory
//     buffer.
//   - Large files (> threshold) are streamed through inspection while being
//     tee'd to a transient HOLDING blob store, so a large clean file is never
//     buffered whole in memory (no OOM).
//   - Blocked content — and, fail-closed, content the inspector could not scan
//     (server down/timeout/garbage) — is QUARANTINED to an Object-Locked (WORM)
//     blob store and the transfer is refused.
//
// The gate does not emit evidence itself; it returns a Decision the caller
// records through the evidence bus, keeping evidence emission in one place.
package inspectgate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"time"

	"github.com/rupivbluegreen/omni-sag/internal/inspect"
)

// BlobStore is a minimal object store. Put with size < 0 streams the reader
// (used for large content so nothing is buffered whole).
type BlobStore interface {
	Put(ctx context.Context, key, contentType string, r io.Reader, size int64) error
	Get(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// Decision is the outcome of inspecting one transfer.
type Decision struct {
	Allow         bool
	Verdict       string // clean | blocked | modified | error
	Reason        string
	SHA256        string
	Bytes         int64
	ICAPStatus    int
	QuarantineKey string // set when content was quarantined (blocked or fail-closed)
	HoldingKey    string // set when a large clean file was streamed to holding (delivered)
}

// Gate inspects transfers and routes them by verdict and size.
type Gate struct {
	insp       inspect.Inspector
	holding    BlobStore // transient, non-WORM; nil disables size-tiering (all buffered)
	quarantine BlobStore // Object-Locked (WORM)
	threshold  int64     // files strictly larger than this stream via holding
	now        func() time.Time
}

// Config configures a Gate.
type Config struct {
	Inspector  inspect.Inspector
	Holding    BlobStore
	Quarantine BlobStore
	Threshold  int64
	Now        func() time.Time
}

// New builds a Gate. Inspector and Quarantine are required.
func New(cfg Config) (*Gate, error) {
	if cfg.Inspector == nil {
		return nil, fmt.Errorf("inspectgate: inspector is required")
	}
	if cfg.Quarantine == nil {
		return nil, fmt.Errorf("inspectgate: quarantine store is required")
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 1 << 20 // 1 MiB
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Gate{
		insp:       cfg.Inspector,
		holding:    cfg.Holding,
		quarantine: cfg.Quarantine,
		threshold:  cfg.Threshold,
		now:        cfg.Now,
	}, nil
}

// Inspect scans content for a transfer described by meta. It returns a Decision;
// the error return is only for a serious infrastructure failure (e.g. quarantine
// write failed) — a scan that the inspector could not complete still yields a
// fail-closed Decision (Allow=false), not an error.
func (g *Gate) Inspect(ctx context.Context, meta inspect.TransferMeta, content io.Reader) (Decision, error) {
	// Peek up to threshold+1 bytes to classify small vs large without buffering
	// more than the threshold.
	head := make([]byte, g.threshold+1)
	n, rerr := io.ReadFull(content, head)
	head = head[:n]
	small := g.holding == nil || rerr == io.EOF || rerr == io.ErrUnexpectedEOF
	if !small && rerr != nil {
		return Decision{}, fmt.Errorf("inspectgate: read content: %w", rerr)
	}
	if small {
		return g.inspectSmall(ctx, meta, head)
	}
	return g.inspectLarge(ctx, meta, io.MultiReader(bytes.NewReader(head), content))
}

// inspectSmall inspects a fully-buffered payload.
func (g *Gate) inspectSmall(ctx context.Context, meta inspect.TransferMeta, data []byte) (Decision, error) {
	sum := sha256.Sum256(data)
	dec := Decision{SHA256: hex.EncodeToString(sum[:]), Bytes: int64(len(data))}

	res, err := g.insp.Inspect(ctx, meta, bytes.NewReader(data))
	dec.ICAPStatus = res.ICAPStatus
	switch {
	case err != nil:
		// Fail closed: could not scan → treat as blocked and quarantine.
		dec.Verdict, dec.Reason = "error", err.Error()
		key, qerr := g.quarantineBytes(ctx, meta, data)
		dec.QuarantineKey = key
		return dec, qerr
	case res.Verdict == inspect.VerdictBlocked:
		dec.Verdict, dec.Reason = "blocked", res.Reason
		key, qerr := g.quarantineBytes(ctx, meta, data)
		dec.QuarantineKey = key
		return dec, qerr
	case res.Verdict == inspect.VerdictModified:
		dec.Allow, dec.Verdict, dec.Reason = true, "modified", res.Reason
		return dec, nil
	default:
		dec.Allow, dec.Verdict = true, "clean"
		return dec, nil
	}
}

// inspectLarge streams content through inspection while tee-ing it to the
// holding store, so nothing larger than the threshold is buffered in memory.
func (g *Gate) inspectLarge(ctx context.Context, meta inspect.TransferMeta, content io.Reader) (Decision, error) {
	holdKey := g.key("holding", meta)

	hpr, hpw := io.Pipe()
	holdErr := make(chan error, 1)
	go func() { holdErr <- g.holding.Put(ctx, holdKey, "application/octet-stream", hpr, -1) }()

	ipr, ipw := io.Pipe()
	type ir struct {
		res inspect.Result
		err error
	}
	inspCh := make(chan ir, 1)
	go func() {
		res, err := g.insp.Inspect(ctx, meta, ipr)
		// Drain anything the inspector left unread so the copier never blocks.
		_, _ = io.Copy(io.Discard, ipr)
		inspCh <- ir{res, err}
	}()

	hasher := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(ipw, hpw, hasher), content)
	_ = ipw.Close()
	_ = hpw.Close()
	got := <-inspCh
	hErr := <-holdErr

	dec := Decision{SHA256: hex.EncodeToString(hasher.Sum(nil)), Bytes: n, ICAPStatus: got.res.ICAPStatus}
	if hErr != nil {
		return dec, fmt.Errorf("inspectgate: holding upload: %w", hErr)
	}

	failClosed := copyErr != nil || got.err != nil
	blocked := got.res.Verdict == inspect.VerdictBlocked
	if failClosed || blocked {
		if failClosed {
			dec.Verdict = "error"
			if got.err != nil {
				dec.Reason = got.err.Error()
			} else {
				dec.Reason = copyErr.Error()
			}
		} else {
			dec.Verdict, dec.Reason = "blocked", got.res.Reason
		}
		// Promote the held content into WORM quarantine, then drop the holding
		// copy. Streamed, so a large blocked file is not buffered.
		qkey := g.key("quarantine", meta)
		if perr := g.promote(ctx, holdKey, qkey); perr != nil {
			return dec, fmt.Errorf("inspectgate: quarantine: %w", perr)
		}
		dec.QuarantineKey = qkey
		return dec, nil
	}

	// Clean (or modified): the holding object is the delivered artifact.
	dec.Allow = true
	dec.HoldingKey = holdKey
	if got.res.Verdict == inspect.VerdictModified {
		dec.Verdict, dec.Reason = "modified", got.res.Reason
	} else {
		dec.Verdict = "clean"
	}
	return dec, nil
}

// quarantineBytes writes buffered content to the WORM store and returns its key.
func (g *Gate) quarantineBytes(ctx context.Context, meta inspect.TransferMeta, data []byte) (string, error) {
	key := g.key("quarantine", meta)
	if err := g.quarantine.Put(ctx, key, "application/octet-stream", bytes.NewReader(data), int64(len(data))); err != nil {
		return "", fmt.Errorf("inspectgate: quarantine put: %w", err)
	}
	return key, nil
}

// promote streams an object from the holding store into WORM quarantine, then
// deletes the holding copy.
func (g *Gate) promote(ctx context.Context, srcKey, dstKey string) error {
	rc, err := g.holding.Get(ctx, srcKey)
	if err != nil {
		return fmt.Errorf("get holding %s: %w", srcKey, err)
	}
	defer rc.Close()
	if err := g.quarantine.Put(ctx, dstKey, "application/octet-stream", rc, -1); err != nil {
		return fmt.Errorf("put quarantine %s: %w", dstKey, err)
	}
	_ = g.holding.Delete(ctx, srcKey)
	return nil
}

func (g *Gate) key(kind string, meta inspect.TransferMeta) string {
	name := meta.Filename
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("%s/%s-%s", kind, g.now().Format("20060102T150405.000000000Z"), name)
}
