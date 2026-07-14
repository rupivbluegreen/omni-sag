// Package inspectgate interposes content inspection (ICAP, via internal/inspect)
// on file transfers. It is the Slice-5 wiring that connects the inspect leaf to
// storage and a verdict:
//
//   - Small files (<= threshold) are inspected inline from a bounded memory
//     buffer.
//   - Large files (> threshold) are streamed through inspection while being
//     tee'd to a transient HOLDING blob store, so a large file is never
//     buffered whole in memory (no OOM).
//   - Every upload — clean, blocked, and, fail-closed, content the inspector
//     could not scan (server down/timeout/garbage) — is QUARANTINED to an
//     Object-Locked (WORM) blob store, giving every transfer a permanent,
//     byte-level evidentiary copy. Blocked/unscannable/modified content is
//     additionally refused; clean content is quarantined and still delivered.
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
	QuarantineKey string // set for every verdict: a permanent, byte-level copy in WORM quarantine
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
	atEOF := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
	if rerr != nil && !atEOF {
		return Decision{}, fmt.Errorf("inspectgate: read content: %w", rerr)
	}
	// atEOF means the whole payload fit in the buffer -> small. Otherwise the
	// buffer filled with more still to come -> the payload exceeds the threshold.
	if !atEOF {
		if g.holding == nil {
			// No large-file support configured: fail closed rather than inspect
			// only the prefix and record a (false) clean verdict on a partial file.
			return Decision{Allow: false, Verdict: "error", Bytes: int64(n),
				Reason: "file exceeds inline inspection limit and no holding store is configured"}, nil
		}
		return g.inspectLarge(ctx, meta, io.MultiReader(bytes.NewReader(head), content))
	}
	return g.inspectSmall(ctx, meta, head)
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
		// The inspector wants to alter the payload. We do not currently deliver
		// modified bytes, and delivering the ORIGINAL would defeat the DLP, so
		// treat Modified as fail-closed: quarantine and refuse.
		dec.Verdict, dec.Reason = "modified", "content modification required; delivering sanitized content is not supported — refused: "+res.Reason
		key, qerr := g.quarantineBytes(ctx, meta, data)
		dec.QuarantineKey = key
		return dec, qerr
	case res.Verdict == inspect.VerdictClean:
		key, qerr := g.quarantineBytes(ctx, meta, data)
		if qerr != nil {
			// The scan says clean, but persisting the evidentiary copy failed —
			// this is an infrastructure failure, not a content verdict; fail
			// closed rather than deliver content with no byte-level record.
			// dec.Allow stays false (its zero value): the clean verdict never
			// leaks through when the quarantine write itself fails.
			dec.Verdict, dec.Reason = "error", "quarantine write failed: "+qerr.Error()
			return dec, qerr
		}
		dec.Allow, dec.Verdict, dec.QuarantineKey = true, "clean", key
		return dec, nil
	default:
		// Defense in depth: an unrecognized verdict is NOT a pass. A buggy or
		// compromised inspector returning an out-of-range verdict must fail
		// closed (quarantine + refuse), never fall through to allow.
		dec.Verdict, dec.Reason = "error", fmt.Sprintf("unrecognized inspector verdict %d", res.Verdict)
		key, qerr := g.quarantineBytes(ctx, meta, data)
		dec.QuarantineKey = key
		return dec, qerr
	}
}

// inspectLarge streams content through inspection while tee-ing it to the
// holding store, so nothing larger than the threshold is buffered in memory.
func (g *Gate) inspectLarge(ctx context.Context, meta inspect.TransferMeta, content io.Reader) (Decision, error) {
	holdKey := g.key("holding", meta)

	hpr, hpw := io.Pipe()
	holdErr := make(chan error, 1)
	go func() {
		err := g.holding.Put(ctx, holdKey, "application/octet-stream", hpr, -1)
		// If Put returned early (e.g. the holding write failed mid-stream), close
		// the read side with the error so the tee's next write unblocks and the
		// transfer fails closed instead of deadlocking.
		_ = hpr.CloseWithError(err)
		holdErr <- err
	}()

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
	// Modified is treated as fail-closed like Blocked: we do not deliver modified
	// bytes, and delivering the streamed original would defeat the DLP.
	blocked := got.res.Verdict == inspect.VerdictBlocked || got.res.Verdict == inspect.VerdictModified
	// Defense in depth: only an explicit Clean verdict may be delivered. Any
	// other (unrecognized) verdict fails closed rather than being delivered.
	unknown := !failClosed && !blocked && got.res.Verdict != inspect.VerdictClean
	if failClosed || blocked || unknown {
		if failClosed {
			dec.Verdict = "error"
			if got.err != nil {
				dec.Reason = got.err.Error()
			} else {
				dec.Reason = copyErr.Error()
			}
		} else if got.res.Verdict == inspect.VerdictModified {
			dec.Verdict, dec.Reason = "modified", "content modification required; delivering sanitized content is not supported — refused: "+got.res.Reason
		} else if got.res.Verdict == inspect.VerdictBlocked {
			dec.Verdict, dec.Reason = "blocked", got.res.Reason
		} else {
			dec.Verdict, dec.Reason = "error", fmt.Sprintf("unrecognized inspector verdict %d", got.res.Verdict)
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

	// Clean: promote the held content into quarantine too, same as the
	// blocked path above — every upload gets a permanent, byte-level
	// evidentiary copy, not only blocked ones. The holding copy is deleted
	// once promoted (g.promote already does this).
	qkey := g.key("quarantine", meta)
	if perr := g.promote(ctx, holdKey, qkey); perr != nil {
		// As in inspectSmall: a clean scan verdict does not matter if we
		// cannot persist the evidentiary copy — fail closed (dec.Allow stays
		// false, its zero value) rather than deliver content with no
		// byte-level record.
		dec.Verdict, dec.Reason = "error", "quarantine write failed: "+perr.Error()
		return dec, fmt.Errorf("inspectgate: quarantine: %w", perr)
	}
	dec.Allow, dec.Verdict, dec.QuarantineKey = true, "clean", qkey
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
