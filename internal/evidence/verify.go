package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// VerifyReport is the outcome of an offline bundle verification.
type VerifyReport struct {
	OK                 bool
	RecordsChecked     int
	SegmentsChecked    int
	CheckpointsChecked int
	SigningKeys        []string // distinct checkpoint public keys seen
	Problems           []string // every failure, most useful first
}

func (r *VerifyReport) fail(format string, a ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, a...))
}

type segmentFile struct {
	epoch   uint64
	index   uint64
	name    string
	records []Record
}

// VerifyBundle verifies an evidence bundle offline: it recomputes record
// hashes, checks the hash chain and per-emitter (epoch, seq) contiguity,
// recomputes each segment's Merkle root, and verifies every checkpoint
// signature and the checkpoint hash-chain. No gateway is required.
//
// If pinnedKey is non-empty, every checkpoint must be signed by that hex public
// key. Otherwise the embedded keys are trusted but must be internally
// consistent (all checkpoints share one key).
func VerifyBundle(dir, pinnedKey string) (*VerifyReport, error) {
	rep := &VerifyReport{}

	segs, err := loadSegments(filepath.Join(dir, "segments"))
	if err != nil {
		return nil, err
	}
	ckpts, err := loadCheckpoints(filepath.Join(dir, "checkpoints"))
	if err != nil {
		return nil, err
	}
	if len(segs) == 0 {
		rep.fail("bundle contains no segments")
	}

	verifyRecordHashes(rep, segs)
	all := flattenSorted(segs)
	rep.RecordsChecked = len(all)
	verifyPerEpochChains(rep, all)
	verifyPerEmitterSequences(rep, all)
	verifyCheckpoints(rep, segs, ckpts, pinnedKey)

	rep.SegmentsChecked = len(segs)
	rep.CheckpointsChecked = len(ckpts)
	rep.OK = len(rep.Problems) == 0
	return rep, nil
}

// verifyRecordHashes recomputes each record's canonical hash and compares it to
// the stored Hash — the core tamper check.
func verifyRecordHashes(rep *VerifyReport, segs []segmentFile) {
	for _, s := range segs {
		for i, r := range s.records {
			got, err := r.ComputeHash()
			if err != nil {
				rep.fail("segment %s record #%d (global_seq=%d): cannot hash: %v", s.name, i, r.GlobalSeq, err)
				continue
			}
			if got != r.Hash {
				rep.fail("TAMPER: segment %s record #%d (emitter=%s epoch=%d seq=%d global_seq=%d): hash mismatch (stored=%s recomputed=%s)",
					s.name, i, r.EmitterID, r.Epoch, r.Seq, r.GlobalSeq, short(r.Hash), short(got))
			}
		}
	}
}

// verifyPerEpochChains checks, WITHIN each epoch, that global_seq is contiguous
// 1..N and that prev_hash links each record to its predecessor (the first
// record links to genesis). The hash chain and global_seq restart per epoch
// (each process start is a fresh, independently-signed chain); cross-epoch
// deletion is instead prevented by writing sealed segments to WORM storage.
func verifyPerEpochChains(rep *VerifyReport, all []Record) {
	byEpoch := map[uint64][]Record{}
	for _, r := range all {
		byEpoch[r.Epoch] = append(byEpoch[r.Epoch], r)
	}
	epochs := make([]uint64, 0, len(byEpoch))
	for e := range byEpoch {
		epochs = append(epochs, e)
	}
	sort.Slice(epochs, func(i, j int) bool { return epochs[i] < epochs[j] })

	for _, ep := range epochs {
		recs := byEpoch[ep]
		sort.Slice(recs, func(i, j int) bool { return recs[i].GlobalSeq < recs[j].GlobalSeq })
		for i, r := range recs {
			wantSeq := uint64(i + 1)
			if r.GlobalSeq != wantSeq {
				rep.fail("epoch %d: global_seq gap/reorder at position %d: got %d, want %d", ep, i, r.GlobalSeq, wantSeq)
			}
			wantPrev := GenesisPrevHash
			if i > 0 {
				wantPrev = recs[i-1].Hash
			}
			if r.PrevHash != wantPrev {
				rep.fail("epoch %d: broken hash chain at global_seq=%d: prev_hash=%s, want %s", ep, r.GlobalSeq, short(r.PrevHash), short(wantPrev))
			}
		}
	}
}

// verifyPerEmitterSequences checks that within each (emitter, epoch) the seq is
// 1..N contiguous with no gaps or duplicates.
func verifyPerEmitterSequences(rep *VerifyReport, all []Record) {
	type key struct {
		emitter string
		epoch   uint64
	}
	seqs := map[key][]uint64{}
	for _, r := range all {
		k := key{r.EmitterID, r.Epoch}
		seqs[k] = append(seqs[k], r.Seq)
	}
	// stable iteration for deterministic output
	keys := make([]key, 0, len(seqs))
	for k := range seqs {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].emitter != keys[j].emitter {
			return keys[i].emitter < keys[j].emitter
		}
		return keys[i].epoch < keys[j].epoch
	})
	for _, k := range keys {
		s := append([]uint64(nil), seqs[k]...)
		sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
		for i, v := range s {
			want := uint64(i + 1)
			if v != want {
				rep.fail("emitter %q epoch %d: sequence gap/duplicate — expected %d, got %d", k.emitter, k.epoch, want, v)
				break
			}
		}
	}
}

// verifyCheckpoints verifies each checkpoint signature, the checkpoint
// hash-chain, and that each checkpoint's Merkle root / chain head / count match
// the actual segment records. It also flags segments with no checkpoint.
func verifyCheckpoints(rep *VerifyReport, segs []segmentFile, ckpts []Checkpoint, pinnedKey string) {
	byIndex := map[[2]uint64]segmentFile{}
	covered := map[[2]uint64]bool{}
	for _, s := range segs {
		byIndex[[2]uint64{s.epoch, s.index}] = s
	}

	sort.Slice(ckpts, func(i, j int) bool {
		if ckpts[i].Epoch != ckpts[j].Epoch {
			return ckpts[i].Epoch < ckpts[j].Epoch
		}
		return ckpts[i].SegmentIndex < ckpts[j].SegmentIndex
	})

	keySeen := map[string]bool{}
	// The checkpoint hash-chain restarts per epoch, mirroring the record chain.
	prevHashByEpoch := map[uint64]string{}
	for ci, c := range ckpts {
		keySeen[c.PublicKey] = true
		if pinnedKey != "" && c.PublicKey != pinnedKey {
			rep.fail("checkpoint %d-%d signed by unpinned key %s (want %s)", c.Epoch, c.SegmentIndex, short(c.PublicKey), short(pinnedKey))
		}
		if !c.VerifySig() {
			rep.fail("checkpoint %d-%d: INVALID signature", c.Epoch, c.SegmentIndex)
		}
		want, ok := prevHashByEpoch[c.Epoch]
		if !ok {
			want = GenesisPrevCheckpoint
		}
		if c.PrevCheckpointHash != want {
			rep.fail("checkpoint %d-%d: broken checkpoint chain (prev=%s, want %s)", c.Epoch, c.SegmentIndex, short(c.PrevCheckpointHash), short(want))
		}
		h, err := c.HashHex()
		if err != nil {
			rep.fail("checkpoint %d-%d: cannot hash: %v", c.Epoch, c.SegmentIndex, err)
		}
		prevHashByEpoch[c.Epoch] = h

		seg, ok := byIndex[[2]uint64{c.Epoch, c.SegmentIndex}]
		if !ok {
			rep.fail("checkpoint %d-%d has no matching segment", c.Epoch, c.SegmentIndex)
			continue
		}
		covered[[2]uint64{c.Epoch, c.SegmentIndex}] = true

		if c.RecordCount != len(seg.records) {
			rep.fail("checkpoint %d-%d: record_count=%d but segment has %d records (truncation/injection)", c.Epoch, c.SegmentIndex, c.RecordCount, len(seg.records))
		}
		leaves := make([][]byte, len(seg.records))
		for i, r := range seg.records {
			cb, _ := r.CanonicalBytes()
			leaves[i] = cb
		}
		root := hexBytes(mustRoot(leaves))
		if root != c.MerkleRoot {
			rep.fail("checkpoint %d-%d: Merkle root mismatch (stored=%s recomputed=%s)", c.Epoch, c.SegmentIndex, short(c.MerkleRoot), short(root))
		}
		if len(seg.records) > 0 {
			last := seg.records[len(seg.records)-1]
			if c.ChainHead != last.Hash {
				rep.fail("checkpoint %d-%d: chain_head mismatch (stored=%s actual=%s)", c.Epoch, c.SegmentIndex, short(c.ChainHead), short(last.Hash))
			}
		}
		_ = ci
	}

	for _, s := range segs {
		if !covered[[2]uint64{s.epoch, s.index}] {
			rep.fail("segment %s is not covered by any checkpoint (unsealed or missing checkpoint)", s.name)
		}
	}

	if pinnedKey == "" && len(keySeen) > 1 {
		rep.fail("checkpoints signed by %d different keys; bundle is not internally consistent", len(keySeen))
	}
	for k := range keySeen {
		rep.SigningKeys = append(rep.SigningKeys, k)
	}
	sort.Strings(rep.SigningKeys)
}

func mustRoot(leaves [][]byte) []byte {
	r := MerkleRoot(leaves)
	return r[:]
}

func flattenSorted(segs []segmentFile) []Record {
	var all []Record
	for _, s := range segs {
		all = append(all, s.records...)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].GlobalSeq < all[j].GlobalSeq })
	return all
}

func loadSegments(dir string) ([]segmentFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []segmentFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		epoch, index, ok := parseEpochIndex(e.Name(), "segment-", ".jsonl")
		if !ok {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		sf := segmentFile{epoch: epoch, index: index, name: e.Name()}
		for _, line := range strings.Split(strings.TrimRight(string(data), "\n"), "\n") {
			if line == "" {
				continue
			}
			var r Record
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				return nil, fmt.Errorf("segment %s: bad record json: %w", e.Name(), err)
			}
			sf.records = append(sf.records, r)
		}
		out = append(out, sf)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].epoch != out[j].epoch {
			return out[i].epoch < out[j].epoch
		}
		return out[i].index < out[j].index
	})
	return out, nil
}

func loadCheckpoints(dir string) ([]Checkpoint, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Checkpoint
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var c Checkpoint
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, fmt.Errorf("checkpoint %s: bad json: %w", e.Name(), err)
		}
		out = append(out, c)
	}
	return out, nil
}

func parseEpochIndex(name, prefix, suffix string) (uint64, uint64, bool) {
	s := strings.TrimSuffix(strings.TrimPrefix(name, prefix), suffix)
	parts := strings.Split(s, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	epoch, err1 := strconv.ParseUint(parts[0], 10, 64)
	index, err2 := strconv.ParseUint(parts[1], 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return epoch, index, true
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
