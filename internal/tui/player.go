package tui

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Frame is one asciicast v2 event: [time, kind, data]. Kind is "o" (output) or
// "i" (input).
type Frame struct {
	Time float64
	Kind string
	Data string
}

// Cast is a parsed asciicast v2 recording.
type Cast struct {
	Width  int
	Height int
	Frames []Frame
}

// Duration is the timestamp of the last frame.
func (c Cast) Duration() float64 {
	if len(c.Frames) == 0 {
		return 0
	}
	return c.Frames[len(c.Frames)-1].Time
}

// ParseCast parses an asciicast v2 stream: a JSON header line followed by
// one JSON array event per line.
func ParseCast(r io.Reader) (Cast, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8<<20)

	var cast Cast
	haveHeader := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if !haveHeader {
			var hdr struct {
				Version int `json:"version"`
				Width   int `json:"width"`
				Height  int `json:"height"`
			}
			if err := json.Unmarshal([]byte(line), &hdr); err != nil {
				return Cast{}, fmt.Errorf("asciicast: bad header: %w", err)
			}
			if hdr.Version != 2 {
				return Cast{}, fmt.Errorf("asciicast: unsupported version %d", hdr.Version)
			}
			cast.Width, cast.Height = hdr.Width, hdr.Height
			haveHeader = true
			continue
		}
		var ev []json.RawMessage
		if err := json.Unmarshal([]byte(line), &ev); err != nil || len(ev) != 3 {
			continue // tolerate a malformed event line
		}
		var t float64
		var kind, data string
		if json.Unmarshal(ev[0], &t) != nil || json.Unmarshal(ev[1], &kind) != nil || json.Unmarshal(ev[2], &data) != nil {
			continue
		}
		cast.Frames = append(cast.Frames, Frame{Time: t, Kind: kind, Data: data})
	}
	if err := sc.Err(); err != nil {
		return Cast{}, err
	}
	if !haveHeader {
		return Cast{}, fmt.Errorf("asciicast: empty or missing header")
	}
	return cast, nil
}

// player is the pure playback model driving the replay view. It is deliberately
// runtime-free so Update logic is unit-testable: advance time, and it emits the
// accumulated output up to that point.
type player struct {
	cast    Cast
	idx     int     // next frame to emit
	elapsed float64 // current playback position (seconds)
	playing bool
	out     string // accumulated "o" output up to elapsed
}

func newPlayer(c Cast) player { return player{cast: c, playing: true} }

// advanceTo moves playback to absolute time t (t >= elapsed), emitting any
// output frames in between.
func (p player) advanceTo(t float64) player {
	for p.idx < len(p.cast.Frames) && p.cast.Frames[p.idx].Time <= t {
		if p.cast.Frames[p.idx].Kind == "o" {
			p.out += p.cast.Frames[p.idx].Data
		}
		p.idx++
	}
	p.elapsed = t
	return p
}

// seek jumps to absolute time t (may be earlier), rebuilding the output buffer.
func (p player) seek(t float64) player {
	if t < 0 {
		t = 0
	}
	p.idx, p.out, p.elapsed = 0, "", 0
	return p.advanceTo(t)
}

func (p player) toggle() player { p.playing = !p.playing; return p }

func (p player) done() bool { return p.idx >= len(p.cast.Frames) }
