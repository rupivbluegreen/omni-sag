package tui

import (
	"strings"
	"testing"
)

// These fuzz targets exercise the asciicast v2 parser and the pure playback
// model. A recording is attacker-influenced content (it captures client input),
// and an operator may replay an arbitrary/corrupt .cast file, so ParseCast and
// the player must never panic, hang, or OOM on hostile input.

// FuzzParseCast fuzzes the asciicast v2 stream parser and then drives the pure
// player over whatever frames it produced (seek to both ends, step forward).
func FuzzParseCast(f *testing.F) {
	f.Add("{\"version\":2,\"width\":80,\"height\":24}\n[0.1,\"o\",\"hi\"]\n[0.2,\"i\",\"x\"]\n")
	f.Add("{\"version\":2,\"width\":80,\"height\":24}\n")
	f.Add("{\"version\":1}\n")
	f.Add("not json\n")
	f.Add("")
	f.Add("{\"version\":2}\n[]\n[1]\n[1,2,3,4]\n[\"a\",\"b\",\"c\"]\n")
	f.Add("{\"version\":2,\"width\":-5,\"height\":999999999}\n[1e308,\"o\",\"x\"]\n")

	f.Fuzz(func(t *testing.T, data string) {
		cast, err := ParseCast(strings.NewReader(data))
		if err != nil {
			return
		}
		_ = cast.Duration()

		p := newPlayer(cast)
		// Seek to the end, back to the start, and step forward one frame at a
		// time. None of these may panic regardless of frame contents.
		p = p.seek(cast.Duration())
		p = p.seek(-1e9)
		p = p.seek(0)
		guard := 0
		for !p.done() && guard < len(cast.Frames)+2 {
			p = p.advanceTo(p.elapsed + 0.001)
			guard++
		}
		_ = p.toggle()
		_ = p.out
	})
}
