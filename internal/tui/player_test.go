package tui

import (
	"strings"
	"testing"
)

func TestParseCast(t *testing.T) {
	data := `{"version":2,"width":80,"height":24}
[0.0,"o","hello "]
[0.5,"o","world"]
[1.0,"i","x"]
`
	c, err := ParseCast(strings.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	if c.Width != 80 || c.Height != 24 {
		t.Fatalf("header wrong: %+v", c)
	}
	if len(c.Frames) != 3 || c.Duration() != 1.0 {
		t.Fatalf("frames/duration wrong: %+v", c)
	}
}

func TestParseCast_RejectsNonV2(t *testing.T) {
	if _, err := ParseCast(strings.NewReader(`{"version":1}`)); err == nil {
		t.Fatal("expected version rejection")
	}
	if _, err := ParseCast(strings.NewReader("")); err == nil {
		t.Fatal("expected empty rejection")
	}
}

func TestPlayer_AdvanceSeekToggle(t *testing.T) {
	c := Cast{Frames: []Frame{{0, "o", "A"}, {0.5, "o", "B"}, {1.0, "o", "C"}}}
	p := newPlayer(c)
	if !p.playing {
		t.Fatal("new player should be playing")
	}

	p = p.advanceTo(0.6) // frames at 0 and 0.5
	if p.out != "AB" {
		t.Fatalf("advanceTo(0.6) out=%q", p.out)
	}
	p = p.advanceTo(1.0)
	if p.out != "ABC" || !p.done() {
		t.Fatalf("advanceTo(1.0) out=%q done=%v", p.out, p.done())
	}

	p = p.seek(0) // rewind: only the t=0 frame is shown again
	if p.out != "A" || p.elapsed != 0 {
		t.Fatalf("seek(0) out=%q elapsed=%v", p.out, p.elapsed)
	}
	p = p.seek(0.5)
	if p.out != "AB" {
		t.Fatalf("seek(0.5) out=%q", p.out)
	}

	p = p.toggle()
	if p.playing {
		t.Fatal("toggle should pause")
	}
}

// Input frames ("i") are not rendered to the output buffer.
func TestPlayer_IgnoresInputFrames(t *testing.T) {
	c := Cast{Frames: []Frame{{0, "o", "A"}, {0.1, "i", "SECRET"}, {0.2, "o", "B"}}}
	p := newPlayer(c).advanceTo(1.0)
	if p.out != "AB" {
		t.Fatalf("input frame leaked into output: %q", p.out)
	}
}
