package credential

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestSecret_ZeroizeAndBytes(t *testing.T) {
	buf := []byte("hunter2")
	s := New(buf)
	if string(s.Bytes()) != "hunter2" {
		t.Fatalf("Bytes = %q", s.Bytes())
	}
	if s.Len() != 7 {
		t.Fatalf("Len = %d", s.Len())
	}
	s.Destroy()
	if s.Bytes() != nil {
		t.Fatal("Bytes after Destroy must be nil")
	}
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("underlying buffer not zeroized at %d", i)
		}
	}
	s.Destroy() // idempotent
}

func TestSecret_NeverLeaksViaFormatting(t *testing.T) {
	s := New([]byte("t0p-s3cret"))
	got := fmt.Sprintf("v=%v s=%s q=%q gv=%#v", s, s, s, s)
	if strings.Contains(got, "t0p-s3cret") {
		t.Fatalf("secret leaked via formatting: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Fatalf("expected REDACTED, got %q", got)
	}
}

// ADR-0001: Secret must not implement fmt.Stringer.
func TestSecret_HasNoStringMethod(t *testing.T) {
	var i any = New(nil)
	if _, ok := i.(interface{ String() string }); ok {
		t.Fatal("Secret must not implement String() (ADR-0001)")
	}
}

type failFetcher struct{}

func (failFetcher) Fetch(context.Context, Query) (*Secret, error) {
	return nil, errors.New("ccp unreachable")
}

type okFetcher struct{ pw string }

func (f okFetcher) Fetch(context.Context, Query) (*Secret, error) {
	return New([]byte(f.pw)), nil
}

type emptyFetcher struct{}

func (emptyFetcher) Fetch(context.Context, Query) (*Secret, error) { return New(nil), nil }

func TestResolve_NonInjectModes(t *testing.T) {
	p := NewProvider(Config{})
	ctx := context.Background()

	if r, err := p.Resolve(ctx, Request{Mode: ModePassthrough}); err != nil || r.Outcome != OutcomePassthrough {
		t.Fatalf("passthrough: %+v %v", r, err)
	}
	if r, err := p.Resolve(ctx, Request{Mode: ""}); err != nil || r.Outcome != OutcomePassthrough {
		t.Fatalf("empty mode must normalize to passthrough: %+v %v", r, err)
	}
	if r, err := p.Resolve(ctx, Request{Mode: ModePrompt}); err != nil || r.Outcome != OutcomePrompt {
		t.Fatalf("prompt: %+v %v", r, err)
	}
	r, err := p.Resolve(ctx, Request{Mode: ModeDeny})
	if !errors.Is(err, ErrDenied) || r.Outcome != OutcomeDenied {
		t.Fatalf("deny must return ErrDenied: %+v %v", r, err)
	}
}

// The load-bearing property (FR-18): inject must NEVER downgrade. Every failure
// mode yields ErrFailClosed with no secret and no prompt/passthrough outcome.
func TestResolve_InjectNeverDowngrades(t *testing.T) {
	ctx := context.Background()
	cases := map[string]*Provider{
		"no fetcher configured": NewProvider(Config{}),
		"fetcher errors":        NewProvider(Config{Fetcher: failFetcher{}, Query: func(Request) Query { return Query{} }}),
		"fetcher returns empty": NewProvider(Config{Fetcher: emptyFetcher{}, Query: func(Request) Query { return Query{} }}),
	}
	for name, p := range cases {
		r, err := p.Resolve(ctx, Request{Mode: ModeInject, Target: "db.lab:22"})
		if !errors.Is(err, ErrFailClosed) {
			t.Fatalf("%s: expected ErrFailClosed, got %v", name, err)
		}
		if r.Secret != nil {
			t.Fatalf("%s: fail-closed must yield no secret", name)
		}
		if r.Outcome == OutcomePrompt || r.Outcome == OutcomePassthrough {
			t.Fatalf("%s: SILENT DOWNGRADE — outcome %s", name, r.Outcome)
		}
	}
}

func TestResolve_InjectSuccess(t *testing.T) {
	p := NewProvider(Config{Fetcher: okFetcher{pw: "s3cr3t!"}, Query: func(Request) Query { return Query{} }})
	r, err := p.Resolve(context.Background(), Request{Mode: ModeInject, Target: "db.lab:22"})
	if err != nil {
		t.Fatalf("inject success: %v", err)
	}
	if r.Outcome != OutcomeInjected || string(r.Secret.Bytes()) != "s3cr3t!" {
		t.Fatalf("unexpected result: %+v", r)
	}
	r.Secret.Destroy()
}
