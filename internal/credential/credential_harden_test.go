package credential

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// #2: half-open must admit exactly one trial until it resolves.
func TestBreaker_HalfOpenAdmitsOneTrial(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(BreakerConfig{Threshold: 1, Cooldown: 10 * time.Second, Now: func() time.Time { return now }})

	b.Fail() // threshold 1 -> open
	if b.Allow() {
		t.Fatal("breaker should be open after reaching threshold")
	}
	now = now.Add(11 * time.Second) // cooldown elapsed

	if !b.Allow() {
		t.Fatal("first call after cooldown must be admitted (half-open trial)")
	}
	if b.Allow() {
		t.Fatal("half-open must admit only ONE trial until it resolves")
	}
	if b.Allow() {
		t.Fatal("still only one trial in flight")
	}
	b.Success() // trial resolved -> closed
	if !b.Allow() {
		t.Fatal("breaker should be closed after a successful trial")
	}
}

// #2: a failed half-open trial reopens; only one trial per cooldown.
func TestBreaker_FailedTrialReopens(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(BreakerConfig{Threshold: 1, Cooldown: 10 * time.Second, Now: func() time.Time { return now }})
	b.Fail()
	now = now.Add(11 * time.Second)
	if !b.Allow() {
		t.Fatal("trial should be admitted")
	}
	b.Fail() // trial failed -> reopen
	if b.Allow() {
		t.Fatal("a failed trial must reopen the breaker")
	}
	now = now.Add(11 * time.Second)
	if !b.Allow() {
		t.Fatal("next cooldown should admit a fresh trial")
	}
}

// #4: formatting a Secret VALUE (not just *Secret) must redact.
func TestSecret_ValueFormatRedacts(t *testing.T) {
	s := New([]byte("hunter2"))
	for _, v := range []string{
		fmt.Sprintf("%v", *s),
		fmt.Sprintf("%+v", *s),
		fmt.Sprintf("%#v", *s),
		fmt.Sprintf("%s", *s),
		fmt.Sprintf("%v", s), // pointer too
	} {
		if strings.Contains(v, "hunter2") {
			t.Fatalf("secret leaked in formatted output: %q", v)
		}
	}
}
