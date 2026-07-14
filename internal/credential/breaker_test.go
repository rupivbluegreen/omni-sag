package credential

import (
	"testing"
	"time"
)

func TestBreaker_OpensAndRecovers(t *testing.T) {
	now := time.Unix(0, 0)
	clock := func() time.Time { return now }
	b := NewBreaker(BreakerConfig{Threshold: 2, Cooldown: 10 * time.Second, Now: clock})

	if !b.Allow() {
		t.Fatal("fresh breaker must be closed")
	}
	b.Fail()
	if !b.Allow() {
		t.Fatal("one failure below threshold must stay closed")
	}
	b.Fail() // reaches threshold 2 → open
	if b.Allow() {
		t.Fatal("breaker must be open after reaching threshold")
	}
	// Before cooldown elapses, stays open.
	now = now.Add(5 * time.Second)
	if b.Allow() {
		t.Fatal("must stay open during cooldown")
	}
	// After cooldown, half-open allows one trial.
	now = now.Add(6 * time.Second)
	if !b.Allow() {
		t.Fatal("must half-open after cooldown")
	}
	// A failed trial reopens.
	b.Fail()
	if b.Allow() {
		t.Fatal("failed half-open trial must reopen")
	}
	// After another cooldown, a successful trial closes it.
	now = now.Add(11 * time.Second)
	if !b.Allow() {
		t.Fatal("must half-open again")
	}
	b.Success()
	if !b.Allow() {
		t.Fatal("success must close the breaker")
	}
}
