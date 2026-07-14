package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// clock is a manually-advanced time source so lockout/backoff/window logic is
// tested deterministically without sleeping.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Unix(1_700_000_000, 0)} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestLimiter(cfg Config, c *clock) *Limiter {
	l := New(cfg)
	l.now = c.now
	return l
}

func testConfig() Config {
	return Config{
		MaxFailures: 3,
		Window:      1 * time.Minute,
		BaseBackoff: 10 * time.Second,
		MaxBackoff:  40 * time.Second,
		MaxEntries:  100,
	}
}

// Below the threshold, every attempt is allowed.
func TestAllow_UnderThreshold(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	for i := 0; i < 2; i++ { // MaxFailures is 3
		if ok, _ := l.Allow("1.2.3.4"); !ok {
			t.Fatalf("attempt %d must be allowed under threshold", i)
		}
		l.RecordFailure("1.2.3.4")
	}
	if ok, _ := l.Allow("1.2.3.4"); !ok {
		t.Fatal("must still be allowed after 2 failures (threshold is 3)")
	}
}

// Reaching MaxFailures locks the source for BaseBackoff, and the lockout clears
// after the backoff elapses.
func TestLockoutAndExpiry(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("ip"); !ok {
			t.Fatalf("attempt %d should be allowed before lockout", i)
		}
		l.RecordFailure("ip")
	}
	ok, retry := l.Allow("ip")
	if ok {
		t.Fatal("source must be locked out after MaxFailures")
	}
	if retry <= 0 || retry > 10*time.Second {
		t.Fatalf("retryAfter = %v, want (0, 10s]", retry)
	}
	// Not yet expired.
	c.advance(9 * time.Second)
	if ok, _ := l.Allow("ip"); ok {
		t.Fatal("still locked out before backoff elapses")
	}
	// Expired.
	c.advance(2 * time.Second)
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("lockout must clear after backoff elapses")
	}
}

// A success resets the failure counter and any lockout state.
func TestResetOnSuccess(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	l.RecordFailure("ip")
	l.RecordFailure("ip")
	l.RecordSuccess("ip")
	// Counter reset: two fresh failures must not lock (would need 3).
	l.RecordFailure("ip")
	l.RecordFailure("ip")
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("success must reset the failure counter")
	}
}

// Failures older than Window do not accumulate toward a lockout.
func TestSlidingWindow(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	l.RecordFailure("ip")
	l.RecordFailure("ip")
	c.advance(2 * time.Minute) // window is 1m; the two above age out
	l.RecordFailure("ip")
	if ok, _ := l.Allow("ip"); !ok {
		t.Fatal("failures older than the window must not count toward lockout")
	}
}

// Each successive lockout doubles the backoff, capped at MaxBackoff so a source
// can never be locked out permanently.
func TestBackoffDoublesAndIsBounded(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)

	lockAndMeasure := func() time.Duration {
		for i := 0; i < 3; i++ {
			l.RecordFailure("ip")
		}
		_, retry := l.Allow("ip")
		return retry
	}

	first := lockAndMeasure()
	if first != 10*time.Second {
		t.Fatalf("first backoff = %v, want 10s", first)
	}
	c.advance(first + time.Second) // let it expire
	second := lockAndMeasure()
	if second != 20*time.Second {
		t.Fatalf("second backoff = %v, want 20s (doubled)", second)
	}
	c.advance(second + time.Second)
	third := lockAndMeasure()
	if third != 40*time.Second {
		t.Fatalf("third backoff = %v, want 40s (doubled)", third)
	}
	c.advance(third + time.Second)
	fourth := lockAndMeasure()
	if fourth != 40*time.Second { // capped at MaxBackoff, never grows unbounded
		t.Fatalf("fourth backoff = %v, want 40s (capped at MaxBackoff)", fourth)
	}
}

// A lockout on one source must never affect another source: an attacker on IP-A
// cannot deny service to a victim on IP-B.
func TestIsolationBetweenKeys(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	for i := 0; i < 10; i++ {
		l.RecordFailure("attacker")
	}
	if ok, _ := l.Allow("attacker"); ok {
		t.Fatal("attacker source should be locked")
	}
	if ok, _ := l.Allow("victim"); !ok {
		t.Fatal("a different source must remain unaffected (no cross-source DoS)")
	}
}

// The tracked-entry map is bounded so a flood of distinct (possibly spoofed)
// keys cannot exhaust memory, and a real lockout survives the flood.
func TestBoundedEntries(t *testing.T) {
	c := newClock()
	cfg := testConfig()
	cfg.MaxEntries = 50
	l := newTestLimiter(cfg, c)

	// Establish a real lockout that must be preserved.
	for i := 0; i < 3; i++ {
		l.RecordFailure("victim-lockout")
	}
	if ok, _ := l.Allow("victim-lockout"); ok {
		t.Fatal("precondition: victim should be locked out")
	}

	// Flood distinct keys, each with a single failure, advancing time so they
	// become stale and cleanable.
	for i := 0; i < 500; i++ {
		l.RecordFailure(fmt.Sprintf("flood-%d", i))
		c.advance(time.Millisecond)
	}
	if got := l.Len(); got > cfg.MaxEntries {
		t.Fatalf("entry count = %d, must stay <= MaxEntries=%d", got, cfg.MaxEntries)
	}
	// The active lockout must not have been evicted by the flood.
	if ok, _ := l.Allow("victim-lockout"); ok {
		t.Fatal("active lockout must survive a distinct-key flood")
	}
}

// Empty key (unknown source) fails open in the limiter itself; the caller is
// responsible for always supplying a real source.
func TestEmptyKeyFailsOpen(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	for i := 0; i < 100; i++ {
		l.RecordFailure("")
	}
	if ok, _ := l.Allow(""); !ok {
		t.Fatal("empty key must not be throttled by the limiter")
	}
	if l.Len() != 0 {
		t.Fatalf("empty key must not create entries, got Len=%d", l.Len())
	}
}

// Recording a failure while already locked out must not extend the lockout
// (otherwise a persistent attacker could inflate a shared-NAT victim's lockout).
func TestFailureDuringLockoutDoesNotExtend(t *testing.T) {
	c := newClock()
	l := newTestLimiter(testConfig(), c)
	for i := 0; i < 3; i++ {
		l.RecordFailure("ip")
	}
	_, retry0 := l.Allow("ip")
	c.advance(3 * time.Second)
	l.RecordFailure("ip") // hammering while locked
	_, retry1 := l.Allow("ip")
	// retry1 should just be retry0 minus the elapsed 3s, not reset/extended.
	if retry1 > retry0-3*time.Second+time.Millisecond {
		t.Fatalf("lockout was extended by a failure during lockout: retry0=%v retry1=%v", retry0, retry1)
	}
}

// The limiter must be safe under concurrent use.
func TestConcurrentUse(t *testing.T) {
	l := New(testConfig()) // real clock is fine here
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			key := fmt.Sprintf("ip-%d", g%4)
			for i := 0; i < 1000; i++ {
				l.Allow(key)
				l.RecordFailure(key)
				if i%50 == 0 {
					l.RecordSuccess(key)
				}
			}
		}(g)
	}
	wg.Wait()
}
