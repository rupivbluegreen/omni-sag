package credential

import (
	"sync"
	"time"
)

// Breaker is a simple circuit breaker guarding CyberArk. After Threshold
// consecutive failures it opens for Cooldown, then half-opens to allow a single
// trial; a success closes it. While open, `inject` fails closed immediately
// instead of hammering a down CCP.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	mu        sync.Mutex
	failures  int
	openUntil time.Time
	halfOpen  bool
}

// BreakerConfig configures a Breaker. Zero values get sane defaults.
type BreakerConfig struct {
	Threshold int
	Cooldown  time.Duration
	Now       func() time.Time
}

// NewBreaker returns a closed breaker.
func NewBreaker(cfg BreakerConfig) *Breaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 3
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Breaker{threshold: cfg.Threshold, cooldown: cfg.Cooldown, now: cfg.Now}
}

// Allow reports whether a call may proceed. When open it returns false until the
// cooldown elapses, then permits EXACTLY ONE trial (half-open) — further calls
// are refused until that trial resolves via Success/Fail, so a down or slow CCP
// cannot be hit by a storm of concurrent requests.
func (b *Breaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.openUntil.IsZero() {
		return true // closed
	}
	if b.halfOpen {
		return false // a trial is already in flight; admit only one
	}
	if b.now().Before(b.openUntil) {
		return false // still open
	}
	b.halfOpen = true // cooldown elapsed and no trial in flight → admit one
	return true
}

// Success resets the breaker to fully closed.
func (b *Breaker) Success() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.openUntil = time.Time{}
	b.halfOpen = false
}

// Fail records a failure. A failed half-open trial reopens the breaker; enough
// consecutive failures opens it.
func (b *Breaker) Fail() {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.halfOpen {
		b.halfOpen = false
		b.openUntil = b.now().Add(b.cooldown)
		return
	}
	b.failures++
	if b.failures >= b.threshold {
		b.openUntil = b.now().Add(b.cooldown)
	}
}
