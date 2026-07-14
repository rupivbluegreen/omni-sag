// Package ratelimit provides a per-key failed-attempt throttle used to defend
// the SSH auth path against password brute force.
//
// The limiter is a leaf: it imports nothing from the rest of omni-sag, so it can
// be wired into the data path (session password callback) without creating a
// dependency edge. It keys on the SSH source IP rather than the username on
// purpose — a username-keyed lockout would let an attacker lock a victim's
// account out from anywhere, whereas an IP-keyed lockout only ever slows the
// source doing the guessing (see TestIsolationBetweenKeys).
//
// Two properties keep the defense from becoming a denial-of-service itself:
//
//   - Every lockout is bounded by MaxBackoff, so no source is ever locked out
//     permanently — even under a sustained attack the lockout self-clears.
//   - The tracked-entry map is bounded by MaxEntries, so a flood of distinct
//     (possibly spoofed) source keys cannot exhaust memory; stale entries are
//     reclaimed first and active lockouts are preserved.
package ratelimit

import (
	"sync"
	"time"
)

// Config tunes the brute-force limiter. Zero/negative fields are replaced with
// the corresponding DefaultConfig value by New.
type Config struct {
	// MaxFailures is the number of failures within Window that trips a lockout.
	MaxFailures int
	// Window is the sliding interval over which failures accumulate. Failures
	// older than Window do not count toward a lockout.
	Window time.Duration
	// BaseBackoff is the lockout duration for the first lockout of a source.
	BaseBackoff time.Duration
	// MaxBackoff caps the lockout duration. Successive lockouts double the
	// backoff but never exceed this, guaranteeing lockouts are never permanent.
	MaxBackoff time.Duration
	// MaxEntries bounds the number of tracked sources so a distinct-key flood
	// cannot exhaust memory.
	MaxEntries int
}

// DefaultConfig returns production-sane defaults: 5 failures in 15 minutes trips
// a lockout starting at 30s and doubling up to 15 minutes, tracking up to 100k
// sources.
func DefaultConfig() Config {
	return Config{
		MaxFailures: 5,
		Window:      15 * time.Minute,
		BaseBackoff: 30 * time.Second,
		MaxBackoff:  15 * time.Minute,
		MaxEntries:  100_000,
	}
}

type entry struct {
	failures    int
	windowStart time.Time
	lockedUntil time.Time
	level       int // number of lockouts so far; drives exponential backoff
	lastSeen    time.Time
}

// Limiter throttles repeated auth failures per key. It is safe for concurrent
// use by multiple goroutines.
type Limiter struct {
	mu      sync.Mutex
	cfg     Config
	now     func() time.Time // swappable for tests
	entries map[string]*entry
}

// New builds a Limiter, filling any non-positive Config field from DefaultConfig
// and ensuring MaxBackoff >= BaseBackoff.
func New(cfg Config) *Limiter {
	d := DefaultConfig()
	if cfg.MaxFailures <= 0 {
		cfg.MaxFailures = d.MaxFailures
	}
	if cfg.Window <= 0 {
		cfg.Window = d.Window
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = d.BaseBackoff
	}
	if cfg.MaxBackoff < cfg.BaseBackoff {
		cfg.MaxBackoff = cfg.BaseBackoff
	}
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = d.MaxEntries
	}
	return &Limiter{
		cfg:     cfg,
		now:     time.Now,
		entries: make(map[string]*entry),
	}
}

// Allow reports whether an auth attempt from key may proceed. When the source is
// locked out it returns false and the remaining time until the lockout clears.
// An empty key fails open (the caller must supply a real source).
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if key == "" {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.entries[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	e.lastSeen = now
	if now.Before(e.lockedUntil) {
		return false, e.lockedUntil.Sub(now)
	}
	return true, 0
}

// RecordFailure registers a failed auth attempt for key. When the failure count
// within Window reaches MaxFailures the source is locked out for a backoff that
// doubles per successive lockout, capped at MaxBackoff. A failure that arrives
// while the source is already locked out does not extend the lockout.
func (l *Limiter) RecordFailure(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.entries[key]
	if e == nil {
		e = &entry{windowStart: now, lastSeen: now}
		if !l.insertLocked(key, e) {
			return // at capacity with all-active entries; skip tracking this key
		}
	}
	e.lastSeen = now

	// Hammering during an active lockout must not extend it.
	if now.Before(e.lockedUntil) {
		return
	}
	// Slide the window: stale failures age out.
	if now.Sub(e.windowStart) > l.cfg.Window {
		e.failures = 0
		e.windowStart = now
	}
	e.failures++
	if e.failures >= l.cfg.MaxFailures {
		e.level++
		e.lockedUntil = now.Add(l.backoffFor(e.level))
		e.failures = 0
		e.windowStart = now
	}
}

// RecordSuccess clears all failure and lockout state for key.
func (l *Limiter) RecordSuccess(key string) {
	if key == "" {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.entries, key)
}

// Len returns the number of tracked sources (for tests/metrics).
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}

// backoffFor returns BaseBackoff * 2^(level-1), capped at MaxBackoff. The
// doubling loop short-circuits once the cap is reached so it cannot overflow for
// large levels.
func (l *Limiter) backoffFor(level int) time.Duration {
	b := l.cfg.BaseBackoff
	for i := 1; i < level; i++ {
		b *= 2
		if b >= l.cfg.MaxBackoff {
			return l.cfg.MaxBackoff
		}
	}
	if b > l.cfg.MaxBackoff {
		return l.cfg.MaxBackoff
	}
	return b
}

// insertLocked adds e under key, keeping the map within MaxEntries. When full it
// first reclaims stale (idle, unlocked) entries; if none can be reclaimed —
// i.e. every tracked source is actively being throttled — it declines to track
// the new key rather than evict an active lockout. Caller holds l.mu.
func (l *Limiter) insertLocked(key string, e *entry) bool {
	if len(l.entries) >= l.cfg.MaxEntries {
		l.reclaimStaleLocked()
		if len(l.entries) >= l.cfg.MaxEntries {
			return false
		}
	}
	l.entries[key] = e
	return true
}

// reclaimStaleLocked deletes entries that are not locked out and whose last
// activity is older than Window. Active lockouts are always preserved so a
// distinct-key flood cannot dislodge a real one. Caller holds l.mu.
func (l *Limiter) reclaimStaleLocked() {
	now := l.now()
	for k, v := range l.entries {
		if now.Before(v.lockedUntil) {
			continue // keep active lockouts
		}
		if now.Sub(v.lastSeen) > l.cfg.Window {
			delete(l.entries, k)
		}
	}
}
