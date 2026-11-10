// Package ratelimit provides keyed rate limiters and failure trackers.
package ratelimit

import (
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Limiter is a keyed token bucket limiter.
type Limiter struct {
	r     rate.Limit
	burst int

	mu      sync.Mutex
	entries map[string]*entry
	last    time.Time
}

type entry struct {
	l    *rate.Limiter
	seen time.Time
}

// New creates a limiter allowing perSecond events with the given burst.
func New(perSecond float64, burst int) *Limiter {
	return &Limiter{r: rate.Limit(perSecond), burst: burst, entries: map[string]*entry{}, last: time.Now()}
}

// Allow reports whether an event for key may happen now.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.last) > time.Minute {
		for k, e := range l.entries {
			if now.Sub(e.seen) > 10*time.Minute {
				delete(l.entries, k)
			}
		}
		l.last = now
	}
	e := l.entries[key]
	if e == nil {
		if len(l.entries) > 100000 {
			return false
		}
		e = &entry{l: rate.NewLimiter(l.r, l.burst)}
		l.entries[key] = e
	}
	e.seen = now
	return e.l.Allow()
}

// Failures tracks failed attempts per key within a window and blocks a key
// after max failures for the block duration.
type Failures struct {
	max    int
	window time.Duration
	block  time.Duration

	mu sync.Mutex
	m  map[string]*fail
}

type fail struct {
	count        int
	first        time.Time
	blockedUntil time.Time
}

// NewFailures creates a failure tracker.
func NewFailures(max int, window, block time.Duration) *Failures {
	return &Failures{max: max, window: window, block: block, m: map[string]*fail{}}
}

// Blocked reports whether key is currently blocked.
func (f *Failures) Blocked(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	e := f.m[key]
	return e != nil && time.Now().Before(e.blockedUntil)
}

// Fail records a failure for key.
func (f *Failures) Fail(key string) {
	now := time.Now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.m) > 100000 {
		for k, e := range f.m {
			if now.Sub(e.first) > f.window && now.After(e.blockedUntil) {
				delete(f.m, k)
			}
		}
	}
	e := f.m[key]
	if e == nil || now.Sub(e.first) > f.window {
		e = &fail{first: now}
		f.m[key] = e
	}
	e.count++
	if e.count >= f.max {
		e.blockedUntil = now.Add(f.block)
	}
}

// Reset clears the failures of key.
func (f *Failures) Reset(key string) {
	f.mu.Lock()
	delete(f.m, key)
	f.mu.Unlock()
}
