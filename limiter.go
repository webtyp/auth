package auth

import (
	"sync"

	"webtyp.com/fmt"
	"webtyp.com/time"
)

// RateLimiter is what a mode asks before spending work on a login attempt,
// and tells when an attempt failed. IPLimiter is the built-in in-process
// implementation; a consumer with its own policy (a shared cache, a
// database-backed counter) can satisfy this instead.
type RateLimiter interface {
	Check(ip string) error // non-nil → the attempt is refused before any work
	Fail(ip string)        // record a failed attempt
	Reset(ip string)       // a success clears the IP's history
}

// ErrTooManyAttempts is deliberately generic: it must never reveal whether
// the block is per-IP, per-account, or the credential's own format was
// wrong — the same body every other login failure already returns.
var ErrTooManyAttempts = fmt.Err("too", "many", "attempts")

type ipRecord struct {
	fails        int
	windowFrom   int64 // unix seconds, start of the current failure window
	blockedUntil int64 // unix seconds; 0 = not blocked
}

// IPLimiter blocks an IP for blockSeconds once it accumulates maxAttempts
// failures within windowSeconds. Counters live only in this process —
// a restart clears them (see the consumer's docs/PLAN.md for that tradeoff).
type IPLimiter struct {
	mu            sync.Mutex
	records       map[string]*ipRecord
	maxAttempts   int
	windowSeconds int64
	blockSeconds  int64
}

// NewIPLimiter builds an IPLimiter. maxAttempts must be > 0.
func NewIPLimiter(maxAttempts int, windowSeconds, blockSeconds int64) *IPLimiter {
	return &IPLimiter{
		records:       make(map[string]*ipRecord),
		maxAttempts:   maxAttempts,
		windowSeconds: windowSeconds,
		blockSeconds:  blockSeconds,
	}
}

// Check returns ErrTooManyAttempts while ip is inside an active block.
func (l *IPLimiter) Check(ip string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	rec, ok := l.records[ip]
	if !ok {
		return nil
	}
	now := time.Now() / 1e9
	if rec.blockedUntil != 0 && now < rec.blockedUntil {
		return ErrTooManyAttempts
	}
	return nil
}

// Fail records one failed attempt for ip, starting a new window when the
// previous one has aged out, and blocks ip once maxAttempts is reached.
func (l *IPLimiter) Fail(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now() / 1e9
	rec, ok := l.records[ip]
	if !ok || now-rec.windowFrom > l.windowSeconds {
		rec = &ipRecord{windowFrom: now}
		l.records[ip] = rec
	}
	rec.fails++
	if rec.fails >= l.maxAttempts {
		rec.blockedUntil = now + l.blockSeconds
	}
}

// Reset clears ip's history — call on a successful login.
func (l *IPLimiter) Reset(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.records, ip)
}

var _ RateLimiter = (*IPLimiter)(nil)
