//go:build !wasm

package tests

import (
	"testing"
	"time"

	"webtyp.com/auth"
)

const limiterTestIP = "10.0.0.1"

func TestIPLimiter_BlocksAfterMaxAttempts(t *testing.T) {
	l := auth.NewIPLimiter(3, 60, 60)

	for i := 0; i < 2; i++ {
		l.Fail(limiterTestIP)
		if err := l.Check(limiterTestIP); err != nil {
			t.Fatalf("attempt %d: unexpected block: %v", i+1, err)
		}
	}
	l.Fail(limiterTestIP) // 3rd failure — crosses maxAttempts

	if err := l.Check(limiterTestIP); err != auth.ErrTooManyAttempts {
		t.Fatalf("Check after 3 failures = %v, want ErrTooManyAttempts", err)
	}
}

func TestIPLimiter_BlockExpires(t *testing.T) {
	l := auth.NewIPLimiter(1, 60, 1) // 1 failure blocks for 1 second

	l.Fail(limiterTestIP)
	if err := l.Check(limiterTestIP); err == nil {
		t.Fatal("expected the IP to be blocked immediately after crossing maxAttempts")
	}

	time.Sleep(1100 * time.Millisecond)

	if err := l.Check(limiterTestIP); err != nil {
		t.Fatalf("expected the block to have expired, got: %v", err)
	}
}

func TestIPLimiter_ResetClearsHistory(t *testing.T) {
	l := auth.NewIPLimiter(2, 60, 60)

	l.Fail(limiterTestIP)
	l.Reset(limiterTestIP) // a success wipes the slate — 2 fresh attempts needed

	l.Fail(limiterTestIP)
	if err := l.Check(limiterTestIP); err != nil {
		t.Fatalf("one failure after Reset must not block, got: %v", err)
	}
}

func TestIPLimiter_WindowDiscardsOldFailures(t *testing.T) {
	l := auth.NewIPLimiter(2, 1, 60) // window = 1s

	l.Fail(limiterTestIP)
	// The window check truncates to whole seconds, so sleeping just past 1s
	// risks landing exactly on the boundary; 2.1s guarantees at least a
	// 2-second gap regardless of where in its own second Fail() landed.
	time.Sleep(2100 * time.Millisecond) // the first failure ages out of the window

	l.Fail(limiterTestIP) // starts a fresh window — only 1 failure in it
	if err := l.Check(limiterTestIP); err != nil {
		t.Fatalf("a failure outside the previous window must not count toward the block, got: %v", err)
	}
}
