//go:build !wasm

package tests

import (
	"testing"
	"time"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
)

// TestSlidingSessionExtendsOnActivity covers the owner's requirement that N
// minutes without activity end the session: server-side that is a sliding
// idle TTL, so every authenticated read must push the expiry forward.
func TestSlidingSessionExtendsOnActivity(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, IdleTTL: 2})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("sliding@test.com", "Sliding", "")
	if err != nil {
		t.Fatal(err)
	}

	sess, err := m.CreateSession(u.Id, "192.168.1.5", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	// IdleTTL supersedes TokenTTL for the initial lifetime too, otherwise the
	// first window would silently be the 24h default.
	if sess.ExpiresAt-sess.CreatedAt != 2 {
		t.Fatalf("initial lifetime = %ds, want 2s from IdleTTL", sess.ExpiresAt-sess.CreatedAt)
	}

	time.Sleep(1100 * time.Millisecond)

	got, err := m.GetSession(sess.Id)
	if err != nil {
		t.Fatalf("session expired while still active: %v", err)
	}
	if got.ExpiresAt <= sess.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want > %d — activity must slide the expiry", got.ExpiresAt, sess.ExpiresAt)
	}

	// The slide must reach storage: the cache is per-isolate and a Worker
	// that evicts it would otherwise resurrect the old expiry.
	qb := db.Query(&auth.Session{}).Where(auth.Session_.Id).Eq(sess.Id)
	rows, err := auth.ReadAllSession(qb)
	if err != nil || len(rows) == 0 {
		t.Fatalf("session row unreadable: %v", err)
	}
	if rows[0].ExpiresAt != got.ExpiresAt {
		t.Errorf("stored ExpiresAt = %d, want %d — the slide never reached the row", rows[0].ExpiresAt, got.ExpiresAt)
	}
}

// TestFixedSessionNeverSlides is the closed-by-default half: IdleTTL 0 is
// today's behavior, byte for byte.
func TestFixedSessionNeverSlides(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("fixed@test.com", "Fixed", "")
	if err != nil {
		t.Fatal(err)
	}

	sess, err := m.CreateSession(u.Id, "192.168.1.5", "test-agent")
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(1100 * time.Millisecond)

	got, err := m.GetSession(sess.Id)
	if err != nil {
		t.Fatal(err)
	}
	if got.ExpiresAt != sess.ExpiresAt {
		t.Errorf("ExpiresAt moved from %d to %d with IdleTTL 0", sess.ExpiresAt, got.ExpiresAt)
	}
}
