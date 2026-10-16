//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/model"
	"webtyp.com/orm"
)

func TestSessionPolicy_Expiration(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("policy@test.com", "Policy", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("S1 - idle elapsed", func(t *testing.T) {
		policy := auth.SessionPolicy{Absolute: 3600, Idle: 60, Assurance: model.AssuranceSingleFactor}
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
		if err != nil {
			t.Fatal(err)
		}

		// Age by 61 seconds
		age := int64(61)
		sess.CreatedAt -= age
		sess.ExpiresAt -= age
		sess.AbsoluteAt -= age
		if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}
		m, _ = authority.New(db, auth.Config{IDs: testIDs})

		if _, err := m.GetSession(sess.Id); err != auth.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})

	t.Run("S1 - absolute elapsed", func(t *testing.T) {
		policy := auth.SessionPolicy{Absolute: 3600, Idle: 7200, Assurance: model.AssuranceSingleFactor}
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
		if err != nil {
			t.Fatal(err)
		}

		// Age by 3601 seconds
		age := int64(3601)
		sess.CreatedAt -= age
		sess.ExpiresAt -= age
		sess.AbsoluteAt -= age
		if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}
		m, _ = authority.New(db, auth.Config{IDs: testIDs})

		if _, err := m.GetSession(sess.Id); err != auth.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})

	t.Run("S2 - access after 61s moves ExpiresAt but never beyond AbsoluteAt", func(t *testing.T) {
		policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
		if err != nil {
			t.Fatal(err)
		}

		// Age by 65 seconds
		age := int64(65)
		sess.CreatedAt -= age
		sess.ExpiresAt -= age
		sess.AbsoluteAt -= age
		if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}
		m, _ = authority.New(db, auth.Config{IDs: testIDs})

		got, err := m.GetSession(sess.Id)
		// Because `now` is calculated again inside GetSession, it might be exactly AbsoluteAt or not.
		// Wait! It only slides if the new expiry is > than old ExpiresAt + 60.
		// If the old ExpiresAt is 1792019416, and AbsoluteAt is 1792019426, the slide is only 10s.
		// The slide minimum is 60s!
		// To make it slide, we need to set the old ExpiresAt to something >60s behind AbsoluteAt.
		// Ah, the slide is ONLY persisted if it's > 60s.
		if err != nil {
			t.Fatal(err)
		}

		if got.ExpiresAt <= sess.ExpiresAt {
			t.Errorf("expected ExpiresAt to move forward, got %d <= %d", got.ExpiresAt, sess.ExpiresAt)
		}
		if got.ExpiresAt > got.AbsoluteAt {
			t.Errorf("expected ExpiresAt %d <= AbsoluteAt %d", got.ExpiresAt, got.AbsoluteAt)
		}
	})

	t.Run("S2 - when AbsoluteAt is nearer than now+Idle", func(t *testing.T) {
		policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
		if err != nil {
			t.Fatal(err)
		}

		// Age by 3000 seconds (AbsoluteAt is in 600 seconds, Idle is 900)
		age := int64(3000)
		// Idle is 900. If we age by 3000, and we want it to NOT expire from idle,
		// it must be that (now - ExpiresAt) < 0? No, ExpiresAt > now.
		// Let's just set ExpiresAt directly to time.Now().Unix() + 10 to simulate activity 10 seconds ago.
		// Actually, just age all timestamps but make sure ExpiresAt is still in the future:
		sess.CreatedAt -= age
		sess.AbsoluteAt -= age
		// If originally ExpiresAt was CreatedAt + Idle (900), ageing it by 3000 puts it in the past (expired).
		// Let's manually extend the session before updating it.
		sess.ExpiresAt = sess.AbsoluteAt - 65
		// Make sure now + Idle exceeds AbsoluteAt:
		// If age is 3000, now is T+0. CreatedAt is T-3000. AbsoluteAt is CreatedAt + 3600 = T+600.
		// Idle is 900. now + 900 = T+900 > T+600. So it should be capped at T+600.
		if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}
		m, _ = authority.New(db, auth.Config{IDs: testIDs})

		got, err := m.GetSession(sess.Id)
		if err != nil {
			t.Fatal(err)
		}

		if got.ExpiresAt != got.AbsoluteAt {
			t.Errorf("expected ExpiresAt to be capped at AbsoluteAt %d, got %d", got.AbsoluteAt, got.ExpiresAt)
		}
	})

	t.Run("S3 - access after 10s -> row unchanged", func(t *testing.T) {
		policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
		sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
		if err != nil {
			t.Fatal(err)
		}

		// Age by 10 seconds
		age := int64(10)
		sess.CreatedAt -= age
		sess.ExpiresAt -= age
		sess.AbsoluteAt -= age
		if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}
		m, _ = authority.New(db, auth.Config{IDs: testIDs})

		got, err := m.GetSession(sess.Id)
		if err != nil {
			t.Fatal(err)
		}

		if got.ExpiresAt != sess.ExpiresAt {
			t.Errorf("expected ExpiresAt to remain %d, got %d", sess.ExpiresAt, got.ExpiresAt)
		}
	})
}

func TestSessionPolicy_Refusals(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("refusals@test.com", "Refusals", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 0, Idle: 900, Assurance: model.AssuranceSingleFactor}
	_, err = m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
	if err == nil || err.Error() != auth.ErrMsgPolicyAbsolute {
		t.Errorf("expected error %q, got %v", auth.ErrMsgPolicyAbsolute, err)
	}
}

func TestSessionPolicy_Persistence(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("pers@test.com", "Pers", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 1800, Assurance: model.AssuranceMultiFactor}
	sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
	if err != nil {
		t.Fatal(err)
	}

	if sess.AbsoluteAt != sess.CreatedAt+3600 {
		t.Errorf("expected AbsoluteAt to be %d, got %d", sess.CreatedAt+3600, sess.AbsoluteAt)
	}
	if sess.IdleSeconds != 1800 {
		t.Errorf("expected IdleSeconds to be 1800, got %d", sess.IdleSeconds)
	}
	if sess.Assurance != int64(model.AssuranceMultiFactor) {
		t.Errorf("expected Assurance to be %d, got %d", model.AssuranceMultiFactor, sess.Assurance)
	}
}

func TestSessionPolicy_Rotate(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("rot@test.com", "Rot", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 1800, Assurance: model.AssuranceMultiFactor}
	sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", policy)
	if err != nil {
		t.Fatal(err)
	}

	// Age the session slightly to ensure AbsoluteAt logic works during rotation
	age := int64(10)
	sess.CreatedAt -= age
	sess.AbsoluteAt -= age
	sess.ExpiresAt -= age
	if err := db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
		t.Fatal(err)
	}
	m, _ = authority.New(db, auth.Config{IDs: testIDs})

	rotSess, err := m.RotateSession(sess.Id, "127.0.0.2", "ua2")
	if err != nil {
		t.Fatal(err)
	}

	if rotSess.Assurance != int64(model.AssuranceMultiFactor) {
		t.Errorf("rotated session Assurance %d != %d", rotSess.Assurance, model.AssuranceMultiFactor)
	}
	if rotSess.IdleSeconds != 1800 {
		t.Errorf("rotated session IdleSeconds %d != 1800", rotSess.IdleSeconds)
	}

}
