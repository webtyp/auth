//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
)

// TestEmaillessUsers covers LAN staff, who have no email: the column is
// unique, so two users created without one must not collide.
//
// Unblocked by the NULLABLE_COLUMNS wave: orm.Create omits the empty email
// from the INSERT so the database stores NULL (phase D), and NULL scans as
// the Go zero value on every backend (phases A/B/C). No schema migration was
// needed: the column was already nullable (no NotNull).
func TestEmaillessUsers(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	first, err := m.CreateUser("", "Staff One", "")
	if err != nil {
		t.Fatalf("first email-less user rejected: %v", err)
	}
	second, err := m.CreateUser("", "Staff Two", "")
	if err != nil {
		t.Fatalf("second email-less user rejected: %v", err)
	}
	if first.Id == second.Id {
		t.Fatal("both email-less users share an id")
	}

	for _, u := range []auth.User{first, second} {
		stored, err := m.GetUser(u.Id)
		if err != nil {
			t.Fatalf("email-less user %s unreadable: %v", u.Id, err)
		}
		if stored.Email != "" {
			t.Errorf("user %s stored email %q, want empty", u.Id, stored.Email)
		}
		if stored.Status != "active" {
			t.Errorf("user %s status = %q, want active", u.Id, stored.Status)
		}
	}
}

// TestEmailUniquenessStillHolds: relaxing the empty case must not relax the
// real one.
func TestEmailUniquenessStillHolds(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.CreateUser("taken@test.com", "First", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateUser("taken@test.com", "Second", ""); err != auth.ErrEmailTaken {
		t.Errorf("duplicate email error = %v, want ErrEmailTaken", err)
	}
}

// TestUserByEmailNeverMatchesEmpty: an empty lookup must not hand back an
// arbitrary LAN user, which is what an "" = "" match would do.
func TestUserByEmailNeverMatchesEmpty(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateUser("", "Staff One", ""); err != nil {
		t.Fatal(err)
	}

	if _, err := m.UserByEmail(""); err != auth.ErrNotFound {
		t.Errorf("UserByEmail(\"\") = %v, want ErrNotFound", err)
	}
}
