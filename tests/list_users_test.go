//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/ddl"
	"webtyp.com/orm"
	"webtyp.com/sqlite"
)

func TestListUsers_Empty(t *testing.T) {
	m, _ := authority.New(newTestDB(t), auth.Config{IDs: testIDs})

	users, err := m.ListUsers()
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if len(users) != 0 {
		t.Errorf("expected len == 0, got %d", len(users))
	}
}

func TestListUsers_WithAndWithoutEmail(t *testing.T) {
	m, _ := authority.New(newTestDB(t), auth.Config{IDs: testIDs})

	a, _ := m.CreateUser("", "Staff One", "")
	b, _ := m.CreateUser("ana@example.com", "Ana", "")

	users, err := m.ListUsers()
	if err != nil {
		t.Errorf("expected err == nil, got %v", err)
	}
	if len(users) != 2 {
		t.Errorf("expected len == 2, got %d", len(users))
	}

	foundA := false
	foundB := false
	for _, u := range users {
		if u.Id == a.Id && u.Name == a.Name {
			foundA = true
		}
		if u.Id == b.Id && u.Name == b.Name {
			foundB = true
		}
	}

	if !foundA {
		t.Errorf("expected to find user A in the list")
	}
	if !foundB {
		t.Errorf("expected to find user B in the list")
	}
}

func TestListUsers_DatabaseClosed(t *testing.T) {
	conn, _ := sqlite.Open(":memory:")
	db := orm.New(conn)
	authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	conn.Close()

	users, err := m.ListUsers()
	if err == nil {
		t.Errorf("expected err != nil, got nil")
	}
	if users != nil {
		t.Errorf("expected returned slice to be nil, got %v", users)
	}
}
