//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/crud"
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
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

func TestUsers_ListAcceptsReadArgs(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	m.CreateUser("user1@test.com", "Alice", "")
	m.CreateUser("user2@test.com", "Bob", "")
	m.CreateUser("user3@test.com", "Charlie", "")

	caller := crud.LoopbackActingAs(nil, "admin-1", m)
	read := func(args *crud.ReadArgs) authority.UserList {
		t.Helper()
		var list authority.UserList
		var callErr error
		caller.Call(router.Operation{Module: authority.ModelName, Entity: "user", Action: model.Read}, args, &list, func(err error) { callErr = err })
		if callErr != nil {
			t.Fatalf("user.read: %v", callErr)
		}
		return list
	}

	// 1. Limit
	list := read(&crud.ReadArgs{Limit: 2})
	if len(list) != 2 {
		t.Fatalf("expected 2 users with Limit=2, got %d", len(list))
	}

	// 2. Search
	found := read(&crud.ReadArgs{Search: "Bob", Limit: 10})
	if len(found) != 1 || found[0].Name != "Bob" {
		t.Fatalf("search failed, got %+v", found)
	}

	// 3. After
	for _, u := range read(&crud.ReadArgs{After: list[0].Id, Limit: 10}) {
		if u.Id <= list[0].Id {
			t.Fatalf("after failed, found id %s <= %s", u.Id, list[0].Id)
		}
	}
}
