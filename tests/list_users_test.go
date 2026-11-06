//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/ddl"
	"webtyp.com/json"
	"webtyp.com/orm"
	"webtyp.com/router/mock"
	"webtyp.com/sqlite"
	"webtyp.com/view"
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

func TestUsers_ListAcceptsListArgs(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})

	reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
	m.MountOperations(reg)

	route, ok := reg.ops[auth.OpListUsers]
	if !ok || route == nil {
		t.Fatalf("op %s not mounted", auth.OpListUsers)
	}
	if _, ok := route.acceptedArg.(*view.ListArgs); !ok {
		t.Fatalf("expected acceptedArg to be *view.ListArgs, got %T", route.acceptedArg)
	}

	m.CreateUser("user1@test.com", "Alice", "")
	m.CreateUser("user2@test.com", "Bob", "")
	m.CreateUser("user3@test.com", "Charlie", "")

	// 1. Limit
	ctx := &mock.Context{}
	args := view.ListArgs{Limit: 2}
	var body string
	json.Encode(&args, &body)
	ctx.InBody = []byte(body)
	route.handler(ctx)
	if ctx.Status != 0 && ctx.Status != 200 {
		t.Fatalf("handler failed: %d", ctx.Status)
	}
	var list auth.UserList
	if err := json.Decode(ctx.ResponseBody(), &list); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 users with Limit=2, got %d", len(list))
	}

	// 2. Search
	ctx = &mock.Context{}
	args = view.ListArgs{Search: "Bob", Limit: 10}
	json.Encode(&args, &body)
	ctx.InBody = []byte(body)
	route.handler(ctx)
	var searchList auth.UserList
	json.Decode(ctx.ResponseBody(), &searchList)
	if len(searchList) != 1 || searchList[0].Name != "Bob" {
		t.Fatalf("search failed, got %+v", searchList)
	}

	// 3. After
	ctx = &mock.Context{}
	args = view.ListArgs{After: list[0].Id, Limit: 10}
	json.Encode(&args, &body)
	ctx.InBody = []byte(body)
	route.handler(ctx)
	var afterList auth.UserList
	json.Decode(ctx.ResponseBody(), &afterList)
	for _, u := range afterList {
		if u.Id <= list[0].Id {
			t.Fatalf("after failed, found id %s <= %s", u.Id, list[0].Id)
		}
	}
}

