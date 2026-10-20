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

func TestDefaultStrategyIssuesAnUnguessableCookie(t *testing.T) {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate: %v", err)
	}

	// authority.New without SetStrategy uses default cookie strategy
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatalf("failed to create authority: %v", err)
	}

	u, err := m.CreateUser("default_strat@example.com", "Default Strategy User", "")
	if err != nil {
		t.Fatalf("failed to create user: %v", err)
	}

	sess1, err := m.CreateSession(u.Id, "127.0.0.1", "agent", testPolicy)
	if err != nil {
		t.Fatalf("failed to create session 1: %v", err)
	}
	sess2, err := m.CreateSession(u.Id, "127.0.0.1", "agent", testPolicy)
	if err != nil {
		t.Fatalf("failed to create session 2: %v", err)
	}

	if isAllDigits(sess1.Id) || isAllDigits(sess2.Id) {
		t.Fatalf("session IDs should not be pure decimal timestamps: %q, %q", sess1.Id, sess2.Id)
	}

	if commonPrefixLen(sess1.Id, sess2.Id) >= 16 {
		t.Fatalf("session IDs share prefix >= 16: %q vs %q", sess1.Id, sess2.Id)
	}
}
