//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	emailpassword "webtyp.com/auth/email_password"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/router/mock"
)

func TestSQLBoundary(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})

	userCRUD := getHandler(m, "users")
	resU, _ := userCRUD.Create(auth.User{Email: "sql@example.com", Name: "SQL Test"})
	u := resU.(auth.User)
	_ = emailpassword.SetPassword(m, u.Id, "password123", nil)

	t.Run("Login Injection", func(t *testing.T) {
		ep := emailpassword.New(m, m, m.Ports().Report)
		if _, err := ep.Login(&mock.Context{}, []byte(`{"email":"' OR 1=1 --","password":"password123"}`)); err == nil {
			t.Errorf("an injected e-mail must be refused")
		}
	})

	t.Run("SetPassword Injection", func(t *testing.T) {
		err := emailpassword.SetPassword(m, "'; DROP TABLE users; --", "password123", nil)
		// The error from getting identity or updating should not be nil.
		// It will return ErrNotFound or some identity creation error, but NOT crash or drop tables.
		if err == nil {
			t.Errorf("expected error for injected user ID")
		}

		// Ensure table still exists
		_, err = m.GetUser(u.Id)
		if err != nil {
			t.Errorf("expected table to still exist, got %v", err)
		}
	})

	t.Run("RegisterLAN Injection", func(t *testing.T) {
		err := trustedip.RegisterRUT(m, u.Id, "12345678-5'; --")
		if !auth.IsInvalidRUT(err) {
			t.Errorf("expected ErrInvalidRUT, got %v", err)
		}
	})

	t.Run("GetUser Injection", func(t *testing.T) {
		_, err := m.GetUser("1 UNION SELECT * FROM user_identities")
		if !auth.IsNotFound(err) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})
}
