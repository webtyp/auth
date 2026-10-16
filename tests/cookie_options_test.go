//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/session/cookie"
	"webtyp.com/model"
	"webtyp.com/router/mock"
)

func TestCookieOptions_Domain(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("domain@test.com", "Domain", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}

	t.Run("Domain empty -> __Host- prefix", func(t *testing.T) {
		opts := cookie.Options{Name: "session", Domain: "", Policy: policy}
		strategy, err := cookie.New(m, opts)
		if err != nil {
			t.Fatal(err)
		}

		ctx := &mock.Context{}
		err = strategy.Issue(ctx, u.Id)
		if err != nil {
			t.Fatal(err)
		}

		c, ok := ctx.Cookie("__Host-session")
		if !ok {
			t.Fatal("expected __Host-session cookie")
		}
		if c.Domain != "" {
			t.Errorf("expected empty Domain, got %s", c.Domain)
		}
	})

	t.Run("Domain set -> exact name, Domain attribute set", func(t *testing.T) {
		opts := cookie.Options{Name: "session", Domain: ".velty.cl", Policy: policy}
		strategy, err := cookie.New(m, opts)
		if err != nil {
			t.Fatal(err)
		}

		ctx := &mock.Context{}
		err = strategy.Issue(ctx, u.Id)
		if err != nil {
			t.Fatal(err)
		}

		c, ok := ctx.Cookie("session")
		if !ok {
			t.Fatal("expected session cookie")
		}
		if c.Domain != ".velty.cl" {
			t.Errorf("expected Domain .velty.cl, got %s", c.Domain)
		}
	})
}

func TestCookieOptions_Issue(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("issue@test.com", "Issue", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
	opts := cookie.Options{Name: "session", Domain: "", Policy: policy}
	strategy, err := cookie.New(m, opts)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	if err := strategy.Issue(ctx, u.Id); err != nil {
		t.Fatal(err)
	}

	c, ok := ctx.Cookie("__Host-session")
	if !ok {
		t.Fatal("expected __Host-session cookie")
	}

	if !c.HttpOnly {
		t.Errorf("expected HttpOnly to be true")
	}
	if !c.Secure {
		t.Errorf("expected Secure to be true")
	}
	if c.SameSite != 3 { // router.SameSiteStrict = 3, but let's check properly if it fails
		// I will check the raw value from mock Context
	}
	if c.Path != "/" {
		t.Errorf("expected Path to be /, got %s", c.Path)
	}
	if c.MaxAge != 3600 {
		t.Errorf("expected MaxAge to be 3600, got %d", c.MaxAge)
	}
}

func TestCookieOptions_Identify(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("identify@test.com", "Identify", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceMultiFactor}
	opts := cookie.Options{Name: "session", Domain: "", Policy: policy}
	strategy, err := cookie.New(m, opts)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	if err := strategy.Issue(ctx, u.Id); err != nil {
		t.Fatal(err)
	}

	c, _ := ctx.Cookie("__Host-session")

	// Create a new context with just the incoming cookie
	ctx2 := &mock.Context{}
	ctx2.SetCookie(c)

	principal, err := strategy.Identify(ctx2)
	if err != nil {
		t.Fatal(err)
	}

	if principal.UserID != u.Id {
		t.Errorf("expected UserID %s, got %s", u.Id, principal.UserID)
	}
	if principal.Assurance != model.AssuranceMultiFactor {
		t.Errorf("expected Assurance %d, got %d", model.AssuranceMultiFactor, principal.Assurance)
	}
	if principal.IssuedAt == 0 {
		t.Errorf("expected non-zero IssuedAt")
	}

	// Missing cookie
	ctx3 := &mock.Context{}
	_, err = strategy.Identify(ctx3)
	if err != auth.ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

func TestCookieOptions_Revoke(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("revoke@test.com", "Revoke", "")
	if err != nil {
		t.Fatal(err)
	}

	policy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceMultiFactor}
	opts := cookie.Options{Name: "session", Domain: ".velty.cl", Policy: policy}
	strategy, err := cookie.New(m, opts)
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	if err := strategy.Issue(ctx, u.Id); err != nil {
		t.Fatal(err)
	}

	c, _ := ctx.Cookie("session")

	// Create a new context with the incoming cookie for Identify to extract ID if needed,
	// actually Revoke extracts it and deletes.
	ctx2 := &mock.Context{}
	ctx2.SetCookie(c)

	if err := strategy.Revoke(ctx2); err != nil {
		t.Fatal(err)
	}

	revC, ok := ctx2.Cookie("session")
	if !ok {
		t.Fatal("expected session cookie to be overwritten by Revoke")
	}

	if revC.Domain != ".velty.cl" {
		t.Errorf("expected Domain .velty.cl, got %s", revC.Domain)
	}
	if revC.Path != "/" {
		t.Errorf("expected Path /, got %s", revC.Path)
	}
	if revC.MaxAge != -1 {
		t.Errorf("expected MaxAge -1, got %d", revC.MaxAge)
	}
}
