//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/session/cookie"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

func TestWithDomain_Issue(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("sso@test.com", "SSO", "")
	if err != nil {
		t.Fatal(err)
	}

	t.Run("with Domain", func(t *testing.T) {
		strategy, err := cookie.New(m, cookie.Options{
			Name:   "session",
			Domain: ".velty.cl",
			Policy: testPolicy,
		})
		if err != nil {
			t.Fatal(err)
		}

		ctx := &mock.Context{}
		if err := strategy.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}
		c, ok := ctx.Cookie("session")
		if !ok {
			t.Fatal("Issue did not set the unprefixed session cookie")
		}
		if c.Domain != ".velty.cl" {
			t.Errorf("Domain: got %q, want %q", c.Domain, ".velty.cl")
		}
	})

	t.Run("without Domain", func(t *testing.T) {
		strategy, err := cookie.New(m, cookie.Options{
			Name:   "session",
			Policy: testPolicy,
		})
		if err != nil {
			t.Fatal(err)
		}

		ctx := &mock.Context{}
		if err := strategy.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}
		c, ok := ctx.Cookie("__Host-session")
		if !ok {
			t.Fatal("Issue did not set the __Host-session cookie")
		}
		if c.Domain != "" {
			t.Errorf("Domain: got %q, want empty", c.Domain)
		}
	})
}

func TestWithDomain_Revoke(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := cookie.New(m, cookie.Options{
		Name:   "session",
		Domain: ".velty.cl",
		Policy: testPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	if err := strategy.Revoke(ctx); err != nil {
		t.Fatal(err)
	}
	c, ok := ctx.Cookie("session")
	if !ok {
		t.Fatal("Revoke did not set the deletion cookie")
	}
	if c.Domain != ".velty.cl" {
		t.Errorf("Domain: got %q, want %q", c.Domain, ".velty.cl")
	}
	if c.MaxAge != -1 {
		t.Errorf("MaxAge: got %d, want -1 (delete)", c.MaxAge)
	}
}

func TestWithDomain_SameSiteStays(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("samesite@test.com", "SameSite", "")
	if err != nil {
		t.Fatal(err)
	}

	strategy, err := cookie.New(m, cookie.Options{
		Name:   "session",
		Domain: ".velty.cl",
		Policy: testPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := &mock.Context{}
	if err := strategy.Issue(ctx, u.Id); err != nil {
		t.Fatal(err)
	}
	c, _ := ctx.Cookie("session")
	if c.SameSite != router.SameSiteStrict {
		t.Errorf("SameSite: got %v, want Strict", c.SameSite)
	}
}
