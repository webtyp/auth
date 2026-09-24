//go:build !wasm

package tests

import (
	"sync/atomic"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	emailpassword "webtyp.com/auth/email_password"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

type countingFormLogin struct {
	calls atomic.Int32
}

func (c *countingFormLogin) Name() string { return "counting" }
func (c *countingFormLogin) Mount(r router.Router) {}
func (c *countingFormLogin) Login(ctx router.Context, body []byte) (string, error) {
	c.calls.Add(1)
	return "", auth.ErrInvalidCredentials
}

func TestDevAutologin_Cases(t *testing.T) {
	db := newTestDB(t)

	// Setup user & trusted IP
	mInit, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := mInit.CreateUser("dev-auto@test.com", "Dev Auto User", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := mInit.RegisterLAN(u.Id, lanRUT); err != nil {
		t.Fatal(err)
	}
	if err := mInit.SetPassword(u.Id, "secret1234"); err != nil {
		t.Fatal(err)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{u.Id: lanTrustedIP}}

	t.Run("Case1_OpensSession", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

		pub1 := &mockPublisher{}
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub1})
		if err != nil {
			t.Fatal(err)
		}
		m.Enable(trustedip.New(m, trusted, m, m, false))

		var capturedUserID string
		handler := m.Authenticate()(func(ctx router.Context) {
			capturedUserID = ctx.UserID()
		})

		reqCtx := &mock.Context{}
		reqCtx.SetValue("RemoteAddr", lanTrustedIP+":54321")
		handler(reqCtx)

		if capturedUserID != u.Id {
			t.Errorf("capturedUserID = %q, want %q", capturedUserID, u.Id)
		}

		c, ok := reqCtx.Cookie("dev_session")
		if !ok || c.Value == "" {
			t.Errorf("expected session cookie to be set on context response")
		}

		assertSecurityEvent(t, pub1, 0, auth.EventDevAutologin)
	})

	t.Run("Case2_SessionIsRealAcrossAuthorityInstances", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

		pub1 := &mockPublisher{}
		m1, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub1})
		if err != nil {
			t.Fatal(err)
		}
		m1.Enable(trustedip.New(m1, trusted, m1, m1, false))

		reqCtx1 := &mock.Context{}
		reqCtx1.SetValue("RemoteAddr", lanTrustedIP+":54321")
		m1.Authenticate()(func(ctx router.Context) {})(reqCtx1)

		c, ok := reqCtx1.Cookie("dev_session")
		if !ok || c.Value == "" {
			t.Fatalf("no cookie issued in instance 1")
		}

		// Instance 2: DEV_AUTOLOGIN is empty
		t.Setenv(auth.EnvDevAutologin, "")
		pub2 := &mockPublisher{}
		m2, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub2})
		if err != nil {
			t.Fatal(err)
		}
		m2.Enable(trustedip.New(m2, trusted, m2, m2, false))

		var capturedUserID string
		handler2 := m2.Authenticate()(func(ctx router.Context) {
			capturedUserID = ctx.UserID()
		})

		reqCtx2 := &mock.Context{}
		reqCtx2.SetCookie(router.Cookie{Name: "dev_session", Value: c.Value})
		reqCtx2.SetValue("RemoteAddr", lanTrustedIP+":54321")
		handler2(reqCtx2)

		if capturedUserID != u.Id {
			t.Errorf("instance 2 identified userID = %q, want %q", capturedUserID, u.Id)
		}
	})

	t.Run("Case3_MismatchedIPFailsAndFiresSecurityEvent", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

		pub3 := &mockPublisher{}
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub3})
		if err != nil {
			t.Fatal(err)
		}
		m.Enable(trustedip.New(m, trusted, m, m, false))

		var capturedUserID string
		handler := m.Authenticate()(func(ctx router.Context) {
			capturedUserID = ctx.UserID()
		})

		reqCtx := &mock.Context{}
		reqCtx.SetValue("RemoteAddr", "10.0.0.7:54321")
		handler(reqCtx)

		if capturedUserID != "" {
			t.Errorf("capturedUserID = %q, want empty for untrusted IP", capturedUserID)
		}

		assertSecurityEvent(t, pub3, 0, auth.EventIPMismatch)
	})

	t.Run("Case4_DoesNotRetryAfterFullRejection", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

		pub4 := &mockPublisher{}
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub4})
		if err != nil {
			t.Fatal(err)
		}

		counter := &countingFormLogin{}
		m.Enable(trustedip.New(m, trusted, m, m, false), counter)

		handler := m.Authenticate()(func(ctx router.Context) {})

		// First request from bad IP -> rejects autologin and sets devLoginFailed latch
		reqCtx1 := &mock.Context{}
		reqCtx1.SetValue("RemoteAddr", "10.0.0.7:54321")
		handler(reqCtx1)

		callsAfterFirst := counter.calls.Load()

		// Next two requests
		reqCtx2 := &mock.Context{}
		reqCtx2.SetValue("RemoteAddr", "10.0.0.7:54321")
		handler(reqCtx2)

		reqCtx3 := &mock.Context{}
		reqCtx3.SetValue("RemoteAddr", "10.0.0.7:54321")
		handler(reqCtx3)

		if got := counter.calls.Load(); got != callsAfterFirst {
			t.Errorf("counter calls increased from %d to %d, expected latch to prevent subsequent calls", callsAfterFirst, got)
		}
	})

	t.Run("Case5_WithoutEnvVar_StandardBehavior", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, "")

		pub5 := &mockPublisher{}
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub5})
		if err != nil {
			t.Fatal(err)
		}
		m.Enable(trustedip.New(m, trusted, m, m, false))

		var capturedUserID string
		handler := m.Authenticate()(func(ctx router.Context) {
			capturedUserID = ctx.UserID()
		})

		reqCtx := &mock.Context{}
		reqCtx.SetValue("RemoteAddr", lanTrustedIP+":54321")
		handler(reqCtx)

		if capturedUserID != "" {
			t.Errorf("capturedUserID = %q, want empty", capturedUserID)
		}
		if len(pub5.SecurityEvents()) != 0 {
			t.Errorf("expected 0 security events, got %d", len(pub5.SecurityEvents()))
		}
	})

	t.Run("Case6_OrderOfEnable", func(t *testing.T) {
		t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

		pub6 := &mockPublisher{}
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub6})
		if err != nil {
			t.Fatal(err)
		}
		epMode := emailpassword.New(m, m, m)
		tipMode := trustedip.New(m, trusted, m, m, false)
		m.Enable(epMode, tipMode)

		var capturedUserID string
		handler := m.Authenticate()(func(ctx router.Context) {
			capturedUserID = ctx.UserID()
		})

		reqCtx := &mock.Context{}
		reqCtx.SetValue("RemoteAddr", lanTrustedIP+":54321")
		handler(reqCtx)

		if capturedUserID != u.Id {
			t.Errorf("capturedUserID = %q, want %q", capturedUserID, u.Id)
		}
	})
}
