//go:build !wasm && !dev

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

func TestDevAutologin_OffWithoutDevTag(t *testing.T) {
	db := newTestDB(t)
	mInit, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	u, err := mInit.CreateUser("dev-off@test.com", "Dev Off User", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := mInit.RegisterLAN(u.Id, lanRUT); err != nil {
		t.Fatal(err)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{u.Id: lanTrustedIP}}
	t.Setenv(auth.EnvDevAutologin, `{"code":"`+lanRUT+`"}`)

	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: pub})
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
		t.Errorf("expected anonymous request without -tags dev, got userID=%q", capturedUserID)
	}
	if len(pub.SecurityEvents()) != 0 {
		t.Errorf("expected 0 security events without -tags dev, got %d", len(pub.SecurityEvents()))
	}
}
