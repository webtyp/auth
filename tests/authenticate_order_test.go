//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/session/cookie"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

type fakeRequestIdentifier struct {
	handled   bool
	principal auth.Principal
}

func (f *fakeRequestIdentifier) IdentifyRequest(ctx router.Context) (auth.Principal, bool) {
	return f.principal, f.handled
}

func (f *fakeRequestIdentifier) Name() string {
	return "fake"
}

func (f *fakeRequestIdentifier) Mount(router.Router) {}

func TestAuthenticate_Order_A1_A2(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("order1@test.com", "Order1", "")
	if err != nil {
		t.Fatal(err)
	}

	// Setup main strategy
	mainPolicy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
	mainStrat, err := cookie.New(m, cookie.Options{Name: "session", Domain: "", Policy: mainPolicy})
	if err != nil {
		t.Fatal(err)
	}
	m.SetStrategy(mainStrat)

	// Setup step-up strategy
	stepUpPolicy := auth.SessionPolicy{Absolute: 900, Idle: 300, Assurance: model.AssuranceMultiFactor}
	stepUpStrat, err := cookie.New(m, cookie.Options{Name: "stepup", Domain: "", Policy: stepUpPolicy})
	if err != nil {
		t.Fatal(err)
	}
	m.SetStepUpStrategy(stepUpStrat)

	t.Run("A1 - fake RequestIdentifier wins", func(t *testing.T) {
		fake := &fakeRequestIdentifier{handled: true, principal: auth.Principal{}}
		m.Enable(fake)
		defer func() {
			// Clear it out for subsequent tests. Wait, there's no remove.
			// Let's create a new module or just be careful. We can just test A1 here.
		}()

		ctx := &mock.Context{}
		// Give it a valid main cookie
		if err := mainStrat.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}

		var authID string
		handler := m.Authenticate()(func(c router.Context) {
			authID = c.UserID()
		})
		handler(ctx)

		if authID != "" {
			t.Errorf("expected anonymous request because fake handled it, got %s", authID)
		}
	})

	t.Run("A2 - step-up cookie + main cookie -> MultiFactor", func(t *testing.T) {
		// New module to avoid the fake RequestIdentifier from A1
		m2, _ := authority.New(db, auth.Config{IDs: testIDs})
		m2.SetStrategy(mainStrat)
		m2.SetStepUpStrategy(stepUpStrat)

		ctx := &mock.Context{}
		if err := mainStrat.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}

		// The Issue method of cookie.Strategy doesn't have an alternative IssueStepUpSession, it's on Module.
		// Wait, IssueStepUpSession needs a router.Context.
		ctxIssueStep := &mock.Context{}
		if err := m2.IssueStepUpSession(ctxIssueStep, u.Id); err != nil {
			t.Fatal(err)
		}

		// Merge cookies
		cMain, _ := ctx.Cookie("__Host-session")
		cStep, _ := ctxIssueStep.Cookie("__Host-stepup")

		ctxReq := &mock.Context{}
		ctxReq.SetCookie(cMain)
		ctxReq.SetCookie(cStep)

		var authID string
		var authAssurance model.Assurance
		handler := m2.Authenticate()(func(c router.Context) {
			authID = c.UserID()
			authAssurance = c.Assurance()
		})
		handler(ctxReq)

		if authID != u.Id {
			t.Errorf("expected %s, got %s", u.Id, authID)
		}
		if authAssurance != model.AssuranceMultiFactor {
			t.Errorf("expected %d, got %d", model.AssuranceMultiFactor, authAssurance)
		}
	})
}

func TestAuthenticate_Order_A3_A5(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("order2@test.com", "Order2", "")
	if err != nil {
		t.Fatal(err)
	}

	mainPolicy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
	mainStrat, err := cookie.New(m, cookie.Options{Name: "session", Domain: "", Policy: mainPolicy})
	if err != nil {
		t.Fatal(err)
	}
	m.SetStrategy(mainStrat)

	t.Run("A3 - main cookie only -> SingleFactor", func(t *testing.T) {
		ctx := &mock.Context{}
		if err := mainStrat.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}

		var authID string
		var authAssurance model.Assurance
		handler := m.Authenticate()(func(c router.Context) {
			authID = c.UserID()
			authAssurance = c.Assurance()
		})
		handler(ctx)

		if authID != u.Id {
			t.Errorf("expected %s, got %s", u.Id, authID)
		}
		if authAssurance != model.AssuranceSingleFactor {
			t.Errorf("expected %d, got %d", model.AssuranceSingleFactor, authAssurance)
		}
	})

	t.Run("A5 - no credentials -> anonymous", func(t *testing.T) {
		ctx := &mock.Context{}

		var authID string
		var authAssurance model.Assurance
		handler := m.Authenticate()(func(c router.Context) {
			authID = c.UserID()
			authAssurance = c.Assurance()
		})
		handler(ctx)

		if authID != "" {
			t.Errorf("expected empty string, got %s", authID)
		}
		if authAssurance != model.AssuranceNone {
			t.Errorf("expected %d, got %d", model.AssuranceNone, authAssurance)
		}
	})

	t.Run("CurrentPrincipal without touching ctx", func(t *testing.T) {
		ctx := &mock.Context{}
		if err := mainStrat.Issue(ctx, u.Id); err != nil {
			t.Fatal(err)
		}

		principal, err := m.CurrentPrincipal(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if principal.UserID != u.Id {
			t.Errorf("expected %s, got %s", u.Id, principal.UserID)
		}
		if ctx.UserID() != "" {
			t.Errorf("CurrentPrincipal should not set UserID on context")
		}

		ctxEmpty := &mock.Context{}
		_, err = m.CurrentPrincipal(ctxEmpty)
		if err != auth.ErrSessionExpired {
			t.Errorf("expected ErrSessionExpired, got %v", err)
		}
	})
}


