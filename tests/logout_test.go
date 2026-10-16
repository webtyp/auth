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

func TestLogout_RevokesBothSessions(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("logout@test.com", "Logout", "")
	if err != nil {
		t.Fatal(err)
	}

	mainPolicy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
	mainStrat, err := cookie.New(m, cookie.Options{Name: "session", Domain: "", Policy: mainPolicy})
	if err != nil {
		t.Fatal(err)
	}
	m.SetStrategy(mainStrat)

	stepUpPolicy := auth.SessionPolicy{Absolute: 900, Idle: 300, Assurance: model.AssuranceMultiFactor}
	stepUpStrat, err := cookie.New(m, cookie.Options{Name: "stepup", Domain: "", Policy: stepUpPolicy})
	if err != nil {
		t.Fatal(err)
	}
	m.SetStepUpStrategy(stepUpStrat)

	r := &mock.Router{}
	m.MountAPI(r)

	// Issue cookies
	ctxIssueMain := &mock.Context{}
	if err := mainStrat.Issue(ctxIssueMain, u.Id); err != nil {
		t.Fatal(err)
	}
	ctxIssueStep := &mock.Context{}
	if err := m.IssueStepUpSession(ctxIssueStep, u.Id); err != nil {
		t.Fatal(err)
	}

	cMain, _ := ctxIssueMain.Cookie("__Host-session")
	cStep, _ := ctxIssueStep.Cookie("__Host-stepup")

	// Verify both exist in DB
	if _, err := m.GetSession(cMain.Value); err != nil {
		t.Fatalf("main session missing: %v", err)
	}
	if _, err := m.GetSession(cStep.Value); err != nil {
		t.Fatalf("stepup session missing: %v", err)
	}

	// Request logout
	ctxReq := &mock.Context{
		InMethod: "POST",
		InPath:   auth.PathLogout,
	}
	ctxReq.SetCookie(cMain)
	ctxReq.SetCookie(cStep)

	r.Invoke("POST", auth.PathLogout, ctxReq)

	if ctxReq.Status != 302 {
		t.Fatalf("expected status 302, got %d", ctxReq.Status)
	}
	if ctxReq.GetHeader("Location") != auth.PathLogin {
		t.Errorf("expected location %s, got %s", auth.PathLogin, ctxReq.GetHeader("Location"))
	}

	// Verify both are deleted from DB
	if _, err := m.GetSession(cMain.Value); err == nil {
		t.Errorf("main session not deleted")
	}
	if _, err := m.GetSession(cStep.Value); err == nil {
		t.Errorf("stepup session not deleted")
	}
}
