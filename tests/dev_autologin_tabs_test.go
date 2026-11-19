//go:build !wasm && dev

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

const devSecondRUT = "11111111-1" // valid checksum

// devTwoUsers seeds two trusted users and returns a Module built with
// DEV_AUTOLOGIN set to the list of both credentials, plus both user ids.
func devTwoUsers(t *testing.T) (*authority.Module, string, string) {
	t.Helper()
	db := newTestDB(t)
	seed, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	u1, err := seed.CreateUser("one@test.com", "One", "")
	if err != nil {
		t.Fatal(err)
	}
	u2, err := seed.CreateUser("two@test.com", "Two", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedip.RegisterRUT(seed, u1.Id, lanRUT); err != nil {
		t.Fatal(err)
	}
	if err := trustedip.RegisterRUT(seed, u2.Id, devSecondRUT); err != nil {
		t.Fatal(err)
	}
	trusted := &fakeTrustedIP{allowed: map[string]string{u1.Id: lanTrustedIP, u2.Id: lanTrustedIP}}

	t.Setenv(auth.EnvDevAutologin, `[{"code":"`+lanRUT+`"}, {"code":"`+devSecondRUT+`"}]`)
	m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(trustedip.New(m, trusted, m, m.Ports().Report, false))
	return m, u1.Id, u2.Id
}

// devRequest runs Authenticate for a request to host from the trusted IP and
// returns who it resolved to.
func devRequest(m *authority.Module, host string) string {
	var who string
	ctx := &mock.Context{}
	ctx.SetValue(router.ContextKeyRemoteAddr, lanTrustedIP+":54321")
	if host != "" {
		ctx.SetHeader("Host", host)
	}
	m.Authenticate()(func(c router.Context) { who = c.UserID() })(ctx)
	return who
}

func TestDevAutologin_ListSignsInOneUserPerHost(t *testing.T) {
	m, u1, u2 := devTwoUsers(t)
	cases := []struct{ host, want string }{
		{"localhost:6060", u1},
		{"user2.localhost:6060", u2},
		{"127.0.0.1:6060", u1},
		{"", u1},
		{"user3.localhost:6060", ""}, // no third credential
		{"user1.localhost:6060", ""}, // credential 1 lives on localhost
		{"userx.localhost:6060", ""},
	}
	for _, c := range cases {
		if got := devRequest(m, c.host); got != c.want {
			t.Errorf("host %q signed in %q, want %q", c.host, got, c.want)
		}
	}
}

func TestDevAutologin_SignOutPausesOnlyThatHost(t *testing.T) {
	m, u1, _ := devTwoUsers(t)
	r := &mock.Router{}
	m.MountAPI(r)

	out := &mock.Context{InMethod: "POST", InPath: auth.PathLogout}
	out.SetHeader("Host", "user2.localhost:6060")
	r.Invoke("POST", auth.PathLogout, out)
	if out.Status != 302 {
		t.Fatalf("logout status = %d, want 302", out.Status)
	}

	if got := devRequest(m, "user2.localhost:6060"); got != "" {
		t.Errorf("after sign-out user2.localhost signed in %q, want the normal login", got)
	}
	if got := devRequest(m, "localhost:6060"); got != u1 {
		t.Errorf("localhost signed in %q, want %q (only the signed-out host pauses)", got, u1)
	}
}

func TestDevAutologin_TabsRouteListsHostsToLoopbackOnly(t *testing.T) {
	m, _, _ := devTwoUsers(t)
	r := &mock.Router{}
	m.MountAPI(r)

	local := &mock.Context{InMethod: "GET", InPath: auth.PathDevAutologinTabs}
	local.SetValue(router.ContextKeyRemoteAddr, "[::1]:40000")
	r.Invoke("GET", auth.PathDevAutologinTabs, local)
	if local.Status != 200 {
		t.Fatalf("loopback status = %d, want 200", local.Status)
	}
	if got, want := string(local.ResponseBody()), `["localhost","user2.localhost"]`; got != want {
		t.Errorf("body = %s, want %s", got, want)
	}

	remote := &mock.Context{InMethod: "GET", InPath: auth.PathDevAutologinTabs}
	remote.SetValue(router.ContextKeyRemoteAddr, lanTrustedIP+":40000")
	r.Invoke("GET", auth.PathDevAutologinTabs, remote)
	if remote.Status != 404 {
		t.Errorf("LAN caller status = %d, want 404", remote.Status)
	}
}

func TestDevAutologin_SingleObjectStillWorks(t *testing.T) {
	db := newTestDB(t)
	seed, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := seed.CreateUser("solo@test.com", "Solo", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedip.RegisterRUT(seed, u.Id, lanRUT); err != nil {
		t.Fatal(err)
	}
	t.Setenv(auth.EnvDevAutologin, ` {"code":"`+lanRUT+`"} `)
	m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(trustedip.New(m, &fakeTrustedIP{allowed: map[string]string{u.Id: lanTrustedIP}}, m, m.Ports().Report, false))
	if got := devRequest(m, "localhost:6060"); got != u.Id {
		t.Errorf("single object signed in %q, want %q", got, u.Id)
	}
}

func TestDevAutologin_InvalidValueIsIgnored(t *testing.T) {
	invalid := []string{
		`[{"code":"x"} {"code":"y"}]`, // missing comma
		`[{"code":"a"}, {"code":"b", {"code":"c"}}]`, // object never closed, the next one inside it
		`[]`,
		`["x"]`,
		`{"code":`,
	}
	for _, value := range invalid {
		db := newTestDB(t)
		t.Setenv(auth.EnvDevAutologin, value)
		m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "dev_session", Events: &mockPublisher{}})
		if err != nil {
			t.Fatal(err)
		}
		var logged int
		m.SetLog(func(...any) { logged++ })
		counter := &countingFormLogin{}
		m.Enable(counter)
		devRequest(m, "localhost:6060")
		devRequest(m, "localhost:6060")
		if got := counter.calls.Load(); got != 0 {
			t.Errorf("invalid DEV_AUTOLOGIN %s was replayed %d times, want 0", value, got)
		}
		if logged != 1 {
			t.Errorf("invalid DEV_AUTOLOGIN %s logged %d lines, want exactly 1 warning", value, logged)
		}
	}
}

// devRequestWith runs Authenticate for host with the given cookies and returns
// who it resolved to, how strongly, and the request (to read issued cookies).
func devRequestWith(m *authority.Module, host string, cookies ...router.Cookie) (string, model.Assurance, *mock.Context) {
	var who string
	var level model.Assurance
	ctx := &mock.Context{}
	ctx.SetValue(router.ContextKeyRemoteAddr, lanTrustedIP+":54321")
	ctx.SetHeader("Host", host)
	for _, c := range cookies {
		ctx.SetCookie(c)
	}
	m.Authenticate()(func(c router.Context) { who, level = c.UserID(), c.Assurance() })(ctx)
	return who, level, ctx
}

func TestDevAutologin_OpensBothFactors(t *testing.T) {
	m, u1, _ := devTwoUsers(t)
	who, level, ctx := devRequestWith(m, "localhost:6060")
	if who != u1 || level != model.AssuranceMultiFactor {
		t.Fatalf("autologin = %q at assurance %d, want %q at %d", who, level, u1, model.AssuranceMultiFactor)
	}
	if c, ok := ctx.Cookie("__Host-" + authority.StepUpCookieName); !ok || c.Value == "" {
		t.Error("autologin did not issue the second-factor session cookie")
	}
}

func TestDevAutologin_UpgradesAOneFactorSession(t *testing.T) {
	m, u1, _ := devTwoUsers(t)
	_, _, first := devRequestWith(m, "localhost:6060")
	main, _ := first.Cookie("__Host-dev_session")

	// The same browser after a restart: it still has the main cookie only.
	who, level, _ := devRequestWith(m, "localhost:6060", main)
	if who != u1 || level != model.AssuranceMultiFactor {
		t.Errorf("one-factor session on a live autologin host = %q at %d, want %q at %d", who, level, u1, model.AssuranceMultiFactor)
	}
}

func TestDevAutologin_HandLoginOnASignedOutHostKeepsOneFactor(t *testing.T) {
	m, _, u2 := devTwoUsers(t)
	devRequestWith(m, "user2.localhost:6060")

	r := &mock.Router{}
	m.MountAPI(r)
	out := &mock.Context{InMethod: "POST", InPath: auth.PathLogout}
	out.SetHeader("Host", "user2.localhost:6060")
	r.Invoke("POST", auth.PathLogout, out)

	// Stand-in for a session the developer then opened by hand on that host:
	// a one-factor cookie for u2 (the revoked row cannot be reused, so issue one).
	hand := &mock.Context{}
	if err := m.IssueSession(hand, u2); err != nil {
		t.Fatal(err)
	}
	c, _ := hand.Cookie("__Host-dev_session")
	who, level, _ := devRequestWith(m, "user2.localhost:6060", c)
	if who != u2 || level != model.AssuranceSingleFactor {
		t.Errorf("hand login on a signed-out host = %q at %d, want %q at %d (no second factor added)", who, level, u2, model.AssuranceSingleFactor)
	}
}
