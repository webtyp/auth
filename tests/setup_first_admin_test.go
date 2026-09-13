//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/json"
	"webtyp.com/router/mock"
	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	trustedip "webtyp.com/auth/trusted_ip"
)

const (
	setupRUT = "12345678-5" // valid checksum
	setupIP  = "192.168.20.44"
)

// setupHarness wires the real authority + trusted_ip with the setup routes
// enabled, and records what the consumer's create callback was handed.
type setupHarness struct {
	m       *authority.Module
	r       *mock.Router
	pub     *mockPublisher
	gotCode string
	gotName string
	gotIP   string
	calls   int
}

func newSetupHarness(t *testing.T) *setupHarness {
	t.Helper()
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "setup_session", Events: pub})
	if err != nil {
		t.Fatal(err)
	}
	h := &setupHarness{m: m, pub: pub}

	// The consumer's composition, reduced to what auth itself can observe: a
	// user plus the provider identity. A real app also creates a device, a
	// staff record and a role here — none of which auth knows about.
	create := func(code, name, ip string) error {
		h.calls++
		h.gotCode, h.gotName, h.gotIP = code, name, ip
		u, err := m.CreateUser("", name, "")
		if err != nil {
			return err
		}
		return m.RegisterLAN(u.Id, code)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{}}
	m.Enable(trustedip.New(m, trusted, m, m, false, trustedip.WithFirstAdminSetup(m, create)))

	h.r = &mock.Router{}
	h.r.Configure(mock.Config{})
	m.MountAPI(h.r)
	return h
}

func (h *setupHarness) get(t *testing.T) *mock.Context {
	t.Helper()
	ctx := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	ctx.SetValue("RemoteAddr", setupIP+":54321")
	h.r.Invoke("GET", auth.PathSetup, ctx)
	return ctx
}

func (h *setupHarness) post(t *testing.T, code, name string) *mock.Context {
	t.Helper()
	ctx := &mock.Context{InMethod: "POST", InPath: auth.PathSetup}
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetValue("RemoteAddr", setupIP+":54321")

	var body string
	if err := json.Encode(&auth.SetupData{Code: code, Name: name}, &body); err != nil {
		t.Fatal(err)
	}
	ctx.InBody = []byte(body)
	h.r.Invoke("POST", auth.PathSetup, ctx)
	return ctx
}

// TestFirstAdminSetup walks the whole first-run lifecycle: open on a fresh
// install, creates the admin bound to the IP that performed the setup, and
// then closes permanently.
func TestFirstAdminSetup(t *testing.T) {
	h := newSetupHarness(t)

	t.Run("OpenWhileNoAdminExists", func(t *testing.T) {
		ctx := h.get(t)
		if ctx.Status != 200 {
			t.Fatalf("GET status = %d, want 200 on a fresh install", ctx.Status)
		}
	})

	t.Run("CreatesAdminBoundToTheSetupIP", func(t *testing.T) {
		from := len(h.pub.SecurityEvents())
		ctx := h.post(t, setupRUT, "Admin")
		if ctx.Status != 302 {
			t.Fatalf("POST status = %d, want 302 (installer is signed in)", ctx.Status)
		}
		if h.calls != 1 {
			t.Fatalf("create callback ran %d times, want 1", h.calls)
		}
		if h.gotIP != setupIP {
			t.Errorf("create got ip %q, want the request's own IP %q — that IP is the device the admin will log in from", h.gotIP, setupIP)
		}
		if h.gotName != "Admin" {
			t.Errorf("create got name %q, want %q", h.gotName, "Admin")
		}
		if h.gotCode != setupRUT {
			t.Errorf("create got code %q, want the normalized credential %q", h.gotCode, setupRUT)
		}
		if c, ok := ctx.Cookie("setup_session"); !ok || c.Value == "" {
			t.Errorf("setup must issue a session so the installer lands inside: %+v", c)
		}
		assertSecurityEvent(t, h.pub, from, auth.EventSetupCompleted)
	})

	t.Run("ClosesOnceAnAdminExists", func(t *testing.T) {
		if ctx := h.get(t); ctx.Status != 404 {
			t.Errorf("GET status = %d, want 404 once setup is done", ctx.Status)
		}
	})

	t.Run("RejectsASecondAdminAndReportsIt", func(t *testing.T) {
		from := len(h.pub.SecurityEvents())
		before := h.calls
		ctx := h.post(t, "11111111-1", "Intruder")
		if ctx.Status != 404 {
			t.Fatalf("POST status = %d, want 404 once setup is done", ctx.Status)
		}
		if h.calls != before {
			t.Errorf("create callback ran again after setup closed (%d → %d)", before, h.calls)
		}
		assertSecurityEvent(t, h.pub, from, auth.EventSetupRejected)
	})
}

// TestFirstAdminSetup_RejectsInvalidCredential: an admin created with a
// credential the login path would reject could never sign in, so setup runs
// the same checksum and refuses.
func TestFirstAdminSetup_RejectsInvalidCredential(t *testing.T) {
	h := newSetupHarness(t)

	ctx := h.post(t, "12345678-0", "Admin") // wrong check digit
	if ctx.Status != 400 {
		t.Fatalf("POST status = %d, want 400 for a bad checksum", ctx.Status)
	}
	if h.calls != 0 {
		t.Error("create callback must not run for an invalid credential")
	}
	// Still open: a typo during setup cannot lock the installer out.
	if got := h.get(t); got.Status != 200 {
		t.Errorf("GET status = %d, want 200 — a rejected attempt must leave setup open", got.Status)
	}
}

// TestFirstAdminSetup_RequiresAName guards the one field auth can validate
// itself: a nameless administrator is a row nobody can identify later.
func TestFirstAdminSetup_RequiresAName(t *testing.T) {
	h := newSetupHarness(t)

	if ctx := h.post(t, setupRUT, ""); ctx.Status != 400 {
		t.Fatalf("POST status = %d, want 400 without a name", ctx.Status)
	}
	if h.calls != 0 {
		t.Error("create callback must not run without a name")
	}
}

// brokenRegistry stands in for the state a real install hits when the schema
// was never created: the query itself fails, so nobody can say whether an
// admin exists.
type brokenRegistry struct{}

func (brokenRegistry) HasIdentity(string) (bool, error) {
	return false, auth.ErrNotFound
}

// TestFirstAdminSetup_UnreadableRegistryStaysClosedAndSaysSo covers the case
// that actually bit in practice: a database with no tables yet. Setup must
// stay shut (we cannot know whether an admin exists, so we must not let
// anyone claim the account) — but it must also SAY so, because from outside
// this 404 is identical to "already configured", and an operator staring at
// a login screen has no other way to learn the schema is missing.
func TestFirstAdminSetup_UnreadableRegistryStaysClosedAndSaysSo(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
	if err != nil {
		t.Fatal(err)
	}
	created := 0
	create := func(string, string, string) error { created++; return nil }
	m.Enable(trustedip.New(m, &fakeTrustedIP{allowed: map[string]string{}}, m, m, false,
		trustedip.WithFirstAdminSetup(brokenRegistry{}, create)))

	r := &mock.Router{}
	r.Configure(mock.Config{})
	m.MountAPI(r)

	from := len(pub.SecurityEvents())
	ctx := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	ctx.SetValue("RemoteAddr", setupIP+":54321")
	r.Invoke("GET", auth.PathSetup, ctx)

	if ctx.Status != 404 {
		t.Errorf("GET status = %d, want 404 — an unreadable registry must never swing setup open", ctx.Status)
	}
	assertSecurityEvent(t, pub, from, auth.EventSetupUnavailable)

	// And a POST must not reach the consumer's create callback either.
	from = len(pub.SecurityEvents())
	post := &mock.Context{InMethod: "POST", InPath: auth.PathSetup}
	post.SetHeader("Content-Type", "application/json")
	post.SetValue("RemoteAddr", setupIP+":54321")
	post.InBody = []byte(`{"code":"` + setupRUT + `","name":"Admin"}`)
	r.Invoke("POST", auth.PathSetup, post)

	if post.Status != 404 {
		t.Errorf("POST status = %d, want 404", post.Status)
	}
	if created != 0 {
		t.Error("create callback must not run while the registry is unreadable")
	}
	assertSecurityEvent(t, pub, from, auth.EventSetupUnavailable)
	// The reason must be the real one: "rejected" would claim an admin
	// already exists, which is exactly what we could not determine.
	for _, e := range pub.SecurityEvents()[from:] {
		if e.Type == auth.EventSetupRejected {
			t.Error("an unreadable registry must not be reported as EventSetupRejected — that names the wrong cause")
		}
	}
}

// TestFirstAdminSetup_DisabledByDefault: a consumer that never opts in gets
// no setup surface at all — the routes simply do not exist.
func TestFirstAdminSetup_DisabledByDefault(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(trustedip.New(m, &fakeTrustedIP{allowed: map[string]string{}}, m, m, false))

	r := &mock.Router{}
	r.Configure(mock.Config{})
	m.MountAPI(r)

	for _, rt := range r.Routes() {
		if rt.Path == auth.PathSetup {
			t.Fatalf("%s must not be mounted without WithFirstAdminSetup", auth.PathSetup)
		}
	}
}
