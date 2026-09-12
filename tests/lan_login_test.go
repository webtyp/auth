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

// fakeTrustedIP answers the allowlist question per (user, ip) without the
// LANIP table, so a rejected login is caused by the value under test and not
// by missing fixture rows.
type fakeTrustedIP struct{ allowed map[string]string }

func (f *fakeTrustedIP) IsTrustedIP(userID, ip string) bool {
	return f.allowed[userID] == ip
}

const (
	lanRUT        = "12345678-5" // valid checksum, registered below
	lanUnknownRUT = "11111111-1" // valid checksum, never registered
	lanBadRUT     = "12345678-0" // wrong check digit
	lanTrustedIP  = "192.168.20.10"
)

// TestLANRUTLogin drives the real trusted_ip authenticator over the real
// authority module: a consumer app posting auth.PathLoginRUT with
// auth.RUTLoginData, which is the whole contract this library now publishes.
func TestLANRUTLogin(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{
		IDs:        testIDs,
		CookieName: "lan_session",
		Events:     pub,
	})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("lan-login@test.com", "LAN Staff", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLAN(u.Id, lanRUT); err != nil {
		t.Fatal(err)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{u.Id: lanTrustedIP}}
	m.Enable(trustedip.New(m, trusted, m, m, false))

	r := &mock.Router{}
	r.Configure(mock.Config{})
	m.MountAPI(r)

	t.Run("TrustedIPIssuesSession", func(t *testing.T) {
		ctx := postRUT(t, r, lanRUT, lanTrustedIP)
		if ctx.Status != 302 {
			t.Fatalf("status = %d, want 302", ctx.Status)
		}
		c, ok := ctx.Cookie("lan_session")
		if !ok || c.Value == "" {
			t.Errorf("no session cookie issued: %+v", c)
		}
	})

	t.Run("UntrustedIPReportsMismatch", func(t *testing.T) {
		from := len(pub.SecurityEvents())
		ctx := postRUT(t, r, lanRUT, "10.0.0.7")
		if ctx.Status != 401 {
			t.Fatalf("status = %d, want 401", ctx.Status)
		}
		assertSecurityEvent(t, pub, from, auth.EventIPMismatch)
	})

	t.Run("BadChecksumReportsInvalidRUT", func(t *testing.T) {
		from := len(pub.SecurityEvents())
		ctx := postRUT(t, r, lanBadRUT, lanTrustedIP)
		if ctx.Status != 401 {
			t.Fatalf("status = %d, want 401", ctx.Status)
		}
		assertSecurityEvent(t, pub, from, auth.EventInvalidRUT)
	})

	t.Run("UnregisteredRUTReportsUnknownRUT", func(t *testing.T) {
		from := len(pub.SecurityEvents())
		ctx := postRUT(t, r, lanUnknownRUT, lanTrustedIP)
		if ctx.Status != 401 {
			t.Fatalf("status = %d, want 401", ctx.Status)
		}
		assertSecurityEvent(t, pub, from, auth.EventUnknownRUT)
	})
}

// TestLANRUTLogin_RateLimited guards the opacity property WithRateLimit
// exists for: an IP blocked after too many failed attempts must be
// indistinguishable from any other rejected login — same status, same body
// — never a 429 or a message that tells an outsider a block even exists.
func TestLANRUTLogin_RateLimited(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{
		IDs:        testIDs,
		CookieName: "lan_session",
		Events:     pub,
	})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("lan-rl@test.com", "LAN Staff", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLAN(u.Id, lanRUT); err != nil {
		t.Fatal(err)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{u.Id: lanTrustedIP}}
	limiter := auth.NewIPLimiter(3, 60, 60)
	m.Enable(trustedip.New(m, trusted, m, m, false, trustedip.WithRateLimit(limiter)))

	r := &mock.Router{}
	r.Configure(mock.Config{})
	m.MountAPI(r)

	// First 3 failures — someone at the ASSIGNED, trusted device typing an
	// unregistered RUT three times. The ordinary rejection path, unaffected
	// until the limit is crossed.
	var lastRejectedBody string
	for i := 0; i < 3; i++ {
		ctx := postRUT(t, r, lanUnknownRUT, lanTrustedIP)
		if ctx.Status != 401 {
			t.Fatalf("attempt %d: status = %d, want 401", i+1, ctx.Status)
		}
		lastRejectedBody = string(ctx.ResponseBody())
	}

	// The 4th attempt, from that SAME trusted IP, uses the CORRECT rut — one
	// that would otherwise issue a session (see TrustedIPIssuesSession
	// above). It must instead be blocked by the limiter: the block applies
	// to the IP regardless of trust, checked before any RUT/IP logic runs.
	from := len(pub.SecurityEvents())
	blocked := postRUT(t, r, lanRUT, lanTrustedIP)
	if blocked.Status != 401 {
		t.Fatalf("blocked attempt: status = %d, want 401 (never 429 — that would out the block)", blocked.Status)
	}
	if got := string(blocked.ResponseBody()); got != lastRejectedBody {
		t.Errorf("blocked body = %q, want the exact same body as an ordinary rejection (%q)", got, lastRejectedBody)
	}
	assertSecurityEvent(t, pub, from, auth.EventRateLimited)
}

// TestLANRUTLogin_UniformRejectionBody is the regression this whole mode
// exists for: every rejection reason must be indistinguishable from the
// outside. Before this test, a malformed value returned ValidateRUT's own
// message ("rut invalid") while every other rejection returned the generic
// "access denied" — an outsider could tell "wrong format" from "wrong
// credential" just by reading the body. All four checked here must match
// byte for byte.
func TestLANRUTLogin_UniformRejectionBody(t *testing.T) {
	db := newTestDB(t)
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, CookieName: "lan_session", Events: pub})
	if err != nil {
		t.Fatal(err)
	}

	active, err := m.CreateUser("active@test.com", "Active", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterLAN(active.Id, lanRUT); err != nil {
		t.Fatal(err)
	}

	suspended, err := m.CreateUser("suspended@test.com", "Suspended", "")
	if err != nil {
		t.Fatal(err)
	}
	const suspendedRUT = "22222222-2"
	if err := m.RegisterLAN(suspended.Id, suspendedRUT); err != nil {
		t.Fatal(err)
	}
	if err := m.SuspendUser(suspended.Id); err != nil {
		t.Fatal(err)
	}

	trusted := &fakeTrustedIP{allowed: map[string]string{active.Id: lanTrustedIP, suspended.Id: lanTrustedIP}}
	m.Enable(trustedip.New(m, trusted, m, m, false))

	r := &mock.Router{}
	r.Configure(mock.Config{})
	m.MountAPI(r)

	cases := []struct {
		name string
		rut  string
		ip   string
	}{
		{"malformed checksum", lanBadRUT, lanTrustedIP},
		{"unregistered rut", lanUnknownRUT, lanTrustedIP},
		{"untrusted ip", lanRUT, "10.0.0.7"},
		{"suspended user", suspendedRUT, lanTrustedIP},
	}

	var firstBody string
	for i, c := range cases {
		ctx := postRUT(t, r, c.rut, c.ip)
		if ctx.Status != 401 {
			t.Fatalf("%s: status = %d, want 401", c.name, ctx.Status)
		}
		got := string(ctx.ResponseBody())
		if i == 0 {
			firstBody = got
			continue
		}
		if got != firstBody {
			t.Errorf("%s: body = %q, want the same body as %q (%q)", c.name, got, cases[0].name, firstBody)
		}
	}
}

func postRUT(t *testing.T, r *mock.Router, rut, ip string) *mock.Context {
	t.Helper()
	ctx := &mock.Context{InMethod: "POST", InPath: auth.PathLoginRUT}
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetValue("RemoteAddr", ip+":54321")

	var body string
	if err := json.Encode(&auth.RUTLoginData{Code: rut}, &body); err != nil {
		t.Fatal(err)
	}
	ctx.InBody = []byte(body)

	r.Invoke("POST", auth.PathLoginRUT, ctx)
	return ctx
}

// assertSecurityEvent checks that the attempt published want, looking only at
// events produced after the index the caller captured.
func assertSecurityEvent(t *testing.T, pub *mockPublisher, from int, want auth.SecurityEventType) {
	t.Helper()
	events := pub.SecurityEvents()
	for _, e := range events[from:] {
		if e.Type == want {
			return
		}
	}
	t.Errorf("no security event of type %d published, got %+v", want, events[from:])
}
