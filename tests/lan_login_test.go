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

func postRUT(t *testing.T, r *mock.Router, rut, ip string) *mock.Context {
	t.Helper()
	ctx := &mock.Context{InMethod: "POST", InPath: auth.PathLoginRUT}
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetValue("RemoteAddr", ip+":54321")

	var body string
	if err := json.Encode(&auth.RUTLoginData{Rut: rut}, &body); err != nil {
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
