package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

// HostFromAddr must strip the port from a net/http-style "host:port" address
// without mangling an IPv6 literal's brackets. See ClientIP's doc comment for
// why this exists: naive fmt.Split(addr, ":") returned "[" for any IPv6
// address, a real bug previously leaf-patched in veltylabs/staff_manager
// instead of fixed here.
func TestHostFromAddr(t *testing.T) {
	cases := []struct{ addr, want string }{
		{"127.0.0.1:54321", "127.0.0.1"},
		{"[::1]:54321", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"", ""},
	}
	for _, c := range cases {
		if got := auth.HostFromAddr(c.addr); got != c.want {
			t.Errorf("HostFromAddr(%q) = %q, want %q", c.addr, got, c.want)
		}
	}
}

// ClientIP is the one place an IP enters auth, so it returns the canonical
// spelling (input.CanonicalIP): one "localhost" reaches the server as ::1 from
// curl and as 127.0.0.1 from Chrome, and a trusted device stored under one
// spelling rejected the other — DEV_AUTOLOGIN and the real login alike
// (EventIPMismatch with the right RUT, mjosefa-cms 2026-09-26).
func TestClientIP_Canonical(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		xff        string
		trustProxy bool
		want       string
	}{
		{"ipv6 loopback", "[::1]:54321", "", false, "127.0.0.1"},
		{"ipv4 loopback", "127.0.0.1:54321", "", false, "127.0.0.1"},
		{"ipv4-mapped peer", "[::ffff:192.168.1.5]:54321", "", false, "192.168.1.5"},
		{"lan ipv4 unchanged", "192.168.1.5:54321", "", false, "192.168.1.5"},
		{"forwarded loopback", "10.0.0.1:80", "::1, 10.0.0.1", true, "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := &mock.Context{}
			ctx.SetValue(router.ContextKeyRemoteAddr, c.remoteAddr)
			if c.xff != "" {
				ctx.SetHeader("X-Forwarded-For", c.xff)
			}
			if got := auth.ClientIP(ctx, c.trustProxy); got != c.want {
				t.Errorf("ClientIP = %q, want %q", got, c.want)
			}
		})
	}
}
