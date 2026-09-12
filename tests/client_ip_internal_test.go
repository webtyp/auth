package tests

import (
	"testing"

	"webtyp.com/auth"
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
