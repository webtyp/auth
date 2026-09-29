//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
)

// Every event type prints a distinct, non-"unknown" name. Adding a constant
// without a name fails here.
func TestSecurityEventType_EveryConstantHasAName(t *testing.T) {
	seen := map[string]auth.SecurityEventType{}
	for ty := auth.EventJWTTampered; ty <= auth.EventDevAutologin; ty++ {
		name := ty.String()
		if name == "unknown" || name == "" {
			t.Errorf("SecurityEventType(%d) has no name", uint8(ty))
		}
		if prev, dup := seen[name]; dup {
			t.Errorf("name %q used by both %d and %d", name, uint8(prev), uint8(ty))
		}
		seen[name] = ty
	}
}

func TestSecurityEventType_KnownNames(t *testing.T) {
	cases := map[auth.SecurityEventType]string{
		auth.EventJWTTampered:        "jwt_tampered",
		auth.EventUnauthorizedAccess: "unauthorized_access",
		auth.EventAccessDenied:       "access_denied",
		auth.EventDevAutologin:       "dev_autologin",
	}
	for ty, want := range cases {
		if got := ty.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", uint8(ty), got, want)
		}
	}
	if got := auth.SecurityEventType(250).String(); got != "unknown" {
		t.Errorf("out-of-range type = %q, want \"unknown\"", got)
	}
}
