package tests

import (
	"testing"

	"webtyp.com/auth"
)

// Sentinel detection without == between interfaces, and every sentinel keeps
// the exact text it had as fmt.Err(...).
func TestSentinelErrors(t *testing.T) {
	if !auth.IsNotFound(auth.ErrNotFound) {
		t.Error("auth.IsNotFound(auth.ErrNotFound) should be true")
	}
	if auth.IsNotFound(auth.ErrRUTTaken) {
		t.Error("auth.IsNotFound(auth.ErrRUTTaken) should be false")
	}
	if auth.IsNotFound(nil) {
		t.Error("auth.IsNotFound(nil) should be false")
	}
	if !auth.IsInvalidRUT(auth.ErrInvalidRUT) {
		t.Error("auth.IsInvalidRUT(auth.ErrInvalidRUT) should be true")
	}
	if auth.IsInvalidRUT(auth.ErrNotFound) {
		t.Error("auth.IsInvalidRUT(auth.ErrNotFound) should be false")
	}
	if auth.IsInvalidRUT(nil) {
		t.Error("auth.IsInvalidRUT(nil) should be false")
	}
	if !auth.IsRUTTaken(auth.ErrRUTTaken) {
		t.Error("auth.IsRUTTaken(auth.ErrRUTTaken) should be true")
	}
	if auth.IsRUTTaken(auth.ErrNotFound) {
		t.Error("auth.IsRUTTaken(auth.ErrNotFound) should be false")
	}
	if auth.IsRUTTaken(nil) {
		t.Error("auth.IsRUTTaken(nil) should be false")
	}
}

func TestSentinelErrorsText(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{auth.ErrInvalidCredentials, "access denied"},
		{auth.ErrSuspended, "user suspended"},
		{auth.ErrEmailTaken, "email registered"},
		{auth.ErrWeakPassword, "password weak"},
		{auth.ErrSessionExpired, "token expired"},
		{auth.ErrNotFound, "user not found"},
		{auth.ErrProviderNotFound, "provider not found"},
		{auth.ErrInvalidOAuthState, "state invalid"},
		{auth.ErrCannotUnlink, "identity cannot unlink"},
		{auth.ErrInvalidRUT, "rut invalid"},
		{auth.ErrRUTTaken, "rut registered"},
		{auth.ErrIPTaken, "ip registered"},
	}

	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("error %v: got text %q, want %q", tt.err, got, tt.want)
		}
	}
}
