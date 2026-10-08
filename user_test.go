package auth

import (
	"testing"
)

func TestSentinelErrors(t *testing.T) {
	if !IsNotFound(ErrNotFound) {
		t.Error("IsNotFound(ErrNotFound) should be true")
	}
	if IsNotFound(ErrRUTTaken) {
		t.Error("IsNotFound(ErrRUTTaken) should be false")
	}
	if IsNotFound(nil) {
		t.Error("IsNotFound(nil) should be false")
	}
	if !IsInvalidRUT(ErrInvalidRUT) {
		t.Error("IsInvalidRUT(ErrInvalidRUT) should be true")
	}
	if IsInvalidRUT(ErrNotFound) {
		t.Error("IsInvalidRUT(ErrNotFound) should be false")
	}
	if IsInvalidRUT(nil) {
		t.Error("IsInvalidRUT(nil) should be false")
	}
	if !IsRUTTaken(ErrRUTTaken) {
		t.Error("IsRUTTaken(ErrRUTTaken) should be true")
	}
	if IsRUTTaken(ErrNotFound) {
		t.Error("IsRUTTaken(ErrNotFound) should be false")
	}
	if IsRUTTaken(nil) {
		t.Error("IsRUTTaken(nil) should be false")
	}
}

func TestSentinelErrorsText(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{ErrInvalidCredentials, "access denied"},
		{ErrSuspended, "user suspended"},
		{ErrEmailTaken, "email registered"},
		{ErrWeakPassword, "password weak"},
		{ErrSessionExpired, "token expired"},
		{ErrNotFound, "user not found"},
		{ErrProviderNotFound, "provider not found"},
		{ErrInvalidOAuthState, "state invalid"},
		{ErrCannotUnlink, "identity cannot unlink"},
		{ErrInvalidRUT, "rut invalid"},
		{ErrRUTTaken, "rut registered"},
		{ErrIPTaken, "ip registered"},
	}

	for _, tt := range tests {
		if got := tt.err.Error(); got != tt.want {
			t.Errorf("error %v: got text %q, want %q", tt.err, got, tt.want)
		}
	}
}
