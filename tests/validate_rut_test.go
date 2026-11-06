//go:build !wasm

package tests

import (
	"testing"

	trustedip "webtyp.com/auth/trusted_ip"
)

// Every way a person writes the same RUT normalizes to the same value: a lookup by RUT never misses a
// record that already exists (Pa100T ended up with 354 duplicated patients because the search missed).
func TestValidateRUT_AnyWayItIsWritten(t *testing.T) {
	for _, written := range []string{"8123456-6", "81234566", "8.123.456-6", "08.123.456-6", "8 123 456-6", " 8.123.456 - 6 ", "008123456-6"} {
		got, err := trustedip.ValidateRUT(written)
		if err != nil || got != "8123456-6" {
			t.Errorf("ValidateRUT(%q) = %q, %v; want 8123456-6", written, got, err)
		}
	}
	if got, err := trustedip.ValidateRUT("10.219.781-k"); err != nil || got != "10219781-K" {
		t.Errorf("lower-case k: %q, %v", got, err)
	}
	for _, bad := range []string{"", "0", "000000-0", "8123456-7", "8a23456-6"} {
		if got, err := trustedip.ValidateRUT(bad); err == nil {
			t.Errorf("ValidateRUT(%q) = %q, want an error", bad, got)
		}
	}
}
