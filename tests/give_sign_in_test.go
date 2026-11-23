//go:build !wasm

package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	trustedip "webtyp.com/auth/trusted_ip"
)

// A professional saved in the staff screen must be able to sign in with their RUT: trusted_ip gives the account
// (auth.GivesSignIn). Giving it again for the same RUT returns the same person, never a second account.
func TestGiveSignIn_RUTAccountOnce(t *testing.T) {
	m, err := authority.New(newTestDB(t), auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	var giver auth.GivesSignIn = trustedip.New(m, &fakeTrustedIP{}, m, m.Ports().Report, false)

	first, err := giver.GiveSignIn("12.345.678-5", "Dra. Ana Rojas")
	if err != nil || first == "" {
		t.Fatalf("GiveSignIn: %q %v", first, err)
	}
	id, err := m.IdentityByProvider(auth.ProviderTrustedIP, "12345678-5")
	if err != nil || id.UserId != first {
		t.Fatalf("RUT identity: %+v %v, want user %s", id, err, first)
	}
	again, err := giver.GiveSignIn("12345678-5", "Ana Rojas")
	if err != nil || again != first {
		t.Fatalf("second GiveSignIn: %q %v, want the same user %s", again, err, first)
	}
	if _, err := giver.GiveSignIn("12345678-0", "Bad"); err == nil {
		t.Fatal("a RUT with a wrong check digit must be refused")
	}
}
