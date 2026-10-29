package tests

import (
	"testing"
	"webtyp.com/auth/passkey"
	"webtyp.com/json"
)

func TestPasskeyDTO(t *testing.T) {
	vo := passkey.VerifyOptions{
		Challenge:        "challenge123",
		RPID:             "rp123",
		AllowCredentials: []string{"cred1", "cred2"},
	}
	var voBuf []byte
	if err := json.Encode(&vo, &voBuf); err != nil {
		t.Fatalf("failed to encode VerifyOptions: %v", err)
	}
	var voDec passkey.VerifyOptions
	if err := json.Decode(voBuf, &voDec); err != nil {
		t.Fatalf("failed to decode VerifyOptions: %v", err)
	}
	if voDec.Challenge != vo.Challenge {
		t.Errorf("expected challenge %q, got %q", vo.Challenge, voDec.Challenge)
	}
	if voDec.RPID != vo.RPID {
		t.Errorf("expected rpid %q, got %q", vo.RPID, voDec.RPID)
	}
	if len(voDec.AllowCredentials) != len(vo.AllowCredentials) {
		t.Fatalf("expected %d allow credentials, got %d", len(vo.AllowCredentials), len(voDec.AllowCredentials))
	}
	for i := range vo.AllowCredentials {
		if voDec.AllowCredentials[i] != vo.AllowCredentials[i] {
			t.Errorf("expected allow credential %q, got %q", vo.AllowCredentials[i], voDec.AllowCredentials[i])
		}
	}

	ro := passkey.RegisterOptions{
		Challenge:          "challenge456",
		RPID:               "rp456",
		UserID:             "user123",
		UserName:           "username123",
		ExcludeCredentials: []string{"cred3", "cred4"},
	}
	var roBuf []byte
	if err := json.Encode(&ro, &roBuf); err != nil {
		t.Fatalf("failed to encode RegisterOptions: %v", err)
	}
	var roDec passkey.RegisterOptions
	if err := json.Decode(roBuf, &roDec); err != nil {
		t.Fatalf("failed to decode RegisterOptions: %v", err)
	}
	if roDec.Challenge != ro.Challenge {
		t.Errorf("expected challenge %q, got %q", ro.Challenge, roDec.Challenge)
	}
	if roDec.RPID != ro.RPID {
		t.Errorf("expected rpid %q, got %q", ro.RPID, roDec.RPID)
	}
	if roDec.UserID != ro.UserID {
		t.Errorf("expected user id %q, got %q", ro.UserID, roDec.UserID)
	}
	if roDec.UserName != ro.UserName {
		t.Errorf("expected user name %q, got %q", ro.UserName, roDec.UserName)
	}
	if len(roDec.ExcludeCredentials) != len(ro.ExcludeCredentials) {
		t.Fatalf("expected %d exclude credentials, got %d", len(ro.ExcludeCredentials), len(roDec.ExcludeCredentials))
	}
	for i := range ro.ExcludeCredentials {
		if roDec.ExcludeCredentials[i] != ro.ExcludeCredentials[i] {
			t.Errorf("expected exclude credential %q, got %q", ro.ExcludeCredentials[i], roDec.ExcludeCredentials[i])
		}
	}
}
