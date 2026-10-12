package auth

import (
	"webtyp.com/json"
	"webtyp.com/model"
)

// SessionStore is where a browser keeps its remembered session; the app passes its
// localStorage (dom.LocalStorageGet/Set/Del). Get answers "" when the key is absent.
type SessionStore interface {
	Get(key string) (string, error)
	Set(key, value string) error
	Del(key string) error
}

const (
	rememberedKey = "webtyp-auth-session"
	keyDay        = "day"
	keyProfile    = "profile"

	errRememberDay  domainError = "auth: RememberSession needs the device's local day"
	errRememberUser domainError = "auth: RememberSession needs a profile with an Id"
)

// RememberSession keeps p as this device's session for day (the device's local date, for example
// "2026-10-12"), so the same person keeps working here that day while the server is unreachable.
// It grants nothing: the server still authorises every request it receives.
func RememberSession(s SessionStore, p ProfileDTO, day string) error {
	if day == "" {
		return errRememberDay
	}
	if p.Id == "" {
		return errRememberUser
	}
	var out string
	if err := json.Encode(&remembered{day: day, profile: p}, &out); err != nil {
		return err
	}
	return s.Set(rememberedKey, out)
}

// RememberedSession returns the session remembered for day. ok is false when there is none, it is
// from another day, or it cannot be read.
func RememberedSession(s SessionStore, day string) (p ProfileDTO, ok bool) {
	raw, err := s.Get(rememberedKey)
	if err != nil || raw == "" || day == "" {
		return ProfileDTO{}, false
	}
	r := &remembered{}
	if err := json.Decode(raw, r); err != nil || r.day != day || r.profile.Id == "" {
		return ProfileDTO{}, false
	}
	return r.profile, true
}

// ForgetSession removes the remembered session (sign-out).
func ForgetSession(s SessionStore) error { return s.Del(rememberedKey) }

// remembered is what RememberSession stores.
type remembered struct {
	day     string
	profile ProfileDTO
}

func (r *remembered) IsNil() bool { return r == nil }
func (r *remembered) EncodeFields(w model.FieldWriter) {
	w.String(keyDay, r.day)
	w.Object(keyProfile, r.profile)
}
func (r *remembered) DecodeFields(rd model.FieldReader) {
	r.day, _ = rd.String(keyDay)
	rd.Object(keyProfile, &r.profile)
}
