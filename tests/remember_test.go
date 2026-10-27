package tests

import (
	"testing"

	"webtyp.com/auth"
	"webtyp.com/model"
)

// memStore stands in for the browser's localStorage.
type memStore struct{ kv map[string]string }

func (m *memStore) Get(key string) (string, error) { return m.kv[key], nil }
func (m *memStore) Set(key, value string) error    { m.kv[key] = value; return nil }
func (m *memStore) Del(key string) error           { delete(m.kv, key); return nil }

func TestRememberedSessionLastsTheDay(t *testing.T) {
	s := &memStore{kv: map[string]string{}}
	if _, ok := auth.RememberedSession(s, "2026-10-12"); ok {
		t.Fatal("nothing remembered yet")
	}

	p := auth.ProfileDTO{Id: "u1", Name: "Ana", Roles: []string{"recepcion"}, Permissions: []string{"reservation:crud"}}
	if err := auth.RememberSession(s, p, "2026-10-12"); err != nil {
		t.Fatalf("RememberSession: %v", err)
	}
	got, ok := auth.RememberedSession(s, "2026-10-12")
	if !ok || got.Id != "u1" || got.Name != "Ana" || len(got.Roles) != 1 || !got.Can("reservation", model.Read) {
		t.Fatalf("same day: %+v %v", got, ok)
	}
	if _, ok := auth.RememberedSession(s, "2026-10-13"); ok {
		t.Fatal("a session must not outlive its day")
	}

	if err := auth.ForgetSession(s); err != nil {
		t.Fatalf("ForgetSession: %v", err)
	}
	if _, ok := auth.RememberedSession(s, "2026-10-12"); ok {
		t.Fatal("forgotten session still remembered")
	}
}

func TestRememberSessionNeedsDayAndUser(t *testing.T) {
	s := &memStore{kv: map[string]string{}}
	if err := auth.RememberSession(s, auth.ProfileDTO{Id: "u1"}, ""); err == nil {
		t.Fatal("empty day accepted")
	}
	if err := auth.RememberSession(s, auth.ProfileDTO{}, "2026-10-12"); err == nil {
		t.Fatal("profile without id accepted")
	}
	if len(s.kv) != 0 {
		t.Fatalf("refused sessions were stored: %v", s.kv)
	}
}

func TestRememberedSessionIgnoresGarbage(t *testing.T) {
	s := &memStore{kv: map[string]string{}}
	auth.RememberSession(s, auth.ProfileDTO{Id: "u1"}, "2026-10-12")
	for k := range s.kv {
		s.kv[k] = "{not json"
	}
	if _, ok := auth.RememberedSession(s, "2026-10-12"); ok {
		t.Fatal("a corrupt entry must read as no session")
	}
}
