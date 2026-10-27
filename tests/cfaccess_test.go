//go:build !wasm

package tests

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
	"encoding/base64"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/cfaccess"
	"webtyp.com/jwt"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

type fakeKeys struct {
	set       jwt.KeySet
	err       error
	fresh     jwt.KeySet // what Refresh returns when hasFresh
	hasFresh  bool
	refreshed int
}

func (f *fakeKeys) Keys() (jwt.KeySet, error) { return f.set, f.err }

func (f *fakeKeys) Refresh() (jwt.KeySet, error) {
	f.refreshed++
	if f.err != nil {
		return jwt.KeySet{}, f.err
	}
	if f.hasFresh {
		return f.fresh, nil
	}
	return f.set, nil
}

func jwksOf(kid string, k *rsa.PrivateKey) string {
	e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
	n := base64.RawURLEncoding.EncodeToString(k.N.Bytes())
	return fmt.Sprintf(`{"keys":[{"kid":"%s","kty":"RSA","e":"%s","n":"%s"}]}`, kid, e, n)
}

func token(t *testing.T, kid string, k *rsa.PrivateKey, payload string) string {
	t.Helper()
	header := fmt.Sprintf(`{"alg":"RS256","kid":"%s","typ":"JWT"}`, kid)
	b64Header := base64.RawURLEncoding.EncodeToString([]byte(header))
	b64Payload := base64.RawURLEncoding.EncodeToString([]byte(payload))
	signingInput := b64Header + "." + b64Payload

	h := sha256.New()
	h.Write([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h.Sum(nil))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}

	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

const (
	team = "acme.cloudflareaccess.com"
	iss  = "https://acme.cloudflareaccess.com"
	aud  = "AUD-TAG-1"
)

func payload(sub, email string, auds []string, iat, exp int64) string {
	audsStr := ""
	for i, a := range auds {
		if i > 0 {
			audsStr += ","
		}
		audsStr += fmt.Sprintf(`"%s"`, a)
	}
	return fmt.Sprintf(`{"iss":"%s","sub":"%s","email":"%s","aud":[%s],"iat":%d,"exp":%d}`, iss, sub, email, audsStr, iat, exp)
}

func TestCFAccess_NewValidation(t *testing.T) {
	keys := &fakeKeys{}
	store := &fakeIdentityStore{}

	cases := []struct {
		name string
		cfg  cfaccess.Config
		keys cfaccess.KeySource
		store auth.IdentityStore
		want string
	}{
		{"empty team", cfaccess.Config{TeamDomain: "", Audience: aud}, keys, store, cfaccess.ErrMsgEmptyTeamDomain},
		{"path in team", cfaccess.Config{TeamDomain: "https://acme.cloudflareaccess.com", Audience: aud}, keys, store, cfaccess.ErrMsgTeamDomainFormat},
		{"empty aud", cfaccess.Config{TeamDomain: team, Audience: ""}, keys, store, cfaccess.ErrMsgEmptyAudience},
		{"nil keys", cfaccess.Config{TeamDomain: team, Audience: aud}, nil, store, cfaccess.ErrMsgNilKeySource},
		{"nil store", cfaccess.Config{TeamDomain: team, Audience: aud}, keys, nil, cfaccess.ErrMsgNilIdentityStore},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := cfaccess.New(tc.cfg, tc.keys, tc.store, nil)
			if err == nil || err.Error() != tc.want {
				t.Errorf("New() err = %v, want %s", err, tc.want)
			}
		})
	}
}

type fakeIdentityStore struct{} // just for setup validation
func (f *fakeIdentityStore) UserByID(id string) (auth.User, error) { return auth.User{}, nil }
func (f *fakeIdentityStore) UserByEmail(email string) (auth.User, error) { return auth.User{}, nil }
func (f *fakeIdentityStore) IdentityByProvider(provider, providerID string) (auth.Identity, error) { return auth.Identity{}, nil }
func (f *fakeIdentityStore) UpsertIdentity(userID, provider, providerID, email string) error { return nil }
func (f *fakeIdentityStore) CreateUser(email, name, phone string) (auth.User, error) { return auth.User{}, nil }
func (f *fakeIdentityStore) IdentityFor(userID, provider string) (auth.Identity, error) { return auth.Identity{}, nil }
func (f *fakeIdentityStore) UpdateUserAvatar(userID, avatar string) error { return nil }

func setup(t *testing.T) (*authority.Module, *rsa.PrivateKey, string, func() []auth.SecurityEvent) {
	t.Helper()
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}

	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "key-1"

	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }
	_ = notify

	return m, k, kid, func() []auth.SecurityEvent { return events }
}

func createCFA(t *testing.T, m *authority.Module, keys cfaccess.KeySource, notify func(auth.SecurityEvent)) *cfaccess.Authenticator {
	cfa, err := cfaccess.New(cfaccess.Config{TeamDomain: team, Audience: aud}, keys, m, notify)
	if err != nil {
		t.Fatal(err)
	}
	return cfa
}

func parseSet(t *testing.T, kid string, k *rsa.PrivateKey) jwt.KeySet {
	t.Helper()
	set, err := jwt.ParseKeySet(jwksOf(kid, k))
	if err != nil {
		t.Fatal(err)
	}
	return set
}

func TestCFAccess_NoHeader(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, func(e auth.SecurityEvent){ events = append(events, e) })

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	p, handled := cfa.IdentifyRequest(ctx)

	if handled {
		t.Error("handled = true, want false")
	}
	if p.UserID != "" {
		t.Errorf("Principal = %+v, want zero", p)
	}
	if len(events) > 0 {
		t.Error("events generated, want 0")
	}
}

func TestCFAccess_ValidLinksByEmail(t *testing.T) {
	m, k, kid, _ := setup(t)
	u, _ := m.CreateUser("ana@clinica.cl", "Ana", "")

	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, nil)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	p, handled := cfa.IdentifyRequest(ctx)

	if !handled {
		t.Error("handled = false, want true")
	}
	if p.UserID != u.Id {
		t.Errorf("UserID = %q, want %q", p.UserID, u.Id)
	}

	id, err := m.IdentityByProvider(auth.ProviderCloudflareAccess, "ana@clinica.cl")
	if err != nil {
		t.Fatalf("IdentityByProvider: %v", err)
	}
	if id.UserId != u.Id {
		t.Errorf("Identity linked to %q, want %q", id.UserId, u.Id)
	}
}

func TestCFAccess_EmailCaseInsensitive(t *testing.T) {
	m, k, kid, _ := setup(t)
	u, _ := m.CreateUser("ana@clinica.cl", "Ana", "")

	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, nil)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "  ANA@Clinica.cl ", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	p, handled := cfa.IdentifyRequest(ctx)
	if !handled || p.UserID != u.Id {
		t.Errorf("UserID = %q, want %q", p.UserID, u.Id)
	}
}

func TestCFAccess_UnknownEmail(t *testing.T) {
	m, k, kid, _ := setup(t)

	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }

	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	p, handled := cfa.IdentifyRequest(ctx)

	if !handled {
		t.Error("handled = false, want true")
	}
	if p.UserID != "" {
		t.Errorf("UserID = %q, want anonymous", p.UserID)
	}
	if len(events) != 1 || events[0].Reason != "unknown_email" || events[0].UserID != "ana@clinica.cl" {
		t.Errorf("events = %+v, want 1 with reason unknown_email and UserID ana@clinica.cl", events)
	}
}

func TestCFAccess_WrongAudience(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }
	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{"OTHER"}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "audience" {
		t.Errorf("events = %+v, want reason audience", events)
	}
}

func TestCFAccess_WrongIssuer(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }
	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	pl := fmt.Sprintf(`{"iss":"https://evil.cloudflareaccess.com","sub":"cf-sub-1","email":"ana@clinica.cl","aud":["%s"],"iat":%d,"exp":%d}`, aud, now, now+600)
	tok := token(t, kid, k, pl)

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "issuer" {
		t.Errorf("events = %+v, want reason issuer", events)
	}
}

func TestCFAccess_Expired(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }
	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now-4000, now-3600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "expired" {
		t.Errorf("events = %+v, want reason expired", events)
	}
}

func TestCFAccess_BadSignatureRefreshesOnce(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }

	// Key B for signature
	kB, _ := rsa.GenerateKey(rand.Reader, 2048)

	fk := &fakeKeys{set: parseSet(t, kid, k)} // Key A in set
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, kB, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "signature" {
		t.Errorf("events = %+v, want reason signature", events)
	}
	if fk.refreshed != 1 {
		t.Errorf("refreshed = %d, want 1", fk.refreshed)
	}
}

func TestCFAccess_RotatedKeyAccepted(t *testing.T) {
	m, kA, kidA, _ := setup(t)
	u, _ := m.CreateUser("ana@clinica.cl", "Ana", "")

	kB, _ := rsa.GenerateKey(rand.Reader, 2048)
	kidB := "key-b"

	fk := &fakeKeys{
		set: parseSet(t, kidA, kA),
		hasFresh: true,
		fresh: parseSet(t, kidB, kB),
	}
	cfa := createCFA(t, m, fk, nil)

	now := time.Now().Unix()
	tok := token(t, kidB, kB, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	p, handled := cfa.IdentifyRequest(ctx)

	if !handled || p.UserID != u.Id {
		t.Errorf("handled = %v, UserID = %q, want handled with %q", handled, p.UserID, u.Id)
	}
	if fk.refreshed != 1 {
		t.Errorf("refreshed = %d, want 1", fk.refreshed)
	}
}

func TestCFAccess_KeysUnavailable(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }
	fk := &fakeKeys{err: errors.New("down")}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "keys_unavailable" {
		t.Errorf("events = %+v, want reason keys_unavailable", events)
	}
}

func TestCFAccess_SuspendedUser(t *testing.T) {
	m, k, kid, _ := setup(t)
	var events []auth.SecurityEvent
	notify := func(e auth.SecurityEvent) { events = append(events, e) }

	u, _ := m.CreateUser("ana@clinica.cl", "Ana", "")
	m.SuspendUser(u.Id)

	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, notify)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	cfa.IdentifyRequest(ctx)

	if len(events) != 1 || events[0].Reason != "inactive" {
		t.Errorf("events = %+v, want reason inactive", events)
	}
}

func TestCFAccess_ThroughAuthority(t *testing.T) {
	m, k, kid, _ := setup(t)
	u, _ := m.CreateUser("ana@clinica.cl", "Ana", "")

	fk := &fakeKeys{set: parseSet(t, kid, k)}
	cfa := createCFA(t, m, fk, nil)
	m.Enable(cfa)

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	ctx := &mock.Context{InMethod: "GET", InPath: "/api/x"}
	ctx.SetHeader(cfaccess.HeaderAssertion, tok)

	var authenticatedUser string
	handler := func(c router.Context) {
		authenticatedUser = c.UserID()
	}
	wrapped := m.Authenticate()
	wrapped(handler)(ctx)

	if authenticatedUser != u.Id {
		t.Errorf("recorded id = %q, want %q", authenticatedUser, u.Id)
	}
}

func TestKeySource_CachesAndThrottles(t *testing.T) {
	k, _ := rsa.GenerateKey(rand.Reader, 2048)
	kid := "key-remote"

	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(jwksOf(kid, k)))
	}))
	defer srv.Close()

	ks := cfaccess.NewKeySource(srv.URL)

	set1, err := ks.Keys()
	if err != nil {
		t.Fatalf("Keys 1: %v", err)
	}
	set2, err := ks.Keys()
	if err != nil {
		t.Fatalf("Keys 2: %v", err)
	}
	set3, err := ks.Refresh()
	if err != nil {
		t.Fatalf("Refresh: %v", err)
	}

	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}

	now := time.Now().Unix()
	tok := token(t, kid, k, payload("cf-sub-1", "ana@clinica.cl", []string{aud}, now, now+600))

	for i, s := range []jwt.KeySet{set1, set2, set3} {
		_, out, _ := jwt.VerifyRS256(s, tok)
		if out != jwt.Valid {
			t.Errorf("set %d didn't verify token: %v", i+1, out)
		}
	}
}

func TestKeySource_ErrorStatus(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(500)
	}))
	defer srv.Close()

	ks := cfaccess.NewKeySource(srv.URL)

	_, err := ks.Keys()
	if err == nil || len(err.Error()) < len(cfaccess.ErrMsgKeysStatus) || err.Error()[:len(cfaccess.ErrMsgKeysStatus)] != cfaccess.ErrMsgKeysStatus {
		t.Errorf("Keys() error = %v, want to start with %s", err, cfaccess.ErrMsgKeysStatus)
	}

	_, err2 := ks.Keys()
	if err2 == nil {
		t.Errorf("Keys() 2 error = nil, want err")
	}

	if hits != 1 {
		t.Errorf("hits = %d, want 1", hits)
	}
}

func TestCertsURL(t *testing.T) {
	want := "https://acme.cloudflareaccess.com/cdn-cgi/access/certs"
	if got := cfaccess.CertsURL("acme.cloudflareaccess.com"); got != want {
		t.Errorf("CertsURL = %q, want %q", got, want)
	}
}
