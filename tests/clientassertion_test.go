//go:build !wasm

package tests

import (
	"errors"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/clientassertion"
	"webtyp.com/crypto/asym"
	"webtyp.com/ddl"
	"webtyp.com/jwt"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

type fakeClientKeys struct {
	keys map[string][]byte
}

func (f *fakeClientKeys) ClientPublicKey(clientID string) ([]byte, error) {
	if k, ok := f.keys[clientID]; ok {
		return k, nil
	}
	return nil, errors.New("unknown client")
}

func TestClientAssertion(t *testing.T) {
	db := newTestDB(t)
	if err := clientassertion.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatal(err)
	}

	const audience = "https://iam.velty.cl"
	const clientID = "proj_misitio"

	pub1, priv1, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, priv2, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	keys := &fakeClientKeys{
		keys: map[string][]byte{
			clientID: pub1,
		},
	}

	// Constructor validation
	if _, err := clientassertion.New(db, keys, "", nil); err == nil || err.Error() != clientassertion.ErrMsgEmptyAudience {
		t.Errorf("expected ErrMsgEmptyAudience, got %v", err)
	}

	var events []auth.SecurityEvent
	ca, err := clientassertion.New(db, keys, audience, func(ev auth.SecurityEvent) {
		events = append(events, ev)
	})
	if err != nil {
		t.Fatal(err)
	}
	if ca.Name() != "client_assertion" {
		t.Errorf("unexpected Name: %s", ca.Name())
	}
	ca.Mount(nil)

	// C1: no Authorization header -> not handled
	ctx := &mock.Context{InMethod: "POST", InPath: "/api/token"}
	if p, handled := ca.IdentifyRequest(ctx); handled || p.UserID != "" {
		t.Errorf("expected unhandled zero principal, got %+v, %v", p, handled)
	}

	expectReject := func(t *testing.T, tok, method, path, wantReason string) {
		t.Helper()
		events = nil
		c := &mock.Context{InMethod: method, InPath: path}
		c.SetHeader("Authorization", "Bearer "+tok)
		p, handled := ca.IdentifyRequest(c)
		if !handled || p.UserID != "" {
			t.Errorf("expected handled anonymous rejection for %s, got %+v, handled=%v", wantReason, p, handled)
		}
		if len(events) != 1 || events[0].Type != auth.EventClientAssertionRejected || events[0].Reason != wantReason {
			t.Errorf("expected EventClientAssertionRejected(%q), got %+v", wantReason, events)
		}
	}

	// malformed
	expectReject(t, "not-a-jwt", "POST", "/api/token", "malformed")

	// unknown_client
	aUnknown, err := jwt.NewClientAssertion("unknown_proj", audience, "POST", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	tokUnknown, err := jwt.SignClientAssertion(priv1, aUnknown)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokUnknown, "POST", "/api/token", "unknown_client")

	// signature mismatch
	aSig, err := jwt.NewClientAssertion(clientID, audience, "POST", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	tokSig, err := jwt.SignClientAssertion(priv2, aSig)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokSig, "POST", "/api/token", "signature")

	// expired
	aExp, err := jwt.NewClientAssertion(clientID, audience, "POST", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	aExp.Iat = 1000
	aExp.Exp = 1001
	tokExp, err := jwt.SignClientAssertion(priv1, aExp)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokExp, "POST", "/api/token", "expired")

	// wrong audience
	aAud, err := jwt.NewClientAssertion(clientID, "https://other.velty.cl", "POST", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	tokAud, err := jwt.SignClientAssertion(priv1, aAud)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokAud, "POST", "/api/token", "audience")

	// wrong method (binding)
	aMethod, err := jwt.NewClientAssertion(clientID, audience, "GET", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	tokMethod, err := jwt.SignClientAssertion(priv1, aMethod)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokMethod, "POST", "/api/token", "binding")

	// wrong path (binding)
	aPath, err := jwt.NewClientAssertion(clientID, audience, "POST", audience+"/api/other")
	if err != nil {
		t.Fatal(err)
	}
	tokPath, err := jwt.SignClientAssertion(priv1, aPath)
	if err != nil {
		t.Fatal(err)
	}
	expectReject(t, tokPath, "POST", "/api/token", "binding")

	// Valid assertion -> handled, UserID == clientID, SingleFactor; second use -> replay
	aValid, err := jwt.NewClientAssertion(clientID, audience, "POST", audience+"/api/token")
	if err != nil {
		t.Fatal(err)
	}
	tokValid, err := jwt.SignClientAssertion(priv1, aValid)
	if err != nil {
		t.Fatal(err)
	}
	validCtx := &mock.Context{InMethod: "POST", InPath: "/api/token"}
	validCtx.SetHeader("Authorization", "Bearer "+tokValid)
	p, handled := ca.IdentifyRequest(validCtx)
	if !handled || p.UserID != clientID || p.Assurance != model.AssuranceSingleFactor {
		t.Fatalf("expected valid client principal, got %+v, handled=%v", p, handled)
	}

	// Replay with same token
	expectReject(t, tokValid, "POST", "/api/token", "replay")

	// notify == nil must not panic
	caNilNotify, err := clientassertion.New(db, keys, audience, nil)
	if err != nil {
		t.Fatal(err)
	}
	badCtx := &mock.Context{InMethod: "POST", InPath: "/api/token"}
	badCtx.SetHeader("Authorization", "Bearer invalid")
	if _, h := caNilNotify.IdentifyRequest(badCtx); !h {
		t.Errorf("expected handled=true on invalid bearer with nil notify")
	}

	// Cookie ignored on a machine request: valid session cookie + invalid bearer -> anonymous through Authenticate()
	m, err := authority.New(db, auth.Config{IDs: testIDs})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(ca)
	u, err := m.CreateUser("human@test.com", "Human", "")
	if err != nil {
		t.Fatal(err)
	}
	sess, err := m.CreateSession(u.Id, "127.0.0.1", "ua", testPolicy)
	if err != nil {
		t.Fatal(err)
	}

	reqCtx := &mock.Context{InMethod: "POST", InPath: "/api/token"}
	reqCtx.SetCookie(router.Cookie{Name: "__Host-session", Value: sess.Id})
	reqCtx.SetHeader("Authorization", "Bearer invalid")

	var authedUser string
	m.Authenticate()(func(c router.Context) {
		authedUser = c.UserID()
	})(reqCtx)
	if authedUser != "" {
		t.Errorf("expected session cookie to be ignored on machine request, got userID=%q", authedUser)
	}
}
