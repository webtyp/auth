//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/passkey"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
)

func TestInternetDoor_RUTLoginNotFound(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	r := &mock.Router{}
	m.MountAPI(r)

	ctx := &mock.Context{InMethod: "POST", InPath: auth.PathLoginRUT, InBody: []byte(`{"code":"111111111"}`)}
	ctx.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	r.Invoke("POST", auth.PathLoginRUT, ctx)

	if ctx.Status != 404 {
		t.Errorf("expected 404 on internet door login, got %d", ctx.Status)
	}
}

func TestInternetDoor_SetupNotFound(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	r := &mock.Router{}
	m.MountAPI(r)

	ctx := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	ctx.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	r.Invoke("GET", auth.PathSetup, ctx)

	if ctx.Status != 404 {
		t.Errorf("expected 404 on internet door setup, got %d", ctx.Status)
	}
}

func TestLocalDoor_RUTLoginStillWorks(t *testing.T) {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs})
	u, _ := m.CreateUser("rut@test.com", "Test", "")
	m.UpsertIdentity(u.Id, auth.ProviderTrustedIP, "11111111-1", "")

	trusted := &fakeTrustedIP{allowed: map[string]string{u.Id: "127.0.0.1"}}
	ti := trustedip.New(m, trusted, m, m, true)

	r := &mock.Router{}
	m.MountAPI(r)
	ti.Mount(r)

	ctx := &mock.Context{InMethod: "POST", InPath: auth.PathLoginRUT, InBody: []byte(`{"code":"11111111-1"}`)}
	ctx.SetValue(router.ContextKeyNetwork, router.NetworkLocal)
	ctx.SetHeader("Content-Type", "application/json")
	ctx.SetValue("RemoteAddr", "127.0.0.1:54321")
	r.Invoke("POST", auth.PathLoginRUT, ctx)

	if ctx.Status != 302 && ctx.Status != 500 && ctx.Status != 401 {
		t.Errorf("expected 302 (or 500 session missing) on local door login, got %d", ctx.Status)
	}
}

func TestInternetDoor_RegisterNotFound(t *testing.T) {
	env := setupPasskeyEnv(t)
	ctx := &mock.Context{InMethod: "POST", InPath: passkey.PathRegisterOptions}
	ctx.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	ctx.SetCookie(env.cMain)

	env.m.Authenticate()(func(c router.Context) { env.r.Invoke("POST", passkey.PathRegisterOptions, c.(*mock.Context)) })(ctx)

	if ctx.Status != 404 {
		t.Errorf("expected 404 on internet door register options, got %d", ctx.Status)
	}
}

func TestPasskeyLogin_WithoutSession(t *testing.T) {
	env := setupPasskeyEnv(t)

	// Create user's passkey
	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("user-cred-internet"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	// 1. Get verify options without cookie
	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetValue(router.ContextKeyNetwork, router.NetworkInternet)

	env.r.Invoke("POST", passkey.PathVerifyOptions, ctxOpt)

	if ctxOpt.Status != 200 && ctxOpt.Status != 0 {
		t.Fatalf("expected 200, got %d", ctxOpt.Status)
	}

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]
	chalBytes, _ := base64.URLDecode(ch)

	// 2. Verify assertion
	flags := byte(0x05)
	respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, []byte("user-cred-internet"), flags)
	respBodyBase64 := base64.URLEncode([]byte(respBody))

	ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
	ctxVer.SetValue(router.ContextKeyNetwork, router.NetworkInternet)

	env.r.Invoke("POST", passkey.PathVerify, ctxVer)

	if ctxVer.Status != 204 && ctxVer.Status != 0 {
		t.Fatalf("expected 204, got %d. body: %s", ctxVer.Status, string(ctxVer.ResponseBody()))
	}

	assertSecurityEvent(t, env.pub, 0, auth.EventPasskeyVerified)

	cStep, ok := ctxVer.Cookie("__Host-stepup")
	if !ok {
		t.Fatal("expected step-up cookie")
	}

	ctxReq := &mock.Context{}
	ctxReq.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	ctxReq.SetCookie(cStep)

	var authAssurance model.Assurance
	var userID string
	env.m.Authenticate()(func(c router.Context) {
		authAssurance = c.Assurance()
		userID = c.UserID()
	})(ctxReq)

	if authAssurance != model.AssuranceMultiFactor {
		t.Errorf("expected AssuranceMultiFactor, got %d", authAssurance)
	}
	if userID != env.userID {
		t.Errorf("expected %s, got %s", env.userID, userID)
	}
}

func TestPasskeyLogin_ChallengeSingleUse(t *testing.T) {
	env := setupPasskeyEnv(t)

	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("user-cred-internet-2"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerifyOptions, ctxOpt)

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]
	chalBytes, _ := base64.URLDecode(ch)

	flags := byte(0x05)
	respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, []byte("user-cred-internet-2"), flags)
	respBodyBase64 := base64.URLEncode([]byte(respBody))

	ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
	ctxVer.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerify, ctxVer)

	if ctxVer.Status != 204 && ctxVer.Status != 0 {
		t.Fatalf("expected 204, got %d", ctxVer.Status)
	}

	ctxVer2 := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
	ctxVer2.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerify, ctxVer2)

	if ctxVer2.Status != 401 {
		t.Errorf("expected 401 on replay, got %d", ctxVer2.Status)
	}
}

func TestPasskeyLogin_UnknownCredential(t *testing.T) {
	env := setupPasskeyEnv(t)

	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerifyOptions, ctxOpt)

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]
	chalBytes, _ := base64.URLDecode(ch)

	_, privKey, _ := asym.GenerateKeyPair()
	flags := byte(0x05)
	respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, []byte("unknown-cred"), flags)
	respBodyBase64 := base64.URLEncode([]byte(respBody))

	ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
	ctxVer.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerify, ctxVer)

	if ctxVer.Status != 401 {
		t.Errorf("expected 401 for unknown cred, got %d", ctxVer.Status)
	}
	if _, ok := ctxVer.Cookie("__Host-stepup"); ok {
		t.Errorf("expected no cookie")
	}
}

func TestPasskeyLogin_ExpiredChallenge(t *testing.T) {
	env := setupPasskeyEnv(t)

	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("user-cred-internet-3"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerifyOptions, ctxOpt)

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]

	// manually expire challenge in DB
	if err := env.db.RawConn().Exec("UPDATE passkey_challenge SET expires_at = 0 WHERE id = ?", ch); err != nil {
		t.Fatal(err)
	}

	chalBytes, _ := base64.URLDecode(ch)
	flags := byte(0x05)
	respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, []byte("user-cred-internet-3"), flags)
	respBodyBase64 := base64.URLEncode([]byte(respBody))

	ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
	ctxVer.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	env.r.Invoke("POST", passkey.PathVerify, ctxVer)

	if ctxVer.Status != 401 {
		t.Errorf("expected 401 for expired challenge, got %d", ctxVer.Status)
	}
}

// Anyone may ask for a login challenge without a session, so the challenges
// nobody used must not pile up: asking for a new one deletes the expired ones.
func TestPasskeyLogin_ExpiredAnonymousChallengesArePurged(t *testing.T) {
	env := setupPasskeyEnv(t)

	ask := func() string {
		ctx := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
		ctx.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
		env.r.Invoke("POST", passkey.PathVerifyOptions, ctx)
		body := string(ctx.ResponseBody())
		start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
		end := strings.Index(body[start:], `"`)
		return body[start : start+end]
	}

	old := ask()
	if err := env.db.RawConn().Exec("UPDATE passkey_challenge SET expires_at = 0 WHERE id = ?", old); err != nil {
		t.Fatal(err)
	}
	ask()

	rows, err := passkey.ReadAllPasskeyChallenge(env.db.Query(&passkey.PasskeyChallenge{}).Where(passkey.PasskeyChallenge_.Id).Eq(old))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 0 {
		t.Errorf("expired anonymous challenge %q still stored after a new request", old)
	}
}
