//go:build !wasm

package tests

import (
	"crypto/sha256"
	"testing"

	"strings"
	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	"webtyp.com/auth/passkey"
	"webtyp.com/auth/session/cookie"
	"webtyp.com/base64"
	"webtyp.com/crypto/asym"
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/router/mock"
	"webtyp.com/webauthn/server"
)

func buildCreateResponse(rpID string, challenge, origin, spki []byte, signCount uint32, credID []byte, flags byte) string {
	cdJSON := `{"type":"webauthn.create","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`

	rpIDHash := sha256.Sum256([]byte(rpID))

	authData := make([]byte, 0, 37+16+2+len(credID))
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))

	authData = append(authData, make([]byte, 16)...)

	authData = append(authData, byte(len(credID)>>8), byte(len(credID)))
	authData = append(authData, credID...)
	authData = append(authData, spki...)

	respJSON := `{"clientDataJSON":"` + base64.URLEncode([]byte(cdJSON)) + `",` +
		`"authenticatorData":"` + base64.URLEncode(authData) + `",` +
		`"publicKeyAlgorithm":-7,` +
		`"publicKey":"` + base64.URLEncode(spki) + `","transports":["internal"]}`

	credJSON := `{"id":"` + base64.URLEncode(credID) + `",` +
		`"rawId":"` + base64.URLEncode(credID) + `",` +
		`"type":"public-key",` +
		`"response":` + respJSON + `}`

	return credJSON
}

func buildGetResponse(rpID string, challenge, origin, privKey []byte, signCount uint32, credID []byte, flags byte) string {
	cdJSON := `{"type":"webauthn.get","challenge":"` + base64.URLEncode(challenge) + `","origin":"` + string(origin) + `"}`

	rpIDHash := sha256.Sum256([]byte(rpID))

	authData := make([]byte, 0, 37)
	authData = append(authData, rpIDHash[:]...)
	authData = append(authData, flags)
	authData = append(authData, byte(signCount>>24), byte(signCount>>16), byte(signCount>>8), byte(signCount))

	clientDataHash := sha256.Sum256([]byte(cdJSON))
	msg := make([]byte, 0, len(authData)+len(clientDataHash))
	msg = append(msg, authData...)
	msg = append(msg, clientDataHash[:]...)

	sig, err := asym.Sign(msg, privKey)
	if err != nil {
		panic(err)
	}

	respJSON := `{"clientDataJSON":"` + base64.URLEncode([]byte(cdJSON)) + `",` +
		`"authenticatorData":"` + base64.URLEncode(authData) + `",` +
		`"signature":"` + base64.URLEncode(sig) + `"}`

	credJSON := `{"id":"` + base64.URLEncode(credID) + `",` +
		`"rawId":"` + base64.URLEncode(credID) + `",` +
		`"type":"public-key",` +
		`"response":` + respJSON + `}`

	return credJSON
}

type pkEnv struct {
	db     *orm.DB
	m      *authority.Module
	pk     *passkey.Module
	pub    *mockPublisher
	r      *mock.Router
	cMain  router.Cookie
	userID string
}

func setupPasskeyEnv(t *testing.T) pkEnv {
	db := newTestDB(t)
	if err := passkey.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatal(err)
	}
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
	if err != nil {
		t.Fatal(err)
	}

	u, err := m.CreateUser("passkey@test.com", "Passkey", "")
	if err != nil {
		t.Fatal(err)
	}

	mainPolicy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
	mainStrat, _ := cookie.New(m, cookie.Options{Name: "session", Domain: "", Policy: mainPolicy})
	m.SetStrategy(mainStrat)

	stepUpPolicy := auth.SessionPolicy{Absolute: 900, Idle: 300, Assurance: model.AssuranceMultiFactor}
	stepUpStrat, _ := cookie.New(m, cookie.Options{Name: "stepup", Domain: "", Policy: stepUpPolicy})
	m.SetStepUpStrategy(stepUpStrat)

	rp := server.RelyingParty{ID: "iam.velty.cl", Origin: "https://iam.velty.cl"}
	pk, err := passkey.New(db, testIDs, m, rp)
	if err != nil {
		t.Fatal(err)
	}

	r := &mock.Router{}
	m.MountAPI(r)

	pk.Mount(r)

	ctxIssueMain := &mock.Context{}
	if err := mainStrat.Issue(ctxIssueMain, u.Id); err != nil {
		t.Fatal(err)
	}
	cMain, _ := ctxIssueMain.Cookie("__Host-session")

	return pkEnv{db: db, m: m, pk: pk, pub: pub, r: r, cMain: cMain, userID: u.Id}
}

func TestPasskey_K1_K2(t *testing.T) {
	env := setupPasskeyEnv(t)

	// Create a credential for K1
	spki, _, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("cred_k1"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	t.Run("K1 - user with passkey and single-factor session calls RegisterOptions -> 401 MFA Required", func(t *testing.T) {
		ctx := &mock.Context{InMethod: "POST", InPath: passkey.PathRegisterOptions}
		ctx.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) { env.r.Invoke("POST", passkey.PathRegisterOptions, c.(*mock.Context)) })(ctx)

		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}
		if ctx.GetHeader("WWW-Authenticate") != router.ChallengeMFARequired {
			t.Errorf("expected header %q, got %q", router.ChallengeMFARequired, ctx.GetHeader("WWW-Authenticate"))
		}
	})

	t.Run("K2 - user with no passkey and old session calls RegisterOptions -> 401 Recent Login Required", func(t *testing.T) {
		env2 := setupPasskeyEnv(t) // new user, no passkey

		// Age the main session > 300s
		sess, err := env2.m.GetSession(env2.cMain.Value)
		if err != nil {
			t.Fatal(err)
		}
		age := int64(301)
		sess.CreatedAt -= age
		sess.AbsoluteAt -= age
		sess.ExpiresAt -= age
		if err := env2.db.Update(&sess, orm.Eq(auth.Session_.Id, sess.Id)); err != nil {
			t.Fatal(err)
		}

		// Flush cache by recreating
		m2, _ := authority.New(env2.db, auth.Config{IDs: testIDs})
		mainPolicy := auth.SessionPolicy{Absolute: 3600, Idle: 900, Assurance: model.AssuranceSingleFactor}
		mainStrat, _ := cookie.New(m2, cookie.Options{Name: "session", Domain: "", Policy: mainPolicy})
		m2.SetStrategy(mainStrat)

		rp := server.RelyingParty{ID: "iam.velty.cl", Origin: "https://iam.velty.cl"}
		pk, _ := passkey.New(env2.db, testIDs, m2, rp)
		r2 := &mock.Router{}
		m2.MountAPI(r2)
		pk.Mount(r2)

		ctx := &mock.Context{InMethod: "POST", InPath: passkey.PathRegisterOptions}
		ctx.SetCookie(env2.cMain)

		m2.Authenticate()(func(c router.Context) { r2.Invoke("POST", passkey.PathRegisterOptions, c.(*mock.Context)) })(ctx)

		if ctx.Status != 401 {
			t.Errorf("expected 401, got %d", ctx.Status)
		}
		if ctx.GetHeader("WWW-Authenticate") != passkey.ChallengeRecentLogin {
			t.Errorf("expected header %q, got %q", passkey.ChallengeRecentLogin, ctx.GetHeader("WWW-Authenticate"))
		}
	})
}

func TestPasskey_K3(t *testing.T) {
	env := setupPasskeyEnv(t)

	t.Run("K3 - first enrollment from fresh session succeeds and replay fails", func(t *testing.T) {
		// 1. Get options
		ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathRegisterOptions}
		ctxOpt.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathRegisterOptions, c.(*mock.Context))
		})(ctxOpt)

		if ctxOpt.Status != 200 && ctxOpt.Status != 0 {
			t.Fatalf("expected 200, got %d", ctxOpt.Status)
		}

		body := string(ctxOpt.ResponseBody())
		start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
		end := strings.Index(body[start:], `"`)
		ch := body[start : start+end]
		chalBytes, _ := base64.URLDecode(ch)
		spki, _, _ := asym.GenerateKeyPair()
		credID := []byte("new-cred-123")
		flags := byte(0x45) // UP | UV | AT

		respBody := buildCreateResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), spki, 0, credID, flags)

		// 2. Register
		ctxReg := &mock.Context{InMethod: "POST", InPath: passkey.PathRegister, InBody: []byte(base64.URLEncode([]byte(respBody)))}
		ctxReg.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathRegister, c.(*mock.Context))
		})(ctxReg)

		if ctxReg.Status != 204 && ctxReg.Status != 0 {
			t.Fatalf("expected 204, got %d. body: %s, events: %+v, www-auth: %s", ctxReg.Status, string(ctxReg.ResponseBody()), env.pub.SecurityEvents(), ctxReg.GetHeader("WWW-Authenticate"))
		}

		assertSecurityEvent(t, env.pub, 0, auth.EventPasskeyRegistered)

		// 3. Replay
		ctxReplay := &mock.Context{InMethod: "POST", InPath: passkey.PathRegister, InBody: []byte(base64.URLEncode([]byte(respBody)))}
		ctxReplay.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathRegister, c.(*mock.Context))
		})(ctxReplay)

		if ctxReplay.Status != 401 {
			t.Errorf("expected 401 on replay, got %d", ctxReplay.Status)
		}
	})
}

func TestPasskey_K4_K5(t *testing.T) {
	env := setupPasskeyEnv(t)

	// Create user's passkey
	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("user-cred"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	// 1. Get verify options
	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetCookie(env.cMain)

	env.m.Authenticate()(func(c router.Context) {
		env.r.Invoke("POST", passkey.PathVerifyOptions, c.(*mock.Context))
	})(ctxOpt)

	if ctxOpt.Status != 200 && ctxOpt.Status != 0 {
		t.Fatalf("expected 200, got %d", ctxOpt.Status)
	}

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]
	chalBytes, _ := base64.URLDecode(ch)

	t.Run("K4 - verify with another user's credential id -> 403", func(t *testing.T) {
		// Use a different credID not owned by the user
		otherCredID := []byte("other-user-cred")
		flags := byte(0x05)
		respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, otherCredID, flags)
		respBodyBase64 := base64.URLEncode([]byte(respBody))

		ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
		ctxVer.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathVerify, c.(*mock.Context))
		})(ctxVer)

		if ctxVer.Status != 403 {
			t.Errorf("expected 403, got %d", ctxVer.Status)
		}
		assertSecurityEvent(t, env.pub, 0, auth.EventPasskeyRejected)
	})

	t.Run("K5 - wrong signature -> 401 empty body", func(t *testing.T) {
		_, badPriv, _ := asym.GenerateKeyPair()
		flags := byte(0x05)
		respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), badPriv, 1, []byte("user-cred"), flags)
		respBodyBase64 := base64.URLEncode([]byte(respBody))

		ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
		ctxVer.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathVerify, c.(*mock.Context))
		})(ctxVer)

		if ctxVer.Status != 401 {
			t.Errorf("expected 401, got %d", ctxVer.Status)
		}
		if len(ctxVer.ResponseBody()) > 0 {
			t.Errorf("expected empty body, got %s", string(ctxVer.ResponseBody()))
		}

		var found auth.SecurityEvent
		events := env.pub.SecurityEvents()
		for _, e := range events {
			if e.Type == auth.EventPasskeyRejected {
				found = e
			}
		}
		if found.Type == 0 || found.Reason == "" {
			t.Errorf("expected EventPasskeyRejected with Reason set, got %+v", found)
		}
	})
}

func TestPasskey_K6_Misc(t *testing.T) {
	env := setupPasskeyEnv(t)

	// Create user's passkey
	spki, privKey, err := asym.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	credID := base64.URLEncode([]byte("user-cred-k6"))
	pubKey := base64.URLEncode(spki)
	if err := env.db.RawConn().Exec("INSERT INTO passkey_credential (id, user_id, public_key, sign_count) VALUES (?, ?, ?, ?)", credID, env.userID, pubKey, 0); err != nil {
		t.Fatal(err)
	}

	// 1. Get verify options
	ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
	ctxOpt.SetCookie(env.cMain)

	env.m.Authenticate()(func(c router.Context) {
		env.r.Invoke("POST", passkey.PathVerifyOptions, c.(*mock.Context))
	})(ctxOpt)

	body := string(ctxOpt.ResponseBody())
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	end := strings.Index(body[start:], `"`)
	ch := body[start : start+end]
	chalBytes, _ := base64.URLDecode(ch)

	t.Run("K6 - valid assertion -> 204, step-up cookie, events", func(t *testing.T) {
		flags := byte(0x05)
		respBody := buildGetResponse("iam.velty.cl", chalBytes, []byte("https://iam.velty.cl"), privKey, 1, []byte("user-cred-k6"), flags)
		respBodyBase64 := base64.URLEncode([]byte(respBody))

		ctxVer := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(respBodyBase64)}
		ctxVer.SetCookie(env.cMain)

		env.m.Authenticate()(func(c router.Context) {
			env.r.Invoke("POST", passkey.PathVerify, c.(*mock.Context))
		})(ctxVer)

		if ctxVer.Status != 204 && ctxVer.Status != 0 {
			t.Fatalf("expected 204, got %d. body: %s", ctxVer.Status, string(ctxVer.ResponseBody()))
		}

		assertSecurityEvent(t, env.pub, 0, auth.EventPasskeyVerified)

		// Check step-up cookie was issued
		cStep, ok := ctxVer.Cookie("__Host-stepup")
		if !ok {
			t.Fatal("expected step-up cookie")
		}

		// Authenticate with step-up yields AssuranceMultiFactor
		ctxReq := &mock.Context{}
		ctxReq.SetCookie(env.cMain)
		ctxReq.SetCookie(cStep)

		var authAssurance model.Assurance
		env.m.Authenticate()(func(c router.Context) {
			authAssurance = c.Assurance()
		})(ctxReq)

		if authAssurance != model.AssuranceMultiFactor {
			t.Errorf("expected AssuranceMultiFactor, got %d", authAssurance)
		}
	})

	t.Run("PathVerifyOptions no passkey -> 404", func(t *testing.T) {
		env2 := setupPasskeyEnv(t)
		ctxOpt := &mock.Context{InMethod: "POST", InPath: passkey.PathVerifyOptions}
		ctxOpt.SetCookie(env2.cMain)

		env2.m.Authenticate()(func(c router.Context) {
			env2.r.Invoke("POST", passkey.PathVerifyOptions, c.(*mock.Context))
		})(ctxOpt)

		if ctxOpt.Status != 404 {
			t.Errorf("expected 404, got %d", ctxOpt.Status)
		}
	})

	t.Run("passkey.New error checks", func(t *testing.T) {
		rp := server.RelyingParty{ID: "", Origin: "https://iam.velty.cl"}
		_, err := passkey.New(env.db, testIDs, env.m, rp)
		if err == nil {
			t.Errorf("expected error for empty RP ID")
		}
		rp2 := server.RelyingParty{ID: "iam.velty.cl", Origin: ""}
		_, err = passkey.New(env.db, testIDs, env.m, rp2)
		if err == nil {
			t.Errorf("expected error for empty RP Origin")
		}
	})

	t.Run("List/Delete require MFA", func(t *testing.T) {
		var listMFA, delMFA bool
		for _, rt := range env.r.Routes() {
			if rt.Path == passkey.PathList {
				listMFA = rt.MFA
			}
			if rt.Path == passkey.PathDelete {
				delMFA = rt.MFA
			}
		}
		if !listMFA {
			t.Errorf("PathList should require MFA")
		}
		if !delMFA {
			t.Errorf("PathDelete should require MFA")
		}
	})
}
