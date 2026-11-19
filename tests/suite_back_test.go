//go:build !wasm

package tests

import (
	"strings"
	"testing"

	"webtyp.com/auth"
	"webtyp.com/auth/authority"
	emailpassword "webtyp.com/auth/email_password"
	"webtyp.com/auth/oauth2"
	trustedip "webtyp.com/auth/trusted_ip"
	"webtyp.com/crud"
	"webtyp.com/crypto/bcrypt"
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/router/mock"
	"webtyp.com/sqlite"
)

func newTestDB(t *testing.T) *orm.DB {
	conn, err := sqlite.Open(":memory:")
	if err != nil {
		t.Fatalf("failed to open db: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
	})
	db := orm.New(conn)
	if err := authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("failed to migrate schema: %v", err)
	}
	return db
}

func RunUserTests(t *testing.T) {
	emailpassword.DefaultHashCost = bcrypt.MinCost
	t.Run("TestInit", testInit)
	t.Run("TestCRUD", testCRUD)
	t.Run("TestAuth", testAuth)
	t.Run("TestSessions", testSessions)
	t.Run("TestOAuth", testOAuth)
	t.Run("TestLAN", testLAN)
}

func testInit(t *testing.T) {
	db := newTestDB(t)
	cfg := auth.Config{
		IDs:        testIDs,
		Events:     &mockPublisher{},
		CookieName: "test_session",
		TokenTTL:   3600,
	}
	m, err := authority.New(db, cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	m.Enable(emailpassword.New(m, m, m.Ports().Report))
	_ = m // to be used later
}

// userHandler adapts the kept methods and the crud operations of the user entity to the small Create/Read/Update/Delete
// shape the older tests of this suite were written against.
type userHandler struct{ m *authority.Module }

func getHandler(m *authority.Module, name string) *userHandler { return &userHandler{m: m} }

func (h *userHandler) call(action model.Action, args model.Encodable) error {
	var callErr error
	crud.LoopbackActingAs(nil, "admin-1", h.m).Call(
		router.Operation{Module: authority.ModelName, Entity: "user", Action: action},
		args, nil, func(err error) { callErr = err })
	return callErr
}

func (h *userHandler) Create(payload any) (any, error) {
	u := payload.(auth.User)
	return h.m.CreateUser(u.Email, u.Name, u.Phone)
}

func (h *userHandler) Read(id string) (any, error) { return h.m.GetUser(id) }

func (h *userHandler) Update(payload any) (any, error) {
	u := payload.(auth.User)
	err := h.call(model.Update, &crud.UpdateArgs{IDs: []string{u.Id}, Fields: []string{"name", "phone"}, Record: &authority.User{Name: u.Name, Phone: u.Phone}})
	return u, err
}

func (h *userHandler) Delete(id string) error {
	return h.call(model.Delete, &crud.DeleteArgs{IDs: []string{id}})
}

func testCRUD(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}

	userCRUD := getHandler(m, "users")
	if userCRUD == nil {
		t.Fatal("userCRUD handler not found")
	}

	res, err := userCRUD.Create(auth.User{Email: "test@example.com", Name: "Test User", Phone: "+56911111111"})
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	u := res.(auth.User)
	if u.Email != "test@example.com" {
		t.Errorf("expected email 'test@example.com', got '%s'", u.Email)
	}

	res2, err := userCRUD.Read(u.Id)
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	u2 := res2.(auth.User)
	if u2.Id != u.Id {
		t.Errorf("expected ID '%s', got '%s'", u.Id, u2.Id)
	}

	u2.Name = "Updated Name"
	res3, err := userCRUD.Update(u2)
	if err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}
	u3 := res3.(auth.User)
	if u3.Name != "Updated Name" {
		t.Errorf("expected Name 'Updated Name', got '%s'", u3.Name)
	}
}

func testAuth(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(emailpassword.New(m, m, m.Ports().Report))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "auth@example.com", Name: "Auth User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := emailpassword.SetPassword(m, u.Id, "password123", nil); err != nil {
		t.Fatalf("SetPassword failed: %v", err)
	}

	ep := emailpassword.New(m, m, m.Ports().Report)
	id, err := ep.Login(&mock.Context{}, []byte(`{"email":"auth@example.com","password":"password123"}`))
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if id != u.Id {
		t.Errorf("Login returned wrong user")
	}

	if _, err := ep.Login(&mock.Context{}, []byte(`{"email":"auth@example.com","password":"wrongpass"}`)); err == nil {
		t.Errorf("a wrong password must be refused")
	}

	if err := emailpassword.CheckPassword(m, u.Id, "password123"); err != nil {
		t.Fatalf("VerifyPassword failed: %v", err)
	}
}

func testSessions(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, TokenTTL: 3600})
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(emailpassword.New(m, m, m.Ports().Report))

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "sess@example.com", Name: "Sess User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	sess, err := m.CreateSession(u.Id, "127.0.0.1", "TestAgent", testPolicy)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	// Get Session
	s2, err := m.GetSession(sess.Id)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if s2.UserId != u.Id {
		t.Errorf("Session user ID mismatch")
	}

	// Instant expire via SQL
	if _, err := db.RawConn().Exec("UPDATE session SET expires_at = 0 WHERE id = ?", sess.Id); err != nil {
		t.Fatalf("failed to expire session in DB: %v", err)
	}

	// Re-init to flush memory cache
	m, _ = authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, TokenTTL: 3600})
	m.Enable(emailpassword.New(m, m, m.Ports().Report))

	_, err = m.GetSession(sess.Id)
	if err != auth.ErrSessionExpired {
		t.Errorf("expected ErrSessionExpired, got %v", err)
	}
}

type MockProvider struct {
	NameVal         string
	ExchangeCodeVal auth.OAuthToken
	UserInfoVal     auth.OAuthUserInfo
}

func (m *MockProvider) Name() string                    { return m.NameVal }
func (m *MockProvider) AuthCodeURL(state string) string { return "http://mock/" + state }
func (m *MockProvider) ExchangeCode(code string) (auth.OAuthToken, error) {
	return m.ExchangeCodeVal, nil
}
func (m *MockProvider) GetUserInfo(token auth.OAuthToken) (auth.OAuthUserInfo, error) {
	return m.UserInfoVal, nil
}

func testOAuth(t *testing.T) {
	db := newTestDB(t)
	mockP := &MockProvider{
		NameVal:         "mock",
		ExchangeCodeVal: auth.OAuthToken{AccessToken: "mocktoken"},
		UserInfoVal:     auth.OAuthUserInfo{ID: "mockid", Email: "mock@example.com", Name: "Mock User"},
	}

	cfg := auth.Config{IDs: testIDs, Events: &mockPublisher{}}
	m, err := authority.New(db, cfg)
	if err != nil {
		t.Fatal(err)
	}
	m.Enable(oauth2.New(m, m, m, m.Ports().Report, []auth.OAuthProvider{mockP}))

	r := &mock.Router{}
	m.MountAPI(r)

	// Simulate hitting GET /oauth/mock
	ctxBegin := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/mock",
	}
	r.Invoke("GET", "/oauth/mock", ctxBegin)
	if ctxBegin.Status != 302 {
		t.Fatalf("expected status 302, got %d", ctxBegin.Status)
	}
	loc := ctxBegin.GetHeader("Location")
	if !strings.HasPrefix(loc, "http://mock/") {
		t.Fatalf("expected redirect to mock URL, got %s", loc)
	}
	state := strings.TrimPrefix(loc, "http://mock/")

	// Simulate hitting GET /oauth/callback/mock
	ctxCallback := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/mock?state=" + state + "&code=mockcode",
	}
	if c, ok := ctxBegin.Cookie("oauth_nonce"); ok {
		ctxCallback.SetCookie(c)
	}
	r.Invoke("GET", "/oauth/callback/mock", ctxCallback)
	if ctxCallback.Status != 302 {
		t.Fatalf("expected callback status 302, got %d", ctxCallback.Status)
	}
	if ctxCallback.GetHeader("Location") != auth.PathAfterLogin {
		t.Errorf("expected redirect after login to %s, got %s", auth.PathAfterLogin, ctxCallback.GetHeader("Location"))
	}

	// Verify user got created
	u, err := m.UserByEmail("mock@example.com")
	if err != nil {
		t.Fatalf("expected user mock@example.com to be created: %v", err)
	}
	if u.Name != "Mock User" {
		t.Errorf("expected name 'Mock User', got %s", u.Name)
	}

	// Second login (existing user)
	ctxBegin2 := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/mock",
	}
	r.Invoke("GET", "/oauth/mock", ctxBegin2)
	loc2 := ctxBegin2.GetHeader("Location")
	state2 := strings.TrimPrefix(loc2, "http://mock/")

	ctxCallback2 := &mock.Context{
		InMethod: "GET",
		InPath:   "/oauth/callback/mock?state=" + state2 + "&code=mockcode",
	}
	if c, ok := ctxBegin2.Cookie("oauth_nonce"); ok {
		ctxCallback2.SetCookie(c)
	}
	r.Invoke("GET", "/oauth/callback/mock", ctxCallback2)
	if ctxCallback2.Status != 302 {
		t.Fatalf("expected callback 2 status 302, got %d", ctxCallback2.Status)
	}

	// Verify we still have the same user
	u2, err := m.UserByEmail("mock@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if u2.Id != u.Id {
		t.Errorf("expected same user ID, got %s vs %s", u.Id, u2.Id)
	}
}

func testLAN(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}, TrustProxy: true})
	if err != nil {
		t.Fatal(err)
	}
	trusted := &fakeTrustedIP{allowed: map[string]string{}}
	ti := trustedip.New(m, trusted, m, m.Ports().Report, true)
	m.Enable(ti)

	userCRUD := getHandler(m, "users")
	res, err := userCRUD.Create(auth.User{Email: "lan@example.com", Name: "LAN User"})
	if err != nil {
		t.Fatal(err)
	}
	u := res.(auth.User)

	if err := trustedip.RegisterRUT(m, u.Id, "12345678-5"); err != nil {
		t.Fatalf("RegisterRUT failed: %v", err)
	}
	trusted.allowed[u.Id] = "192.168.1.10"
	body := []byte(`{"code":"12345678-5"}`)

	ctx := &mock.Context{}
	ctx.SetValue("RemoteAddr", "192.168.1.10:1234")
	if id, err := ti.Login(ctx, body); err != nil || id != u.Id {
		t.Fatalf("Login from the trusted device: id %q err %v", id, err)
	}

	if _, err := ti.Login(ctx, []byte(`{"code":"123"}`)); err == nil {
		t.Errorf("an invalid RUT must be refused")
	}

	ctxW := &mock.Context{}
	ctxW.SetValue("RemoteAddr", "10.0.0.1:1234")
	if _, err := ti.Login(ctxW, body); err == nil {
		t.Errorf("a device that is not trusted must be refused")
	}

	ctxP := &mock.Context{}
	ctxP.SetValue("RemoteAddr", "10.0.0.1:1234")
	ctxP.SetHeader("X-Forwarded-For", "192.168.1.10")
	if id, err := ti.Login(ctxP, body); err != nil || id != u.Id {
		t.Fatalf("Login behind a trusted proxy: id %q err %v", id, err)
	}

	delete(trusted.allowed, u.Id)
	if _, err := ti.Login(ctxP, body); err == nil {
		t.Errorf("a device removed from the register must be refused")
	}

	trusted.allowed[u.Id] = "192.168.1.10"
	if err := trustedip.UnregisterRUT(m, u.Id); err != nil {
		t.Fatalf("UnregisterRUT failed: %v", err)
	}
	if _, err := ti.Login(ctxP, body); err == nil {
		t.Errorf("a RUT removed from the person must be refused")
	}
}

func setupModule(t *testing.T) *authority.Module {
	db := newTestDB(t)
	m, _ := authority.New(db, auth.Config{IDs: testIDs, Events: &mockPublisher{}})
	m.Enable(emailpassword.New(m, m, m.Ports().Report))
	return m
}
