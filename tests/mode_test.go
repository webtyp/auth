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
	"webtyp.com/ddl"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/router/mock"
	"webtyp.com/securityevent"
)

// staffDevices is the app's register of trusted devices (in production, a staff module): it answers which device
// each person may use and records the first administrator's device.
type staffDevices struct {
	trusted    fakeTrustedIP
	firstAdmin [4]string // userID, rut, name, ip
}

func (d *staffDevices) ModelName() string                  { return "staff" }
func (d *staffDevices) IsTrustedIP(userID, ip string) bool { return d.trusted.IsTrustedIP(userID, ip) }
func (d *staffDevices) RegisterFirstAdmin(userID, rut, name, ip string) error {
	d.firstAdmin = [4]string{userID, rut, name, ip}
	d.trusted.allowed[userID] = ip
	return nil
}

// notDevices is a built module that is not a register of devices.
type notDevices struct{}

func (notDevices) ModelName() string { return "catalog" }

var staffDefinition = model.ModuleDefinition{Name: "staff"}

// modeEnv is authority plus the pieces the composition root adds to Ports.
type modeEnv struct {
	m       *authority.Module
	pub     *mockPublisher
	admins  []string
	built   model.ModuleNaming
	logged  []string
	hasErr  error
	limiter auth.RateLimiter
	r       *mock.Router
}

func newModeEnv(t *testing.T) *modeEnv {
	t.Helper()
	db := newTestDB(t)
	if err := passkey.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatal(err)
	}
	pub := &mockPublisher{}
	m, err := authority.New(db, auth.Config{IDs: testIDs, Events: pub})
	if err != nil {
		t.Fatal(err)
	}
	return &modeEnv{m: m, pub: pub, r: &mock.Router{}}
}

func (e *modeEnv) ports() auth.Ports {
	p := e.m.Ports()
	p.MakeAdmin = func(userID string) error { e.admins = append(e.admins, userID); return nil }
	p.HasAdmin = func() (bool, error) { return len(e.admins) > 0, e.hasErr }
	p.Built = func(def model.ModuleDefinition) (model.ModuleNaming, error) { return e.built, nil }
	if e.limiter == nil {
		e.limiter = auth.NewIPLimiter(3, 900, 900)
	}
	p.Limiter = e.limiter
	p.Log = func(args ...any) {
		for _, a := range args {
			if s, ok := a.(string); ok {
				e.logged = append(e.logged, s)
			}
		}
	}
	return p
}

func (e *modeEnv) mount(t *testing.T, mode auth.Mode) {
	t.Helper()
	a, err := mode.Build(e.ports())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	e.m.Enable(a)
	e.r.Configure(mock.Config{})
	e.m.MountAPI(e.r)
}

func TestTrustedIPMode_RefusesWithoutDevices(t *testing.T) {
	e := newModeEnv(t)
	if _, err := (trustedip.Mode{}).Build(e.ports()); err != trustedip.ErrNoDevices {
		t.Fatalf("err = %v, want ErrNoDevices", err)
	}
}

func TestTrustedIPMode_RefusesAModuleThatIsNotDevices(t *testing.T) {
	e := newModeEnv(t)
	e.built = notDevices{}
	if _, err := (trustedip.Mode{Devices: staffDefinition}).Build(e.ports()); err != trustedip.ErrNotDevices {
		t.Fatalf("err = %v, want ErrNotDevices", err)
	}
}

func TestTrustedIPMode_RefusesWithoutAdministratorPieces(t *testing.T) {
	e := newModeEnv(t)
	if _, err := (trustedip.Mode{Devices: staffDefinition}).Build(e.m.Ports()); err != trustedip.ErrPortsIncomplete {
		t.Fatalf("err = %v, want ErrPortsIncomplete", err)
	}
}

func TestTrustedIPMode_FirstAdminGetsDeviceRoleAndSession(t *testing.T) {
	e := newModeEnv(t)
	devices := &staffDevices{trusted: fakeTrustedIP{allowed: map[string]string{}}}
	e.built = devices
	e.mount(t, trustedip.Mode{Devices: staffDefinition})

	get := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	get.SetValue(router.ContextKeyNetwork, router.NetworkLocal)
	e.r.Invoke("GET", auth.PathSetup, get)
	if get.Status != 200 || string(get.ResponseBody()) != `{"required":true}` {
		t.Fatalf("GET on a new install = %d %s, want 200 required", get.Status, get.ResponseBody())
	}

	post := &mock.Context{InMethod: "POST", InPath: auth.PathSetup, InBody: []byte(`{"code":"12345678-5","name":"Ana"}`)}
	post.SetValue(router.ContextKeyNetwork, router.NetworkLocal)
	post.SetHeader("Content-Type", "application/json")
	post.SetValue("RemoteAddr", "192.168.1.20:5000")
	e.r.Invoke("POST", auth.PathSetup, post)
	if post.Status != 302 {
		t.Fatalf("POST setup = %d %s, want 302", post.Status, post.ResponseBody())
	}
	if len(e.admins) != 1 || devices.firstAdmin[0] != e.admins[0] || devices.firstAdmin[3] != "192.168.1.20" {
		t.Fatalf("admins %v, device %v: the administrator must get the role and the device it set up from", e.admins, devices.firstAdmin)
	}
	assertSecurityEvent(t, e.pub, 0, securityevent.AdminCreated, "")

	done := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	done.SetValue(router.ContextKeyNetwork, router.NetworkLocal)
	e.r.Invoke("GET", auth.PathSetup, done)
	if string(done.ResponseBody()) != `{"required":false}` {
		t.Fatalf("GET after setup = %s, want required false", done.ResponseBody())
	}
}

func TestTrustedIPMode_SetupIsHiddenFromTheInternet(t *testing.T) {
	e := newModeEnv(t)
	e.built = &staffDevices{trusted: fakeTrustedIP{allowed: map[string]string{}}}
	e.mount(t, trustedip.Mode{Devices: staffDefinition})
	get := &mock.Context{InMethod: "GET", InPath: auth.PathSetup}
	get.SetValue(router.ContextKeyNetwork, router.NetworkInternet)
	e.r.Invoke("GET", auth.PathSetup, get)
	if get.Status != 404 {
		t.Fatalf("GET from the Internet = %d, want 404", get.Status)
	}
}

func TestPasskeyMode_HasTables(t *testing.T) {
	var mode auth.Mode = passkey.Mode{Origin: "https://app.example.com"}
	if _, ok := mode.(auth.ModeWithTables); !ok {
		t.Fatal("passkey.Mode keeps the credentials, so it must implement auth.ModeWithTables")
	}
}

// setupCode is the code passkey.Mode wrote in the log.
func (e *modeEnv) setupCode(t *testing.T) string {
	t.Helper()
	for _, s := range e.logged {
		if len(s) == 11 && s[5] == '-' {
			return s
		}
	}
	t.Fatalf("no setup code in the log: %v", e.logged)
	return ""
}

func (e *modeEnv) setupOptions(code string) *mock.Context {
	ctx := &mock.Context{InMethod: "POST", InPath: passkey.PathSetupOptions, InBody: []byte(`{"code":"` + code + `","name":"Ana"}`)}
	ctx.SetHeader("Content-Type", "application/json")
	e.r.Invoke("POST", passkey.PathSetupOptions, ctx)
	return ctx
}

func TestPasskeyMode_NoAdministratorWritesASetupCode(t *testing.T) {
	e := newModeEnv(t)
	e.mount(t, passkey.Mode{Origin: "https://app.example.com"})
	_ = e.setupCode(t)
	get := &mock.Context{InMethod: "GET", InPath: passkey.PathSetup}
	e.r.Invoke("GET", passkey.PathSetup, get)
	if string(get.ResponseBody()) != `{"required":true}` {
		t.Fatalf("GET = %s, want required true", get.ResponseBody())
	}
}

func TestPasskeyMode_AdministratorExistsNoCode(t *testing.T) {
	e := newModeEnv(t)
	e.admins = []string{"someone"}
	e.mount(t, passkey.Mode{Origin: "https://app.example.com"})
	if len(e.logged) != 0 {
		t.Fatalf("logged %v, want nothing when an administrator exists", e.logged)
	}
	if ctx := e.setupOptions("00000-00000"); ctx.Status != 404 {
		t.Fatalf("setup options = %d, want 404 (no setup mounted)", ctx.Status)
	}
}

func TestPasskeySetup_WrongCodeLocksAfterFiveTries(t *testing.T) {
	e := newModeEnv(t)
	e.mount(t, passkey.Mode{Origin: "https://app.example.com"})
	code := e.setupCode(t)
	for i := 0; i < 5; i++ {
		if ctx := e.setupOptions("00000-00000"); ctx.Status != 401 {
			t.Fatalf("wrong code try %d = %d, want 401", i+1, ctx.Status)
		}
	}
	assertSecurityEvent(t, e.pub, 0, securityevent.LoginFailed, "wrong setup code")
	if ctx := e.setupOptions(code); ctx.Status != 404 {
		t.Fatalf("right code after five wrong tries = %d, want 404 (locked until restart)", ctx.Status)
	}
}

func TestPasskeySetup_RightCodeCreatesTheAdministrator(t *testing.T) {
	e := newModeEnv(t)
	e.mount(t, passkey.Mode{Origin: "https://app.example.com"})
	opt := e.setupOptions(e.setupCode(t))
	body := string(opt.ResponseBody())
	if !strings.Contains(body, `"challenge":"`) {
		t.Fatalf("options = %d %s, want registration options", opt.Status, body)
	}
	start := strings.Index(body, `"challenge":"`) + len(`"challenge":"`)
	chal, _ := base64.URLDecode(body[start : start+strings.Index(body[start:], `"`)])
	spki, _, _ := asym.GenerateKeyPair()
	resp := buildCreateResponse("app.example.com", chal, []byte("https://app.example.com"), spki, 0, []byte("admin-cred"), 0x45)

	fin := &mock.Context{InMethod: "POST", InPath: passkey.PathSetup, InBody: []byte(base64.URLEncode([]byte(resp)))}
	e.r.Invoke("POST", passkey.PathSetup, fin)
	if fin.Status != 204 {
		t.Fatalf("finish = %d %s, want 204", fin.Status, fin.ResponseBody())
	}
	if len(e.admins) != 1 {
		t.Fatalf("admins = %v, want the new person", e.admins)
	}
	if _, ok := fin.Cookie("__Host-stepup"); !ok {
		t.Fatal("the new administrator must be signed in")
	}
	assertSecurityEvent(t, e.pub, 0, securityevent.AdminCreated, "")
	if ctx := e.setupOptions("00000-00000"); ctx.Status != 404 {
		t.Fatalf("setup after it finished = %d, want 404", ctx.Status)
	}
}

func TestDeleteIdentity_RemovesTheOnlyIdentity(t *testing.T) {
	e := newModeEnv(t)
	u, err := e.m.CreateUser("", "Ana", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedip.RegisterRUT(e.m, u.Id, "12345678-5"); err != nil {
		t.Fatal(err)
	}
	if err := trustedip.UnregisterRUT(e.m, u.Id); err != nil {
		t.Fatalf("UnregisterRUT: %v", err)
	}
	if _, err := e.m.IdentityFor(u.Id, auth.ProviderTrustedIP); !auth.IsNotFound(err) {
		t.Fatalf("identity after unregister: err %v, want not found", err)
	}
	if err := trustedip.UnregisterRUT(e.m, u.Id); !auth.IsNotFound(err) {
		t.Fatalf("second unregister: err %v, want not found", err)
	}
}

func TestMigrateModes_CreatesOnlyTheChosenModesTables(t *testing.T) {
	db := newTestDB(t)
	run := auth.MigrateModes([]auth.Mode{trustedip.Mode{Devices: staffDefinition}, passkey.Mode{Origin: "https://app.example.com"}})
	if err := run(db.RawConn(), db.RawConn().(ddl.Compiler)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.Create(&passkey.PasskeyChallenge{Id: "c1", UserId: "u1", Purpose: "verify", ExpiresAt: 1}); err != nil {
		t.Fatalf("the passkey table must exist after MigrateModes: %v", err)
	}
}

// TestModes_ShareOneLimiter: three failed RUT sign-ins from an IP also block an anonymous passkey sign-in from it
// (ARCHITECTURE/SECURITY_OBSERVABILITY D5): changing mode does not give an attacker more tries.
func TestModes_ShareOneLimiter(t *testing.T) {
	e := newModeEnv(t)
	e.built = &staffDevices{trusted: fakeTrustedIP{allowed: map[string]string{}}}
	e.admins = []string{"someone"}
	for _, mode := range []auth.Mode{trustedip.Mode{Devices: staffDefinition}, passkey.Mode{Origin: "https://app.example.com"}} {
		a, err := mode.Build(e.ports())
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		e.m.Enable(a)
	}
	e.r.Configure(mock.Config{})
	e.m.MountAPI(e.r)

	for i := 0; i < 3; i++ {
		ctx := &mock.Context{InMethod: "POST", InPath: auth.PathLoginRUT, InBody: []byte(`{"code":"11111111-1"}`)}
		ctx.SetValue(router.ContextKeyNetwork, router.NetworkLocal)
		ctx.SetValue("RemoteAddr", "10.0.0.66:4000")
		e.r.Invoke("POST", auth.PathLoginRUT, ctx)
	}
	from := len(e.pub.SecurityEvents())
	ver := &mock.Context{InMethod: "POST", InPath: passkey.PathVerify, InBody: []byte(`{}`)}
	ver.SetValue("RemoteAddr", "10.0.0.66:4000")
	e.r.Invoke("POST", passkey.PathVerify, ver)
	if ver.Status != 401 {
		t.Fatalf("passkey after three failed RUT tries = %d, want 401", ver.Status)
	}
	assertSecurityEvent(t, e.pub, from, securityevent.RateLimited, "")
}
