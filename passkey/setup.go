package passkey

import (
	"sync"

	"webtyp.com/auth"
	"webtyp.com/base64"
	"webtyp.com/crypto/hmac"
	"webtyp.com/crypto/rand"
	"webtyp.com/router"
	"webtyp.com/securityevent"
)

// First-administrator setup with a one-time code (ARCHITECTURE D81). While no administrator exists the server writes
// a code in its log; whoever presents it enrolls their passkey and becomes the administrator. Reading the log proves
// control of the server, so it works on a local network and in the cloud alike. The code serves once, and after
// maxSetupFailures wrong tries it stops working until the server restarts with a new one.
const (
	PathSetup        = "/passkey/setup"
	PathSetupOptions = "/passkey/setup/options"

	purposeSetup     = "setup"
	setupCodeDigits  = 10
	setupCodeGroup   = 5
	setupCodeSep     = "-"
	maxSetupFailures = 5

	setupRequired = `{"required":true}`
	setupDone     = `{"required":false}`

	reasonSetupCode securityevent.Reason = "wrong setup code"
)

// firstAdminSetup is the state of the one setup this process may run.
type firstAdminSetup struct {
	mu        sync.Mutex
	code      string
	failures  int
	done      bool
	pendingID string // the provisional WebAuthn user handle of the person enrolling
	name      string
	users     auth.IdentityStore
	hasAdmin  func() (bool, error)
	makeAdmin func(userID string) error
}

// newSetupCode is setupCodeDigits random digits in groups ("12345-67890").
func newSetupCode() (string, error) {
	b, err := rand.Bytes(setupCodeDigits)
	if err != nil {
		return "", err
	}
	out := make([]byte, 0, setupCodeDigits+1)
	for i, v := range b {
		if i == setupCodeGroup {
			out = append(out, setupCodeSep...)
		}
		out = append(out, '0'+v%10)
	}
	return string(out), nil
}

// open reports whether setup may run now; it answers false once done or once an administrator exists.
func (s *firstAdminSetup) open() (bool, error) {
	if s.done {
		return false, nil
	}
	exists, err := s.hasAdmin()
	if err != nil {
		return false, err
	}
	return !exists, nil
}

func (m *Module) mountSetup(r router.Router) {
	r.Get(PathSetup, m.setupState).Public()
	r.Post(PathSetupOptions, m.setupOptions).Public()
	r.Post(PathSetup, m.setupFinish).Public()
}

// setupState answers whether the first-administrator setup is pending; each answer has one meaning (D76).
func (m *Module) setupState(ctx router.Context) {
	m.setup.mu.Lock()
	ok, err := m.setup.open()
	m.setup.mu.Unlock()
	switch {
	case err != nil:
		ctx.WriteStatus(503)
		ctx.Write([]byte(ErrAdminsUnreadable.Error()))
	case ok:
		ctx.WriteStatus(200)
		ctx.Write([]byte(setupRequired))
	default:
		ctx.WriteStatus(200)
		ctx.Write([]byte(setupDone))
	}
}

// setupOptions checks the code and the name, then starts the enrollment of the first administrator's passkey.
func (m *Module) setupOptions(ctx router.Context) {
	s := m.setup
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok, err := s.open(); err != nil || !ok {
		m.reportEvent(securityevent.Event{Kind: securityevent.SetupRejected, IP: auth.ClientIP(ctx, false)})
		ctx.WriteStatus(404)
		return
	}
	data := &auth.SetupData{}
	if err := ctx.Decode(data); err != nil || data.Name == "" {
		ctx.WriteStatus(400)
		return
	}
	if !hmac.HMACEqual([]byte(data.Code), []byte(s.code)) {
		s.failures++
		m.reportEvent(securityevent.Event{Kind: securityevent.LoginFailed, IP: auth.ClientIP(ctx, false), Reason: reasonSetupCode})
		if s.failures >= maxSetupFailures {
			s.done = true
		}
		ctx.WriteStatus(401)
		return
	}
	s.pendingID = m.ids.NewID()
	s.name = data.Name
	challenge, err := m.newChallenge(s.pendingID, purposeSetup)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	ctx.Encode(&RegisterOptions{
		Challenge: base64.URLEncode(challenge),
		RPID:      m.rp.ID,
		UserID:    base64.URLEncode([]byte(s.pendingID)),
		UserName:  data.Name,
	})
}

// setupFinish verifies the enrolled passkey, creates the administrator, signs them in and closes the setup for good.
func (m *Module) setupFinish(ctx router.Context) {
	s := m.setup
	s.mu.Lock()
	defer s.mu.Unlock()
	if ok, err := s.open(); err != nil || !ok || s.pendingID == "" {
		ctx.WriteStatus(404)
		return
	}
	challenge, ok := m.consumeChallenge(s.pendingID, purposeSetup)
	if !ok {
		m.reject(ctx, 401, reasonChallenge)
		return
	}
	reg, err := m.rp.VerifyRegistration(string(ctx.Body()), challenge)
	if err != nil {
		m.reject(ctx, 401, err.Error())
		return
	}
	u, err := s.users.CreateUser("", s.name, "")
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	credID := base64.URLEncode(reg.CredentialID)
	cred := PasskeyCredential{Id: credID, UserId: u.Id, PublicKey: base64.URLEncode(reg.PublicKey), SignCount: int64(reg.SignCount), CreatedAt: now()}
	if err := m.db.Create(&cred); err != nil {
		ctx.WriteStatus(500)
		return
	}
	if err := s.users.UpsertIdentity(u.Id, name, credID, ""); err != nil {
		ctx.WriteStatus(500)
		return
	}
	if err := s.makeAdmin(u.Id); err != nil {
		ctx.WriteStatus(500)
		return
	}
	s.done = true
	m.reportEvent(securityevent.Event{Kind: securityevent.AdminCreated, UserID: u.Id, IP: auth.ClientIP(ctx, false)})
	if err := m.sessions.IssueStepUpSession(ctx, u.Id); err != nil {
		ctx.WriteStatus(500)
		return
	}
	ctx.WriteStatus(204)
}
