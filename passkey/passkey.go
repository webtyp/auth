// Package passkey is the WebAuthn authenticator: it enrolls passkeys, and a
// verified assertion issues a step-up session (Assurance MultiFactor).
// Verifying the cryptographic response is webauthn/server's job; this package
// owns credentials, single-use challenges and the enrollment gate.
package passkey

import (
	"webtyp.com/auth"
	"webtyp.com/base64"
	"webtyp.com/crypto/rand"
	"webtyp.com/ddl"
	"webtyp.com/fmt"
	"webtyp.com/model"
	"webtyp.com/orm"
	"webtyp.com/router"
	"webtyp.com/time"
	"webtyp.com/webauthn/server"
)

const (
	name = "passkey"

	purposeRegister = "register"
	purposeVerify   = "verify"
	anonymous       = ""

	challengeBytes = 32
	challengeTTL   = 300 // seconds a challenge stays valid
	// freshLoginWindow is how recent a session must be to enroll the FIRST
	// passkey: enrolling is a privileged act, so a stolen old cookie is not enough.
	freshLoginWindow = 300

	// ChallengeRecentLogin is the RFC 9470 challenge (max_age) answered when the
	// first passkey is enrolled from a session older than freshLoginWindow.
	ChallengeRecentLogin = `Bearer error="insufficient_user_authentication", error_description="sign in again to enroll a passkey", max_age=300`

	ErrMsgRelyingParty = "passkey: RelyingParty ID and Origin are required"
	ErrMsgNoSessions   = "passkey: empty sessions"
)

const (
	PathRegisterOptions = "/passkey/register/options"
	PathRegister        = "/passkey/register"
	PathVerifyOptions   = "/passkey/verify/options"
	PathVerify          = "/passkey/verify"
	PathList            = "/passkey/list"
	PathDelete          = "/passkey/delete"
)

// Sessions are the ports of *authority.Module this package needs.
type Sessions interface {
	CurrentPrincipal(ctx router.Context) (auth.Principal, error)
	IssueStepUpSession(ctx router.Context, userID string) error
	Notify(e auth.SecurityEvent)
}

// Module is the passkey authenticator.
type Module struct {
	db       *orm.DB
	ids      model.IDGenerator
	sessions Sessions
	rp       server.RelyingParty
}

// New builds the passkey authenticator. db stores credentials and challenges;
// rp is who the passkeys are for (ID "iam.velty.cl", Origin "https://iam.velty.cl").
func New(db *orm.DB, ids model.IDGenerator, sessions Sessions, rp server.RelyingParty) (*Module, error) {
	if rp.ID == "" || rp.Origin == "" {
		return nil, fmt.Err(ErrMsgRelyingParty)
	}
	if sessions == nil {
		return nil, fmt.Err(ErrMsgNoSessions)
	}
	return &Module{db: db, ids: ids, sessions: sessions, rp: rp}, nil
}

func (m *Module) Name() string { return name }

// Migrate creates the tables this package owns. Like authority.Migrate, it is
// deploy-time work and is not called by New.
func Migrate(conn ddl.Execer, ddlCompiler ddl.Compiler) error {
	models := []model.Model{&PasskeyCredential{}, &PasskeyChallenge{}}
	sorted, err := ddl.TopologicalSort(models)
	if err != nil {
		return err
	}
	return ddl.New(conn, ddlCompiler).Sync(sorted...)
}

func now() time.Unix { return time.NowUnix() }

// newChallenge stores a single-use challenge for userID and returns its bytes.
func (m *Module) newChallenge(userID, purpose string) ([]byte, error) {
	b, err := rand.Bytes(challengeBytes)
	if err != nil {
		return nil, err
	}
	c := PasskeyChallenge{Id: base64.URLEncode(b), UserId: userID, Purpose: purpose, ExpiresAt: now() + challengeTTL}
	if err := m.db.Create(&c); err != nil {
		return nil, err
	}
	return b, nil
}

// consumeChallenge deletes every challenge of userID for purpose and returns
// the newest one that was still live. It reports false when none was.
func (m *Module) consumeChallenge(userID, purpose string) ([]byte, bool) {
	qb := m.db.Query(&PasskeyChallenge{}).
		Where(PasskeyChallenge_.UserId).Eq(userID).
		Where(PasskeyChallenge_.Purpose).Eq(purpose)
	rows, err := ReadAllPasskeyChallenge(qb)
	if err != nil {
		return nil, false
	}
	var best *PasskeyChallenge
	t := now()
	for _, c := range rows {
		m.db.Delete(c, orm.Eq(PasskeyChallenge_.Id, c.Id))
		if c.ExpiresAt > t && (best == nil || c.ExpiresAt > best.ExpiresAt) {
			best = c
		}
	}
	if best == nil {
		return nil, false
	}
	b, err := base64.URLDecode(best.Id)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (m *Module) consumeAnonymousChallenge(chal []byte) bool {
	id := base64.URLEncode(chal)
	qb := m.db.Query(&PasskeyChallenge{}).
		Where(PasskeyChallenge_.Id).Eq(id).
		Where(PasskeyChallenge_.UserId).Eq(anonymous).
		Where(PasskeyChallenge_.Purpose).Eq(purposeVerify)
	rows, err := ReadAllPasskeyChallenge(qb)
	if err != nil || len(rows) == 0 {
		return false
	}
	c := rows[0]
	m.db.Delete(c, orm.Eq(PasskeyChallenge_.Id, c.Id))
	return c.ExpiresAt > now()
}

func (m *Module) credentialsOf(userID string) (PasskeyCredentialList, error) {
	qb := m.db.Query(&PasskeyCredential{}).Where(PasskeyCredential_.UserId).Eq(userID)
	return ReadAllPasskeyCredential(qb)
}

func (m *Module) credential(id string) (*PasskeyCredential, bool) {
	qb := m.db.Query(&PasskeyCredential{}).Where(PasskeyCredential_.Id).Eq(id)
	rows, err := ReadAllPasskeyCredential(qb)
	if err != nil || len(rows) == 0 {
		return nil, false
	}
	return rows[0], true
}

func (m *Module) reject(ctx router.Context, status int, reason string) {
	m.sessions.Notify(auth.SecurityEvent{Type: auth.EventPasskeyRejected, UserID: ctx.UserID(), Reason: reason})
	ctx.WriteStatus(status)
}

// enrollmentAllowed is the gate for the register routes. It answers the 401
// itself and reports false when the caller may not enroll now.
func (m *Module) enrollmentAllowed(ctx router.Context) bool {
	existing, err := m.credentialsOf(ctx.UserID())
	if err != nil {
		ctx.WriteStatus(500)
		return false
	}
	if len(existing) > 0 {
		if ctx.Assurance() != model.AssuranceMultiFactor {
			ctx.SetHeader(router.HeaderWWWAuthenticate, router.ChallengeMFARequired)
			ctx.WriteStatus(401)
			return false
		}
		return true
	}
	p, err := m.sessions.CurrentPrincipal(ctx)
	if err != nil || now()-p.IssuedAt > freshLoginWindow {
		ctx.SetHeader(router.HeaderWWWAuthenticate, ChallengeRecentLogin)
		ctx.WriteStatus(401)
		return false
	}
	return true
}
