package emailpassword

import (
	"webtyp.com/auth"
	"webtyp.com/crypto/bcrypt"
	"webtyp.com/json"
	"webtyp.com/router"
)

// loginFailure carries the exact HTTP answer the POST route must give for a
// rejected attempt, so Login can hold every check while the route only
// writes.
type loginFailure struct {
	status int
	body   string
}

func (f loginFailure) Error() string { return f.body }

func writeFailure(ctx router.Context, err error) {
	if f, ok := err.(loginFailure); ok {
		ctx.WriteStatus(f.status)
		if f.body != "" {
			ctx.Write([]byte(f.body))
		}
		return
	}
	ctx.WriteStatus(500)
}

type Authenticator struct {
	store      auth.IdentityStore
	sessions   auth.SessionIssuer
	notify     auth.SecurityNotifier
	afterLogin string
	rateLimit  auth.RateLimiter
	trustProxy bool
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }

// WithRateLimit gates login attempts through l before any credential check —
// see auth.RateLimiter and auth.NewIPLimiter for the built-in implementation.
func WithRateLimit(l auth.RateLimiter) Option {
	return func(a *Authenticator) { a.rateLimit = l }
}
func WithTrustProxy(v bool) Option { return func(a *Authenticator) { a.trustProxy = v } }

// New builds the email+password mode. store/sessions/notify are required ports;
// everything else is an Option with a safe zero-value default.
func New(store auth.IdentityStore, sessions auth.SessionIssuer, notify auth.SecurityNotifier, opts ...Option) *Authenticator {
	a := &Authenticator{store: store, sessions: sessions, notify: notify}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Authenticator) Name() string { return "email_password" }

// Login runs EVERY check the POST route runs against body — the same bytes the
// form sends — and returns the user id. It never writes a response and never
// issues a session: the caller does.
func (a *Authenticator) Login(ctx router.Context, body []byte) (string, error) {
	ip := auth.ClientIP(ctx, a.trustProxy)
	data := &auth.LoginData{}
	if err := json.Decode(body, data); err != nil {
		return "", loginFailure{status: 400, body: err.Error()}
	}

	if a.rateLimit != nil {
		if err := a.rateLimit.Check(ip); err != nil {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventRateLimited, IP: ip, UserID: data.Email})
			return "", loginFailure{status: 429, body: err.Error()}
		}
	}

	u, err := a.store.UserByEmail(data.Email)
	if err != nil {
		DummyCompare(data.Password, DefaultHashCost)
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}
	if u.Status != "active" {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventNonActiveAccess, UserID: u.Id})
		DummyCompare(data.Password, DefaultHashCost)
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}

	identity, err := a.store.IdentityFor(u.Id, "email_password")
	if err != nil {
		DummyCompare(data.Password, DefaultHashCost)
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}
	if err := VerifyPassword(identity.ProviderId, data.Password); err != nil {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventAccessDenied, IP: ip, UserID: u.Id})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: err.Error()}
	}

	if a.rateLimit != nil {
		a.rateLimit.Reset(ip)
	}
	return u.Id, nil
}

func (a *Authenticator) Mount(r router.Router) {
	afterLogin := a.afterLogin
	if afterLogin == "" {
		afterLogin = auth.PathAfterLogin
	}

	r.Post(auth.PathLogin, func(ctx router.Context) {
		userID, err := a.Login(ctx, ctx.Body())
		if err != nil {
			writeFailure(ctx, err)
			return
		}

		if err := a.sessions.IssueSession(ctx, userID); err != nil {
			ctx.WriteStatus(500)
			ctx.Write([]byte(err.Error()))
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

var _ auth.FormLogin = (*Authenticator)(nil)

var _ auth.Authenticator = (*Authenticator)(nil)

// DefaultHashCost is bcrypt's cost factor. Tests lower it (bcrypt.MinCost) for
// speed — same knob as the old package-level authority.PasswordHashCost.
var DefaultHashCost = bcrypt.DefaultCost

var dummyHashOnce []byte

func getDummyHash(cost int) []byte {
	if len(dummyHashOnce) == 0 {
		dummyHashOnce, _ = bcrypt.GenerateFromPassword([]byte("dummy"), cost)
	}
	return dummyHashOnce
}

// DummyCompare burns the same time a real bcrypt comparison would, so a caller
// can't distinguish "no such user" from "wrong password" by timing.
func DummyCompare(password string, cost int) {
	bcrypt.CompareHashAndPassword(getDummyHash(cost), []byte(password))
}

// HashPassword is the ONLY place bcrypt.GenerateFromPassword is called in this
// repo. authority/credentials_password.go calls this — it never calls bcrypt
// directly.
func HashPassword(password string, cost int) (string, error) {
	if len(password) < 8 {
		return "", auth.ErrWeakPassword
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// VerifyPassword is the ONLY place bcrypt.CompareHashAndPassword is called for a
// real (non-dummy) comparison in this repo.
func VerifyPassword(hash, password string) error {
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return auth.ErrInvalidCredentials
	}
	return nil
}
