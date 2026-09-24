package trustedip

import (
	"webtyp.com/auth"
	"webtyp.com/fmt"
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
	store       auth.IdentityStore
	trusted     auth.TrustedIPStore
	sessions    auth.SessionIssuer
	notify      auth.SecurityNotifier
	trustProxy  bool
	afterLogin  string
	rateLimit   auth.RateLimiter
	registry    auth.ProviderRegistry
	createAdmin func(code, name, ip string) error
}

type Option func(*Authenticator)

func WithAfterLogin(path string) Option { return func(a *Authenticator) { a.afterLogin = path } }

// WithRateLimit gates login attempts through l before any RUT/IP check —
// see auth.RateLimiter and auth.NewIPLimiter for the built-in implementation.
// A blocked attempt returns the exact same 401 body as any other rejected
// login (see Mount): this mode exists to keep an outsider from learning what
// kind of value the field even validates, so the block must not out itself
// with a different status code or message.
func WithRateLimit(l auth.RateLimiter) Option {
	return func(a *Authenticator) { a.rateLimit = l }
}

// WithFirstAdminSetup enables the one-time setup routes at auth.PathSetup,
// open ONLY while reg reports no identity for this provider. It solves this
// mode's chicken-and-egg — only an admin can assign devices, but nobody can
// log in until an admin exists — so the consumer does not have to carry
// bootstrap credentials in its environment.
//
// create receives the checksum-validated credential, the display name, and
// the IP the setup request came from: that IP is the device the first
// administrator will be able to log in from, so whoever performs the setup
// enables the machine they are sitting at. Composing what that means (a
// device record, a staff member, a role) is the consumer's job — this mode
// knows only that it must happen before the session is issued.
//
// Both routes answer 404 once an admin exists, and a POST after that point
// publishes EventSetupRejected: from the outside, a finished install is
// indistinguishable from one that never offered setup at all.
func WithFirstAdminSetup(reg auth.ProviderRegistry, create func(code, name, ip string) error) Option {
	return func(a *Authenticator) {
		a.registry = reg
		a.createAdmin = create
	}
}

// New builds the trusted-IP mode. trustProxy is required (not an Option): this
// mode's entire security property is "the request's real IP is on the
// allowlist" — silently defaulting it to false behind a real proxy would make
// every request look like it came from the proxy's own IP.
func New(store auth.IdentityStore, trusted auth.TrustedIPStore, sessions auth.SessionIssuer, notify auth.SecurityNotifier, trustProxy bool, opts ...Option) *Authenticator {
	a := &Authenticator{store: store, trusted: trusted, sessions: sessions, notify: notify, trustProxy: trustProxy}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

func (a *Authenticator) Name() string { return auth.ProviderTrustedIP }

// Login runs EVERY check the POST route runs against body — the same bytes the
// form sends — and returns the user id. It never writes a response and never
// issues a session: the caller does.
func (a *Authenticator) Login(ctx router.Context, body []byte) (string, error) {
	ip := auth.ClientIP(ctx, a.trustProxy)

	// Checked before decoding the body or touching the store: a blocked IP
	// gets the exact same 401 + generic body as any other rejected login
	// (see WithRateLimit's doc comment) — never a 429 or a distinct
	// message, either of which would tell an outsider the block exists.
	if a.rateLimit != nil {
		if err := a.rateLimit.Check(ip); err != nil {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventRateLimited, IP: ip})
			return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
		}
	}

	data := &auth.RUTLoginData{}
	if err := json.Decode(body, data); err != nil {
		return "", loginFailure{status: 400}
	}

	normalized, err := ValidateRUT(data.Code)
	if err != nil {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventInvalidRUT, IP: ip})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		// The SAME generic body every other rejection below uses — err
		// here is ValidateRUT's own message ("rut invalid"), which would
		// tell an outsider this field validates a checksummed ID. The
		// specific reason is for the security event above (server-side
		// only), never the response.
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}

	identity, err := a.store.IdentityByProvider(auth.ProviderTrustedIP, normalized)
	if err != nil {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventUnknownRUT, IP: ip})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}
	u, err := a.store.UserByID(identity.UserId)
	if err != nil {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventUnknownRUT, IP: ip})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}
	if u.Status != "active" {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventNonActiveAccess, UserID: u.Id})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
	}
	if !a.trusted.IsTrustedIP(u.Id, ip) {
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventIPMismatch, UserID: u.Id, IP: ip})
		if a.rateLimit != nil {
			a.rateLimit.Fail(ip)
		}
		return "", loginFailure{status: 401, body: auth.ErrInvalidCredentials.Error()}
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

	if a.createAdmin != nil && a.registry != nil {
		a.mountSetup(r, afterLogin)
	}

	r.Post(auth.PathLoginRUT, func(ctx router.Context) {
		userID, err := a.Login(ctx, ctx.Body())
		if err != nil {
			writeFailure(ctx, err)
			return
		}
		if err := a.sessions.IssueSession(ctx, userID); err != nil {
			ctx.WriteStatus(500)
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

var _ auth.FormLogin = (*Authenticator)(nil)

// mountSetup serves the first-run routes described on WithFirstAdminSetup.
// Both ask the registry on EVERY request rather than caching the answer at
// mount time: the whole point is that the routes close the instant the first
// administrator exists, and a cached "still empty" would leave them open for
// the lifetime of the process.
func (a *Authenticator) mountSetup(r router.Router, afterLogin string) {
	// open reports whether setup may still run. A registry error keeps the
	// door CLOSED (see authority.HasIdentity): a database hiccup must never
	// be the reason anyone gets to claim the admin account.
	//
	// Closed-on-error is reported, never silent. From outside, all three
	// reasons look like the same 404 — that is deliberate — so without this
	// event an operator cannot tell "already set up" (expected) from "the
	// schema was never created" or "the database is down" (both broken), and
	// a fresh install just refuses to start with no explanation.
	// The error is returned, not folded into the bool, so the caller can tell
	// "an admin already exists" (a rejection worth reporting as such) from
	// "the registry could not answer" (already reported here as Unavailable —
	// reporting it a second time as a rejection would name the wrong cause).
	open := func(ip string) (bool, error) {
		exists, err := a.registry.HasIdentity(auth.ProviderTrustedIP)
		if err != nil {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventSetupUnavailable, IP: ip})
			return false, err
		}
		return !exists, nil
	}

	r.Get(auth.PathSetup, func(ctx router.Context) {
		if ok, _ := open(auth.ClientIP(ctx, a.trustProxy)); !ok {
			ctx.WriteStatus(404)
			return
		}
		ctx.WriteStatus(200)
		ctx.Write([]byte(`{"required":true}`))
	}).Public()

	r.Post(auth.PathSetup, func(ctx router.Context) {
		ip := auth.ClientIP(ctx, a.trustProxy)
		ok, err := open(ip)
		if !ok {
			if err == nil {
				a.notify.Notify(auth.SecurityEvent{Type: auth.EventSetupRejected, IP: ip})
			}
			ctx.WriteStatus(404)
			return
		}

		data := &auth.SetupData{}
		if err := ctx.Decode(data); err != nil {
			ctx.WriteStatus(400)
			return
		}
		if data.Name == "" {
			ctx.WriteStatus(400)
			ctx.Write([]byte(auth.ErrInvalidCredentials.Error()))
			return
		}
		// The same checksum the login path runs — an administrator created
		// with a credential the login would later reject could never sign in.
		normalized, err := ValidateRUT(data.Code)
		if err != nil {
			a.notify.Notify(auth.SecurityEvent{Type: auth.EventInvalidRUT, IP: ip})
			ctx.WriteStatus(400)
			// Setup is the ONE place the specific reason is safe to return:
			// the person reading it is the installer typing their own
			// credential, and the route is gone for everyone after this.
			ctx.Write([]byte(err.Error()))
			return
		}

		if err := a.createAdmin(normalized, data.Name, ip); err != nil {
			ctx.WriteStatus(500)
			ctx.Write([]byte(err.Error()))
			return
		}

		identity, err := a.store.IdentityByProvider(auth.ProviderTrustedIP, normalized)
		if err != nil {
			// createAdmin returned nil but no identity exists: the consumer's
			// composition is broken, and staying silent would leave an install
			// that looks finished and can never be logged into.
			ctx.WriteStatus(500)
			ctx.Write([]byte(auth.ErrNotFound.Error()))
			return
		}
		a.notify.Notify(auth.SecurityEvent{Type: auth.EventSetupCompleted, UserID: identity.UserId, IP: ip})

		// Signing the installer in is the proof the assignment worked: if the
		// device binding were wrong, they would land on the login screen
		// instead, at the moment they can still fix it.
		if err := a.sessions.IssueSession(ctx, identity.UserId); err != nil {
			ctx.WriteStatus(500)
			return
		}
		ctx.SetHeader("Location", afterLogin)
		ctx.WriteStatus(302)
	}).Public()
}

var _ auth.Authenticator = (*Authenticator)(nil)

// ValidateRUT normalizes and checksum-validates a Chilean RUT. Pure, stateless —
// no ports, no DB — so both this package's Mount handler and
// authority/credentials_lan.go (LoginLAN, RegisterLAN — direct, non-HTTP entry
// points kept for admin use and unit testing) call the exact SAME algorithm.
// Body copied verbatim from the current authority/lan.go — do not rewrite the
// checksum logic, only relocate it.
func ValidateRUT(rut string) (string, error) {
	rut = fmt.Convert(rut).TrimSpace().String()
	rut = fmt.Convert(rut).Replace(".", "").Replace("-", "").String()

	if len(rut) < 2 {
		return "", auth.ErrInvalidRUT
	}
	bodyStr := rut[:len(rut)-1]
	dvStr := fmt.ToUpper(rut[len(rut)-1:])
	if _, err := fmt.Convert(bodyStr).Int(); err != nil {
		return "", auth.ErrInvalidRUT
	}
	sum := 0
	multiplier := 2
	for i := len(bodyStr) - 1; i >= 0; i-- {
		digit := int(bodyStr[i] - '0')
		sum += digit * multiplier
		multiplier++
		if multiplier > 7 {
			multiplier = 2
		}
	}
	expectedDV := 11 - (sum % 11)
	var expectedDVStr string
	if expectedDV == 11 {
		expectedDVStr = "0"
	} else if expectedDV == 10 {
		expectedDVStr = "K"
	} else {
		expectedDVStr = fmt.Convert(expectedDV).String()
	}
	if dvStr != expectedDVStr {
		return "", auth.ErrInvalidRUT
	}
	return bodyStr + "-" + expectedDVStr, nil
}
