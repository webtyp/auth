// Package cfaccess identifies a request by the JWT that Cloudflare Access
// adds to every request it lets through (header Cf-Access-Jwt-Assertion).
// The token is verified (RS256 signature, issuer, audience, expiry) before
// anything in it is believed; the e-mail inside becomes a user of this app.
//
// Mount registers nothing: the credential rides on every request.
package cfaccess

import (
	"webtyp.com/auth"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/time"
)

const (
	// HeaderAssertion is the header Cloudflare Access adds to each request.
	HeaderAssertion = "Cf-Access-Jwt-Assertion"

	ErrMsgEmptyTeamDomain   = "cfaccess: team domain is required"
	ErrMsgTeamDomainFormat  = "cfaccess: team domain must be a bare host such as acme.cloudflareaccess.com"
	ErrMsgEmptyAudience     = "cfaccess: audience (application AUD tag) is required"
	ErrMsgNilKeySource      = "cfaccess: key source is required"
	ErrMsgNilIdentityStore  = "cfaccess: identity store is required"

	statusActive = "active" // auth.User.Status of an enabled account (same literal authority writes)
	pathSeparator = "/"
)

// Reasons recorded in auth.EventCloudflareAccessRejected.
const (
	reasonKeysUnavailable = "keys_unavailable"
	reasonSignature       = "signature"
	reasonExpired         = "expired"
	reasonIssuer          = "issuer"
	reasonAudience        = "audience"
	reasonNoEmail         = "no_email"
	reasonUnknownEmail    = "unknown_email"
	reasonInactive        = "inactive"
)

// Config is what the Access application declares in the Cloudflare
// dashboard. Neither value is a secret.
type Config struct {
	// TeamDomain is the bare host of the Zero Trust team,
	// e.g. "acme.cloudflareaccess.com" (no scheme, no path).
	TeamDomain string
	// Audience is the application's "Application Audience (AUD) Tag".
	Audience string
}

// Authenticator turns a verified Access token into a principal.
type Authenticator struct {
	issuer   string
	audience string
	keys     KeySource
	store    auth.IdentityStore
	notify   func(auth.SecurityEvent)
}

var (
	_ auth.Authenticator     = (*Authenticator)(nil)
	_ auth.RequestIdentifier = (*Authenticator)(nil)
)

// New builds the mode. notify may be nil (no security events).
//
// Example:
//
//	keys := cfaccess.NewKeySource(cfaccess.CertsURL("acme.cloudflareaccess.com"))
//	cfa, err := cfaccess.New(cfaccess.Config{TeamDomain: "acme.cloudflareaccess.com", Audience: aud}, keys, authMod, authMod.Notify)
//	authMod.Enable(cfa)
func New(cfg Config, keys KeySource, store auth.IdentityStore, notify func(auth.SecurityEvent)) (*Authenticator, error) {
	switch {
	case cfg.TeamDomain == "":
		return nil, fmt.Err(ErrMsgEmptyTeamDomain)
	case fmt.Contains(cfg.TeamDomain, pathSeparator):
		return nil, fmt.Err(ErrMsgTeamDomainFormat)
	case cfg.Audience == "":
		return nil, fmt.Err(ErrMsgEmptyAudience)
	case keys == nil:
		return nil, fmt.Err(ErrMsgNilKeySource)
	case store == nil:
		return nil, fmt.Err(ErrMsgNilIdentityStore)
	}
	return &Authenticator{
		issuer:   httpsScheme + cfg.TeamDomain,
		audience: cfg.Audience,
		keys:     keys,
		store:    store,
		notify:   notify,
	}, nil
}

func (a *Authenticator) Name() string { return auth.ProviderCloudflareAccess }

// Mount registers nothing: the token rides on every request.
func (a *Authenticator) Mount(router.Router) {}

// IdentifyRequest: no header → not this kind of request (handled false).
// Any header is final: a failure is anonymous AND handled, so a session
// cookie riding along cannot rescue a bad token.
func (a *Authenticator) IdentifyRequest(ctx router.Context) (auth.Principal, bool) {
	token := ctx.GetHeader(HeaderAssertion)
	if token == "" {
		return auth.Principal{}, false
	}
	keys, err := a.keys.Keys()
	if err != nil {
		return a.reject("", reasonKeysUnavailable)
	}
	claims, outcome, err := jwt.VerifyRS256(keys, token)
	if err == nil && outcome == jwt.Forged {
		// Access may have rotated its keys: one forced refresh, then final.
		if fresh, ferr := a.keys.Refresh(); ferr == nil {
			claims, outcome, err = jwt.VerifyRS256(fresh, token)
		}
	}
	if err != nil || outcome == jwt.Forged {
		return a.reject("", reasonSignature)
	}
	if outcome == jwt.Expired {
		return a.reject("", reasonExpired)
	}
	if claims.Iss != a.issuer {
		return a.reject("", reasonIssuer)
	}
	if !claims.HasAudience(a.audience) {
		return a.reject("", reasonAudience)
	}
	email := fmt.ToLower(fmt.Convert(claims.Email).TrimSpace().String())
	if email == "" {
		return a.reject("", reasonNoEmail)
	}
	userID, ok := a.userFor(email)
	if !ok {
		return a.reject(email, reasonUnknownEmail)
	}
	u, err := a.store.UserByID(userID)
	if err != nil || u.Status != statusActive {
		return a.reject(userID, reasonInactive)
	}
	return auth.Principal{UserID: u.Id, Assurance: model.AssuranceSingleFactor}, true
}

// userFor resolves the e-mail: the linked identity first; otherwise the user
// with that e-mail, linking it now (the oauth2 rule).
func (a *Authenticator) userFor(email string) (string, bool) {
	if id, err := a.store.IdentityByProvider(auth.ProviderCloudflareAccess, email); err == nil {
		return id.UserId, true
	}
	u, err := a.store.UserByEmail(email)
	if err != nil {
		return "", false
	}
	if err := a.store.UpsertIdentity(u.Id, auth.ProviderCloudflareAccess, email, email); err != nil {
		return "", false
	}
	return u.Id, true
}

// reject reports the refusal and answers "handled, anonymous". who is the
// e-mail or user id when known, "" otherwise.
func (a *Authenticator) reject(who, reason string) (auth.Principal, bool) {
	if a.notify != nil {
		a.notify(auth.SecurityEvent{Type: auth.EventCloudflareAccessRejected, UserID: who, Reason: reason, Timestamp: time.NowUnix()})
	}
	return auth.Principal{}, true
}
