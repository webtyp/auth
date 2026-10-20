package cookie

import (
	"webtyp.com/auth"
	"webtyp.com/fmt"
	"webtyp.com/model"
	"webtyp.com/router"
)

const (
	hostPrefix  = "__Host-"
	defaultName = "session"
)

// Options configures a cookie session strategy.
type Options struct {
	Name       string             // cookie name; "" = "session"
	Domain     string             // "" = host-only, and the name gets the __Host- prefix
	Policy     auth.SessionPolicy // required: Absolute > 0
	TrustProxy bool
}

// Strategy is a SessionStrategy: an opaque session ID in an HttpOnly cookie,
// backed by whatever SessionRepo the consumer injects (authority.Module
// implements it with its own session table + in-memory cache).
type Strategy struct {
	repo       auth.SessionRepo
	name       string
	domain     string
	policy     auth.SessionPolicy
	trustProxy bool
}

// New builds a cookie strategy. With Domain == "" the cookie is host-only and
// named "__Host-"+Name: the browser then refuses any attempt by another
// subdomain to set or shadow it (RFC 6265bis). With Domain set (e.g.
// ".velty.cl") the session is shared by every subdomain: use that only for a
// single-factor SSO identity, never for a privileged session.
func New(repo auth.SessionRepo, o Options) (*Strategy, error) {
	if o.Policy.Absolute <= 0 {
		return nil, fmt.Err(auth.ErrMsgPolicyAbsolute)
	}
	name := o.Name
	if name == "" {
		name = defaultName
	}
	if o.Domain == "" {
		name = hostPrefix + name
	}
	return &Strategy{repo: repo, name: name, domain: o.Domain, policy: o.Policy, trustProxy: o.TrustProxy}, nil
}

func (s *Strategy) Issue(ctx router.Context, userID string) error {
	ip := auth.ClientIP(ctx, s.trustProxy)
	ua := ctx.GetHeader("User-Agent")
	sess, err := s.repo.CreateSession(userID, ip, ua, s.policy)
	if err != nil {
		return err
	}
	ctx.SetCookie(router.Cookie{
		Name: s.name, Value: sess.Id, HttpOnly: true, Secure: true,
		SameSite: router.SameSiteStrict, MaxAge: int(s.policy.Absolute), Path: "/", // HTTP Max-Age is seconds on the wire
		Domain: s.domain,
	})
	return nil
}

func (s *Strategy) Identify(ctx router.Context) (auth.Principal, error) {
	c, ok := ctx.Cookie(s.name)
	if !ok {
		return auth.Principal{}, auth.ErrSessionExpired
	}
	sess, err := s.repo.GetSession(c.Value)
	if err != nil {
		return auth.Principal{}, err
	}
	return auth.Principal{
		UserID:    sess.UserId,
		Assurance: model.Assurance(sess.Assurance),
		IssuedAt:  sess.CreatedAt,
	}, nil
}

// Revoke deletes the session row and clears the cookie with the same name,
// Path and Domain it was set with: a cookie set with a Domain cannot be
// cleared without it.
func (s *Strategy) Revoke(ctx router.Context) error {
	if c, ok := ctx.Cookie(s.name); ok {
		s.repo.DeleteSession(c.Value)
	}
	ctx.SetCookie(router.Cookie{Name: s.name, Value: "", Path: "/", Domain: s.domain, MaxAge: -1, HttpOnly: true})
	return nil
}

var _ auth.SessionStrategy = (*Strategy)(nil)
