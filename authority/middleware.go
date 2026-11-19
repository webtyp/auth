package authority

import (
	"webtyp.com/auth"
	"webtyp.com/model"
	"webtyp.com/router"
)

// Authenticate returns a router.Middleware that resolves who the caller is and
// how strongly that was proven (see resolve for the order), then sets
// ctx.SetUserID and ctx.SetAssurance. An unidentified caller stays anonymous.
// With DEV_AUTOLOGIN in a build with -tags dev, an unauthenticated request is
// replayed through enabled form login authenticators (see auth.EnvDevAutologin).
//
// authority identifies; it never authorizes — that is rbac.Service.Can (see
// ARCHITECTURE.md). A composition root wires Authenticate() as Authn and
// rbac.Service.Can as Authorize, two separate ports.
func (m *Module) Authenticate() router.Middleware {
	return func(next router.HandlerFunc) router.HandlerFunc {
		return func(ctx router.Context) {
			p := m.resolve(ctx, true)
			ctx.SetUserID(p.UserID)
			ctx.SetAssurance(p.Assurance)
			next(ctx)
		}
	}
}

// CurrentPrincipal runs the same resolution as Authenticate without touching
// ctx's identity. A request that resolves to nobody returns auth.ErrSessionExpired.
func (m *Module) CurrentPrincipal(ctx router.Context) (auth.Principal, error) {
	p := m.resolve(ctx, false)
	if p.UserID == "" {
		return auth.Principal{}, auth.ErrSessionExpired
	}
	return p, nil
}

// resolve, in order: a RequestIdentifier that recognises its credential decides
// (even if the answer is anonymous); then the step-up session; then the main
// session; then dev autologin (only compiled with -tags dev, and only when
// allowDev); otherwise anonymous. Dev autologin opens BOTH sessions (one and
// two factors), so screens that demand a second factor open in development;
// a production build has no such path (devlogin_off.go).
func (m *Module) resolve(ctx router.Context, allowDev bool) auth.Principal {
	for _, a := range m.authenticators {
		if ri, ok := a.(auth.RequestIdentifier); ok {
			if p, handled := ri.IdentifyRequest(ctx); handled {
				return p
			}
		}
	}
	if p, err := m.stepUp.Identify(ctx); err == nil && p.UserID != "" {
		return p
	}
	if p, err := m.strategy.Identify(ctx); err == nil && p.UserID != "" {
		if allowDev && m.dev.upgrade != nil && m.dev.upgrade(ctx, p.UserID) {
			p.Assurance = model.AssuranceMultiFactor
		}
		return p
	}
	if allowDev && m.dev.open != nil {
		if userID := m.dev.open(ctx); userID != "" {
			return auth.Principal{UserID: userID, Assurance: model.AssuranceMultiFactor}
		}
	}
	return auth.Principal{}
}
