package authority

import (
	"webtyp.com/auth"
	"webtyp.com/router"
)

var _ router.APIModule = (*Module)(nil)

// MountAPI mounts the transport routes that set or clear the session cookie, which a crud operation cannot do: logout
// ends a session the same way no matter which mode started it (strategy.Revoke on the step-up and the main
// strategy), then every enabled Authenticator mounts its own login route. authority never inspects what a mode
// mounts. Who the caller is travels through crud: the entity me (rule_me_read.go).
func (m *Module) MountAPI(r router.Router) {
	r.Post(auth.PathLogout, func(ctx router.Context) {
		if m.dev.pause != nil {
			m.dev.pause(ctx)
		}
		m.stepUp.Revoke(ctx)
		m.strategy.Revoke(ctx)
		ctx.SetHeader("Location", auth.PathLogin)
		ctx.WriteStatus(302)
	}).Public()

	if m.dev.mount != nil {
		m.dev.mount(r)
	}
	for _, a := range m.authenticators {
		a.Mount(r)
	}
}
