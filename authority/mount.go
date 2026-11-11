package authority

import (
	"webtyp.com/auth"
	"webtyp.com/router"
)

var _ router.APIModule = (*Module)(nil)

// MountAPI mounts the one session-termination endpoint centrally — logout ends
// a session the same way no matter which mode started it (strategy.Revoke on the step-up and the main strategy) —
// then the profile of the caller, then lets every enabled Authenticator mount its own login route. authority
// never inspects what a mode mounts.
func (m *Module) MountAPI(r router.Router) {
	r.Post(auth.PathLogout, func(ctx router.Context) {
		m.stepUp.Revoke(ctx)
		m.strategy.Revoke(ctx)
		ctx.SetHeader("Location", auth.PathLogin)
		ctx.WriteStatus(302)
	}).Public()

	r.Get(auth.PathMe, m.handleMe).Authenticated()

	for _, a := range m.authenticators {
		a.Mount(r)
	}
}

// handleMe answers the profile of the authenticated caller: id, name, email, avatar and the grants of the project.
// An anonymous caller gets 401; a caller whose user no longer exists gets 404.
func (m *Module) handleMe(ctx router.Context) {
	userID := ctx.UserID()
	if userID == "" {
		ctx.WriteStatus(401)
		return
	}
	u, err := m.GetUser(userID)
	if err != nil {
		ctx.WriteStatus(404)
		return
	}
	profile := auth.ProfileDTO{Id: u.Id, Name: u.Name, Email: u.Email, Avatar: u.Avatar}
	if p := m.config.Permissions; p != nil && p.Grants != nil {
		grants, err := p.Grants.SubjectGrants(p.ProjectID, userID)
		if err != nil {
			ctx.WriteStatus(500)
			return
		}
		for _, g := range grants {
			profile.Grant(g.Resource, g.Actions)
		}
	}
	if err := ctx.Encode(&profile); err != nil {
		ctx.WriteStatus(500)
	}
}
