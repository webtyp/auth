package authority

import (
	"webtyp.com/crud"
	"webtyp.com/model"
)

// ErrSignedInUserNotFound answers a read of me whose session points at a user that no longer exists.
const ErrSignedInUserNotFound model.NotFound = "the signed-in user no longer exists: sign in again"

// Read answers me: one row, the profile of the caller and the grants they hold in the project. The caller comes from
// crud.CurrentUser and the filter is ignored, so nobody reads another person's profile.
func (p *Me) Read(a crud.CurrentUser, filter *Me, args crud.ReadArgs, m *Module) (model.ModelSlice, error) {
	if a.UserID == "" {
		return nil, ErrSignedInUserNotFound
	}
	u, err := m.GetUser(a.UserID)
	if err != nil {
		return nil, ErrSignedInUserNotFound
	}
	me := &Me{Id: u.Id, Name: u.Name, Email: u.Email, Avatar: u.Avatar}
	if perm := m.config.Permissions; perm != nil && perm.Grants != nil {
		grants, err := perm.Grants.SubjectGrants(perm.ProjectID, a.UserID)
		if err != nil {
			return nil, err
		}
		for _, g := range grants {
			if g.Actions == 0 {
				continue
			}
			me.Grants = append(me.Grants, MeGrant{Resource: string(g.Resource), Actions: g.Actions.String()})
		}
	}
	return &MeList{me}, nil
}
