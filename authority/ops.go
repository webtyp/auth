package authority

import (
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/auth"
)

var _ router.OperationModule = (*Module)(nil)

func (m *Module) MountOperations(reg router.OperationRegistry) {
	reg.Operation(auth.OpMe, m.opMe).Authenticated()
	reg.Operation(auth.OpListUsers, m.opListUsers).Requires("users", model.Read)
	reg.Operation(auth.OpUpsertUser, m.opUpsertUser).Requires("users", model.Create|model.Update).Accepts(&auth.User{})
	reg.Operation(auth.OpDeleteUser, m.opDeleteUser).Requires("users", model.Delete).Accepts(&auth.User{})

	reg.Operation(auth.OpRegisterLAN, m.opRegisterLAN).Requires(auth.ResourceLANIdentity, model.Create|model.Update).Accepts(&auth.RegisterLANArgs{})
	reg.Operation(auth.OpUnregisterLAN, m.opUnregisterLAN).Requires(auth.ResourceLANIdentity, model.Delete).Accepts(&auth.LANUserArgs{})
	reg.Operation(auth.OpGetLAN, m.opGetLAN).Requires(auth.ResourceLANIdentity, model.Read).Accepts(&auth.LANUserArgs{})
}

func (m *Module) opMe(ctx router.Context) {
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
	if p := m.config.Permissions; p != nil && p.Resolver != nil {
		for _, res := range p.Resources {
			profile.Grant(res, p.Resolver.AllowedActions(p.ProjectID, userID, res))
		}
	}
	if err := ctx.Encode(&profile); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opListUsers(ctx router.Context) {
	us, err := listUsers(m.db)
	if err != nil {
		ctx.WriteStatus(500)
		return
	}
	list := make(auth.UserList, 0, len(us))
	for i := range us {
		list = append(list, &us[i])
	}
	if err := ctx.Encode(&list); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opUpsertUser(ctx router.Context) {
	var u auth.User
	if err := ctx.Decode(&u); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if u.Id == "" {
		if _, err := createUser(m.db, m.ids, u.Email, u.Name, u.Phone); err != nil {
			ctx.WriteStatus(500)
		}
		return
	}
	if err := updateUser(m.db, m.ucache, u.Id, u.Name, u.Phone); err != nil {
		ctx.WriteStatus(500)
	}
}

func (m *Module) opDeleteUser(ctx router.Context) {
	var u auth.User
	if err := ctx.Decode(&u); err != nil {
		ctx.WriteStatus(400)
		return
	}
	if err := deleteUser(m.db, m.ucache, u.Id); err != nil {
		ctx.WriteStatus(500)
	}
}

