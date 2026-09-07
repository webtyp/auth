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
	// Roles/Permissions se quedan sin poblar aquí a propósito: authority no
	// conoce RBAC (ver ARCHITECTURE.md). Un consumidor que necesite el
	// perfil completo lo compone en su propia raíz de composición, uniendo
	// esto con rbac.Service.
	profile := auth.ProfileDTO{Id: u.Id, Name: u.Name, Email: u.Email, Avatar: u.Avatar}
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

