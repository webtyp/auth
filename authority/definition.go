package authority

import (
	"webtyp.com/input"
	"webtyp.com/model"
)

var UserModel = model.Definition{
	Name:  "user",
	Allow: model.Create | model.Read | model.Update | model.Delete,
	Rules: model.Rules{Create: model.AddMyBusinessRule, Read: model.HaveNoBusinessRule, Update: model.AddMyBusinessRule, Delete: model.AddMyBusinessRule},
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}, OmitEmpty: true, ServerOnly: true},
		{Name: "email", Type: input.Email(), OmitEmpty: true, DB: &model.FieldDB{Unique: true}, Item: model.ItemDescription},
		{Name: "name", Type: input.Text(), Item: model.ItemLabel},
		{Name: "phone", Type: input.Phone()},
		{Name: "status", Type: model.Text(), ServerOnly: true},
		{Name: "avatar", Type: model.Text(), ServerOnly: true},
		{Name: "created_at", Type: model.UnixTime(), ServerOnly: true},
	},
}

var SessionModel = model.Definition{
	Name: "session",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "expires_at", Type: model.UnixTime()},
		{Name: "ip", Type: model.Text()},
		{Name: "user_agent", Type: model.Text()},
		{Name: "created_at", Type: model.UnixTime()},
		{Name: "absolute_at", Type: model.UnixTime()},
		{Name: "idle_seconds", Type: model.UnixTime()},
		{Name: "assurance", Type: model.Int()},
	},
}

var IdentityModel = model.Definition{
	Name: "identity",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "provider", Type: model.Text()},
		{Name: "provider_id", Type: model.Text()},
		{Name: "email", Type: model.Text()},
		{Name: "created_at", Type: model.UnixTime()},
	},
}

var OAuthStateModel = model.Definition{
	Name: "oauth_state",
	Fields: model.Fields{
		{Name: "state", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "nonce_hash", Type: model.Text()},
		{Name: "provider", Type: model.Text()},
		{Name: "expires_at", Type: model.UnixTime()},
		{Name: "created_at", Type: model.UnixTime()},
	},
}

// MeModel is who the caller is: a read of crud that answers one row, the profile of the signed-in user and the
// grants they hold in the project. The rule reads the caller from crud.CurrentUser and takes no id, so nobody can
// read another person's profile. Any signed-in person may read it: DefaultGrants holds that grant and the app applies it to rbac.RoleAuthenticated.
var MeModel = model.Definition{
	Name:  "me",
	Allow: model.Read,
	Rules: model.Rules{Read: model.AddMyBusinessRule},
	Fields: model.Fields{
		{Name: "id", Type: model.Text()},
		{Name: "name", Type: model.Text()},
		{Name: "email", Type: model.Text()},
		{Name: "avatar", Type: model.Text()},
		{Name: "grants", Type: model.StructSlice(&MeGrantModel)},
	},
}

// MeGrantModel is one grant of the caller: the resource and its actions as model.Action.String() writes them ("crud").
var MeGrantModel = model.Definition{
	Name: "me_grant",
	Fields: model.Fields{
		{Name: "resource", Type: model.Text()},
		{Name: "actions", Type: model.Text()},
	},
}

// Definition declara el módulo: usuarios y «quién soy» por crud; sesiones, identidades y estado OAuth son internas.
var Definition = model.ModuleDefinition{
	Name:     "user", // el prefijo wire y RBAC de siempre
	Entities: []model.Definition{UserModel, MeModel, SessionModel, IdentityModel, OAuthStateModel},
}

// DefaultGrants is what every signed-in person may do with this module: read who they are. The composition root
// applies it to rbac.RoleAuthenticated, like any module's default grants.
var DefaultGrants = []model.Grant{{Resource: model.Resource(MeModel.Name), Actions: model.Read}}
