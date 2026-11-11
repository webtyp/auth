package authority

import (
	"webtyp.com/input"
	"webtyp.com/model"
)

var UserModel = model.Definition{
	Name:  "user",
	Allow: model.Create | model.Read | model.Update | model.Delete,
	Rules: model.Rules{Create: model.AddMyBusinessRule, Read: model.AddMyBusinessRule, Update: model.AddMyBusinessRule, Delete: model.AddMyBusinessRule},
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

var LANIPModel = model.Definition{
	Name: "lanip",
	Fields: model.Fields{
		{Name: "id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{RefColumn: "id"}, Ref: &UserModel},
		{Name: "ip", Type: model.Text()},
		{Name: "label", Type: model.Text()},
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

var LANIdentityModel = model.Definition{
	Name:  "lan_identity",
	Allow: model.Create | model.Read | model.Delete,
	Rules: model.Rules{Create: model.HaveNoBusinessRule, Read: model.HaveNoBusinessRule, Delete: model.HaveNoBusinessRule},
	Fields: model.Fields{
		{Name: "user_id", Type: model.Text(), DB: &model.FieldDB{PK: true}},
		{Name: "rut", Type: model.Text(), NotNull: true},
	},
}

// Definition declara el módulo: usuarios e identidades LAN por crud; sesiones, identidades, IP de LAN y estado OAuth son internas.
var Definition = model.ModuleDefinition{
	Name:     "user", // el prefijo wire y RBAC de siempre
	Entities: []model.Definition{UserModel, LANIdentityModel, SessionModel, IdentityModel, LANIPModel, OAuthStateModel},
}
