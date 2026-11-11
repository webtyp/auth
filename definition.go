package auth

import (
	"webtyp.com/input"
	"webtyp.com/model"
)

var LoginDataModel = model.Definition{
	Name: "login_data",
	Fields: model.Fields{
		{Name: "email", Type: input.Email(), NotNull: true},
		{Name: "password", Type: input.Password(), NotNull: true},
	},
}

// RUTLoginDataModel's wire field is named "code", not "rut": the whole
// point of trusted_ip is that neither the request nor the rendered <input
// name=…> should tell an outsider what kind of credential this asks for.
// ValidateRUT still runs the real checksum server-side under this generic
// name.
var RUTLoginDataModel = model.Definition{
	Name: "rut_login_data",
	Fields: model.Fields{
		{Name: "code", Type: input.Text(), NotNull: true},
	},
}

// SetupDataModel is what the first-run screen posts to PathSetup. Its
// credential field is "code" for the same reason RUTLoginDataModel's is —
// the wire never names the kind of credential — even though the person
// filling this one in is the administrator declaring their own.
var SetupDataModel = model.Definition{
	Name: "setup_data",
	Fields: model.Fields{
		{Name: "code", Type: input.Text(), NotNull: true},
		{Name: "name", Type: input.Text(), NotNull: true},
	},
}

var RegisterDataModel = model.Definition{
	Name: "register_data",
	Fields: model.Fields{
		{Name: "name", Type: input.Text(), NotNull: true},
		{Name: "email", Type: input.Email(), NotNull: true},
		{Name: "password", Type: input.Password(), NotNull: true},
		{Name: "phone", Type: input.Phone()},
	},
}

var ProfileDataModel = model.Definition{
	Name: "profile_data",
	Fields: model.Fields{
		{Name: "name", Type: input.Text(), NotNull: true},
		{Name: "phone", Type: input.Phone()},
	},
}

var PasswordDataModel = model.Definition{
	Name: "password_data",
	Fields: model.Fields{
		{Name: "current", Type: input.Password(), NotNull: true},
		{Name: "new", Type: input.Password(), NotNull: true},
		{Name: "confirm", Type: input.Password(), NotNull: true},
	},
}

