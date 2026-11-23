//go:build !wasm

package stories

import "webtyp.com/apptest"

// A valid RUT (checksum included): the first administrator of a fresh install.
const (
	adminRUT  = "11111111-1"
	adminName = "Ana Administradora"
	fieldCode = "code" // auth.SetupData / auth.RUTLoginData: the field the person types the RUT into
	fieldName = "name" // auth.SetupData: the administrator's name
)

// SignInWithRUTSeesMenu: a professional signs in with their RUT from a registered device and sees the menu. The device
// is registered the way a real install does it: the first setup form, filled in on the machine that becomes theirs.
var SignInWithRUTSeesMenu = apptest.Story[Given]{
	ID:   "H-ACCESS-01",
	Says: "Un profesional entra con su RUT desde un equipo registrado y ve el menú de su rol",
	Run: func(app *apptest.RunningApp, g Given) {
		setUpFirstAdmin(app.NewSession(), g)
		signIn(app.NewSession(), g, adminRUT)
	},
}

// setUpFirstAdmin fills the first-setup form a fresh install shows, on the session's machine, which becomes the one
// device that administrator signs in from; the form leaves the person inside the app.
func setUpFirstAdmin(ses *apptest.Session, g Given) {
	ses.OpenHome().FillField(fieldCode, adminRUT).FillField(fieldName, adminName).Submit()
	ses.FindField(fieldCode).ExpectGone()
	ses.Find(g.MenuEntry).ExpectAtLeast(1)
}

// signIn signs in with rut through the real form on the session's machine, until the menu shows.
func signIn(ses *apptest.Session, g Given, rut string) *apptest.Session {
	ses.OpenHome().FillField(fieldCode, rut).Submit()
	ses.FindField(fieldCode).ExpectGone()
	ses.Find(g.MenuEntry).ExpectAtLeast(1)
	return ses
}
