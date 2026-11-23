//go:build !wasm

package stories

import "webtyp.com/apptest"

// UnregisteredDeviceCannotSignIn: the right RUT from a machine nobody registered does not get in. The administrator
// sets the app up from another machine, so this one is not theirs.
var UnregisteredDeviceCannotSignIn = apptest.Story[Given]{
	ID:   "H-ACCESS-02",
	Says: "Desde un equipo no registrado no se puede entrar",
	Run: func(app *apptest.RunningApp, g Given) {
		setUpFirstAdmin(app.NewSessionOnAnotherDevice(), g)
		ses := app.NewSession().OpenHome()
		ses.FillField(fieldCode, adminRUT).Submit()
		ses.Find(g.SignInMessage).ExpectSomeText()
		ses.FindField(fieldCode).ExpectVisible()
		ses.Find(g.MenuEntry).ExpectCount(0)
	},
}
