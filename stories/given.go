//go:build !wasm

// Package stories holds the user stories of the access domain (H-ACCESS-<NN>): signing in and what a person sees
// once inside. They run with webtyp.com/apptest against the consuming app; the app passes Given.
package stories

import (
	"webtyp.com/apptest"
	"webtyp.com/widget"
)

// Given is what the access stories need from the app: only what its chassis looks like. The people and devices
// they sign in with are created through the app's own doors (the first setup), never by the app.
type Given struct {
	MenuEntry     widget.Class // the class the app's chassis gives each menu entry (layout/platformd: platformd.ClsNavItem)
	SignInMessage widget.Class // where the sign-in screen writes what the last attempt answered (layout/login: login.ClsMessage)

	// AddPersonWithoutRole adds, from the administrator's session, a person who may sign in but holds no permission
	// role (mjosefa-cms: staff_manager/stories.AddProfessional).
	AddPersonWithoutRole func(admin *apptest.Session, rut, name string)
	// AdminOnlyRead is a GET path only an administrator may read (mjosefa-cms: the staff list operation).
	AdminOnlyRead string
}

// All are the access stories, in id order.
var All = apptest.Stories[Given]{SignInWithRUTSeesMenu, UnregisteredDeviceCannotSignIn, NoRoleSeesLessAndIsRefused}
