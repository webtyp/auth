//go:build !wasm

package stories

import (
	"net/http"

	"webtyp.com/apptest"
)

const (
	personRUT  = "12345678-5"
	personName = "Dra. Ana Rojas"
)

// NoRoleSeesLessAndIsRefused: the administrator adds a professional with no permission role; that professional signs
// in from the same machine, sees fewer menu entries than the administrator, and the server refuses them what only an
// administrator may read.
var NoRoleSeesLessAndIsRefused = apptest.Story[Given]{
	ID:   "H-ACCESS-03",
	Says: "Un rol sin permiso no ve la pantalla, y la operación le responde «sin permiso»",
	Run: func(app *apptest.RunningApp, g Given) {
		admin := app.NewSession()
		setUpFirstAdmin(admin, g)
		adminEntries := admin.Find(g.MenuEntry).Count()
		g.AddPersonWithoutRole(admin, personRUT, personName)

		person := signIn(app.NewSession(), g, personRUT)
		if n := person.Find(g.MenuEntry).Count(); n >= adminEntries {
			app.Fatalf("a person with no role sees %d menu entries, the administrator %d: want fewer", n, adminEntries)
		}
		if status := person.StatusOf(g.AdminOnlyRead); status != http.StatusForbidden {
			app.Fatalf("GET %s for a person with no role answered %d, want %d", g.AdminOnlyRead, status, http.StatusForbidden)
		}
	},
}
