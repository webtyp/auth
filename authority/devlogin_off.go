//go:build !dev

package authority

import (
	"webtyp.com/router"
)

// devAutologinBody is always nil in every build without -tags dev:
// DEV_AUTOLOGIN is not even read, so setting it on a server does nothing.
func devAutologinBody() []byte { return nil }

func (m *Module) devAutologin(router.Context) string { return "" }
