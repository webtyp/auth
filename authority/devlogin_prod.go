//go:build prod

package authority

import (
	"webtyp.com/router"
)

// devAutologinBody is always nil in production builds: DEV_AUTOLOGIN is not
// even read, so setting it on a production server does nothing.
func devAutologinBody() []byte { return nil }

func (m *Module) devAutologin(router.Context) string { return "" }
