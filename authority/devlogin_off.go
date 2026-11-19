//go:build !dev

package authority

import (
	"webtyp.com/router"
)

// newDevAutologin is always nil in every build without -tags dev:
// DEV_AUTOLOGIN is not even read, so setting it on a server does nothing.
func newDevAutologin(*Module) func(router.Context) string { return nil }
