//go:build dev

package authority

import (
	"sync/atomic"

	"webtyp.com/auth"
	"webtyp.com/env"
	"webtyp.com/router"
	"webtyp.com/securityevent"
)

const (
	modeDevAutologin        = "dev_autologin"
	msgDevAutologinOpened   = "auth: DEV_AUTOLOGIN opened a session for user"
	msgDevAutologinRejected = "auth: DEV_AUTOLOGIN was rejected by every enabled authenticator — showing the normal login. The value must be the exact JSON the login form POSTs, and this machine's IP must be allowed for that user. Not retried until restart."
)

// newDevAutologin reads DEV_AUTOLOGIN and returns a per-module autologin
// handler, or nil when unset. Compiled only with -tags dev — see
// devlogin_off.go for the twin every other build gets.
//
// The returned handler replays the body through each enabled FormLogin in
// Enable order; the first that accepts it gets a real session issued. After
// one full rejection it never runs again in this process, so a wrong value
// costs one rate-limit strike, not one per request.
func newDevAutologin(m *Module) func(router.Context) string {
	body := env.Get(auth.EnvDevAutologin)
	if body == "" {
		return nil
	}
	raw := []byte(body)
	var failed atomic.Bool

	return func(ctx router.Context) string {
		if failed.Load() {
			return ""
		}

		for _, a := range m.authenticators {
			fl, ok := a.(auth.FormLogin)
			if !ok {
				continue
			}
			userID, err := fl.Login(ctx, raw)
			if err != nil {
				continue
			}
			if err := m.strategy.Issue(ctx, userID); err != nil {
				if m.log != nil {
					m.log("auth: devAutologin issue session failed:", err)
				}
				return ""
			}
			m.reportEvent(securityevent.Event{Kind: securityevent.LoginSucceeded, UserID: userID, Mode: modeDevAutologin})
			if m.log != nil {
				m.log(msgDevAutologinOpened, userID)
			}
			return userID
		}

		failed.Store(true)
		if m.log != nil {
			m.log(msgDevAutologinRejected)
		}
		return ""
	}
}
