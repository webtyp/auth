//go:build !prod

package authority

import (
	"webtyp.com/auth"
	"webtyp.com/env"
	"webtyp.com/router"
)

const (
	msgDevAutologinOpened   = "auth: DEV_AUTOLOGIN opened a session for user"
	msgDevAutologinRejected = "auth: DEV_AUTOLOGIN was rejected by every enabled authenticator — showing the normal login. The value must be the exact JSON the login form POSTs, and this machine's IP must be allowed for that user. Not retried until restart."
)

// devAutologinBody reads DEV_AUTOLOGIN. Development builds only — see
// devlogin_prod.go for the production twin.
func devAutologinBody() []byte {
	v := env.Get(auth.EnvDevAutologin)
	if v == "" {
		return nil
	}
	return []byte(v)
}

// devAutologin replays m.devLogin through each enabled FormLogin in Enable
// order; the first that accepts it gets a real session issued. After one
// full rejection it never runs again in this process, so a wrong value
// costs one rate-limit strike, not one per request.
func (m *Module) devAutologin(ctx router.Context) string {
	if m.devLoginFailed.Load() {
		return ""
	}

	for _, a := range m.authenticators {
		fl, ok := a.(auth.FormLogin)
		if !ok {
			continue
		}
		userID, err := fl.Login(ctx, m.devLogin)
		if err != nil {
			continue
		}
		if err := m.strategy.Issue(ctx, userID); err != nil {
			if m.log != nil {
				m.log("auth: devAutologin issue session failed:", err)
			}
			return ""
		}
		m.notify(auth.SecurityEvent{Type: auth.EventDevAutologin, UserID: userID})
		if m.log != nil {
			m.log(msgDevAutologinOpened, userID)
		}
		return userID
	}

	m.devLoginFailed.Store(true)
	if m.log != nil {
		m.log(msgDevAutologinRejected)
	}
	return ""
}
