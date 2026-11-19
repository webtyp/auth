//go:build dev && !wasm

package authority

import (
	"encoding/json"
	"sync/atomic"

	"webtyp.com/auth"
	"webtyp.com/env"
	"webtyp.com/fmt"
	"webtyp.com/input"
	"webtyp.com/router"
	"webtyp.com/securityevent"
)

const (
	modeDevAutologin        = "dev_autologin"
	msgDevAutologinOpened   = "auth: DEV_AUTOLOGIN opened a session for user"
	// One short line each: the reason of a rejection is already in the SECURITY
	// line the authenticator reports; this adds only which credential and tab.
	msgDevAutologinRejected = "auth: DEV_AUTOLOGIN rejected, login form shown on"
	msgDevAutologinPaused   = "auth: DEV_AUTOLOGIN paused after sign-out until restart on"
	msgDevAutologinInvalid  = "auth: DEV_AUTOLOGIN ignored, not a JSON object or list of objects:"

	devHostLocal  = "localhost"
	devHostPrefix = "user"       // credential N (N ≥ 2) signs in on userN.localhost
	devHostSuffix = ".localhost" // Chrome resolves *.localhost to loopback: same IP, own cookies
)

// devCredential is one entry of DEV_AUTOLOGIN and the state of its host.
type devCredential struct {
	body   []byte
	failed atomic.Bool // rejected once: never replayed again in this process
	paused atomic.Bool // signed out on its host: show the login until restart
}

// newDevAutologin reads DEV_AUTOLOGIN and returns its hooks, all nil when
// unset. Compiled only with -tags dev — devlogin_off.go is the twin every
// other build gets.
//
// open replays the credential of the request's host (localhost → 1,
// userN.localhost → N) through each enabled FormLogin in Enable order; the
// first that accepts it gets real sessions issued: the main one and the
// second-factor one, so screens that demand a second factor open in dev. A credential rejected once
// is never replayed again in this process, so a wrong value costs one
// rate-limit strike, not one per request.
func newDevAutologin(m *Module) devAutologin {
	value := env.Get(auth.EnvDevAutologin)
	if value == "" {
		return devAutologin{}
	}
	bodies, err := splitDevCredentials([]byte(value))
	if err != nil {
		// New runs before SetLog, so the warning waits for the first request.
		var told atomic.Bool
		return devAutologin{open: func(router.Context) string {
			if !told.Swap(true) && m.log != nil {
				m.log(msgDevAutologinInvalid, err)
			}
			return ""
		}}
	}
	creds := make([]*devCredential, len(bodies))
	for i, b := range bodies {
		creds[i] = &devCredential{body: b}
	}
	pick := func(ctx router.Context) (*devCredential, int) {
		i := devCredentialIndex(ctx.GetHeader(router.HeaderHost), len(creds))
		if i < 0 {
			return nil, 0
		}
		return creds[i], i + 1
	}

	return devAutologin{
		open: func(ctx router.Context) string {
			c, n := pick(ctx)
			if c == nil || c.failed.Load() || c.paused.Load() {
				return ""
			}
			for _, a := range m.authenticators {
				fl, ok := a.(auth.FormLogin)
				if !ok {
					continue
				}
				userID, err := fl.Login(ctx, c.body)
				if err != nil {
					continue
				}
				if err := m.strategy.Issue(ctx, userID); err != nil {
					if m.log != nil {
						m.log("auth: devAutologin issue session failed:", err)
					}
					return ""
				}
				if err := m.IssueStepUpSession(ctx, userID); err != nil {
					if m.log != nil {
						m.log("auth: devAutologin issue second-factor session failed:", err)
					}
					return ""
				}
				m.reportEvent(securityevent.Event{Kind: securityevent.LoginSucceeded, UserID: userID, Mode: modeDevAutologin})
				if m.log != nil {
					m.log(msgDevAutologinOpened, userID)
				}
				return userID
			}
			c.failed.Store(true)
			if m.log != nil {
				m.log(msgDevAutologinRejected, devTabHost(n))
			}
			return ""
		},
		// upgrade gives a one-factor session (e.g. one opened before this
		// process started) its second factor, but only on a host whose
		// credential is still live: a host paused by sign-out, where the
		// developer signed in by hand, keeps exactly what the login gave.
		upgrade: func(ctx router.Context, userID string) bool {
			c, _ := pick(ctx)
			if c == nil || c.failed.Load() || c.paused.Load() {
				return false
			}
			if err := m.IssueStepUpSession(ctx, userID); err != nil {
				if m.log != nil {
					m.log("auth: devAutologin issue second-factor session failed:", err)
				}
				return false
			}
			return true
		},
		pause: func(ctx router.Context) {
			c, _ := pick(ctx)
			if c == nil || c.paused.Swap(true) {
				return
			}
			if m.log != nil {
				m.log(msgDevAutologinPaused, ctx.GetHeader(router.HeaderHost))
			}
		},
		mount: func(r router.Router) {
			r.Get(auth.PathDevAutologinTabs, func(ctx router.Context) {
				if auth.ClientIP(ctx, false) != input.CanonicalIP("::1") {
					ctx.WriteStatus(404)
					return
				}
				ctx.SetHeader(router.HeaderContentType, router.ContentTypeJSON)
				ctx.WriteStatus(200)
				ctx.Write(devTabHostsJSON(len(creds)))
			}).Public()
		},
	}
}

// devCredentialIndex maps a request Host to the index of its credential:
// userN.localhost → N-1 (2 ≤ N ≤ count, else -1 = no autologin); any other
// host (localhost, 127.0.0.1, none) → 0, so a single credential works as
// before on every host.
func devCredentialIndex(host string, count int) int {
	h := auth.HostFromAddr(host)
	if len(h) <= len(devHostPrefix)+len(devHostSuffix) ||
		h[:len(devHostPrefix)] != devHostPrefix ||
		h[len(h)-len(devHostSuffix):] != devHostSuffix {
		return 0
	}
	digits := h[len(devHostPrefix) : len(h)-len(devHostSuffix)]
	n := 0
	for i := 0; i < len(digits); i++ {
		d := digits[i]
		if d < '0' || d > '9' || n > count {
			return -1
		}
		n = n*10 + int(d-'0')
	}
	if n < 2 || n > count {
		return -1
	}
	return n - 1
}

// devTabHost is the host credential n (1-based) signs in on.
func devTabHost(n int) string {
	if n == 1 {
		return devHostLocal
	}
	return devHostPrefix + devItoa(n) + devHostSuffix
}

// devTabHostsJSON is the body of auth.PathDevAutologinTabs: ["localhost","user2.localhost",…].
func devTabHostsJSON(count int) []byte {
	out := []byte{'['}
	for n := 1; n <= count; n++ {
		if n > 1 {
			out = append(out, ',')
		}
		out = append(out, '"')
		out = append(out, devTabHost(n)...)
		out = append(out, '"')
	}
	return append(out, ']')
}

func devItoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

var errDevNotObject = fmt.Err("every credential must be a JSON object")

// splitDevCredentials returns the JSON objects of value: the object itself, or
// each object of a list, byte for byte (each is replayed as the exact body the
// login form POSTs). Invalid JSON, an empty list or a non-object is an error.
func splitDevCredentials(value []byte) ([][]byte, error) {
	var list []json.RawMessage
	if err := json.Unmarshal(value, &list); err != nil {
		var one map[string]json.RawMessage
		if err2 := json.Unmarshal(value, &one); err2 != nil {
			return nil, err
		}
		list = []json.RawMessage{json.RawMessage(value)}
	}
	if len(list) == 0 {
		return nil, errDevNotObject
	}
	out := make([][]byte, len(list))
	for i, raw := range list {
		var obj map[string]json.RawMessage
		if json.Unmarshal(raw, &obj) != nil {
			return nil, errDevNotObject
		}
		out[i] = raw
	}
	return out, nil
}
