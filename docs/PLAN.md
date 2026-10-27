---
PLAN: "feat(cfaccess): identify requests by the Cloudflare Access JWT; me sends grants as stored"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 5307545931739264509
PR: https://github.com/webtyp/auth/pull/8
REVIEWED_COMMIT: 03f9edbdcbf8ec32f81f6b4b3106558baf0afe1b
---

> Read AGENTS.md at the repo root before any change.

# PLAN — `cfaccess`: Cloudflare Access as a request identifier

## Why

An app served through **Cloudflare Tunnel** with **Cloudflare Access** in front receives, on every
request, the header `Cf-Access-Jwt-Assertion`: a JWT signed by Access (RS256) that says which
e-mail Access verified. The app must turn that header into a user — without a login form, a
password or a session cookie — and it must **never** trust the header without verifying the
signature, the issuer and the audience. This plan adds that as a new mode, `cfaccess`, built like
`clientassertion`: an `auth.RequestIdentifier`, so `authority.Authenticate()` picks it up with no
change to `authority`.

How the e-mail becomes a user: (1) an identity row `(provider "cloudflare_access", providerID =
e-mail)` → its user; (2) otherwise the user whose `Email` is that e-mail, and the identity row is
created then (same linking rule as `oauth2`); (3) otherwise anonymous. A user that is not `active`
is anonymous.

## Tools

```
go install webtyp.com/devflow/cmd/gotest@latest
go install webtyp.com/lang/cmd/langc@latest
go get webtyp.com/jwt@v0.1.29
```

Run the `go get` in the repo root **and** in `tests/` (a separate module: `tests/go.mod`).
`webtyp.com/jwt@v0.1.29` is the first tag with `ParseKeySet`/`VerifyRS256`. If `go get` fails
because that tag lacks them, stop and say so in the PR.

## Ecosystem search

- `auth/clientassertion`: the closest mode (a bearer JWT per request → `RequestIdentifier`); copy its
  shape (`New`, `Name`, empty `Mount`, `reject`, reason constants, `notify func(auth.SecurityEvent)`).
- `auth/oauth2`: links a provider identity to the user with the same e-mail through
  `IdentityStore.UserByEmail` + `UpsertIdentity`; reuse that rule.
- `webtyp/jwt` v0.1.29: `ParseKeySet`, `VerifyRS256`, `IdentityClaims` — reuse.
- `webtyp/fetch`: HTTP that also runs at the edge (used by `oauth2/provider/google`) — reuse for the JWKS.
- Nothing in `webtyp/*` or `veltylabs/*` mentions `Cf-Access` / `cloudflareaccess` → **new** package
  `webtyp.com/auth/cfaccess`.

## Design gate

1. **Prior art.** Cloudflare's own guide (validate `Cf-Access-Jwt-Assertion` with `coreos/go-oidc`:
   issuer = team domain, audience = the application AUD tag, keys from `/cdn-cgi/access/certs`);
   `oauth2-proxy` (trusts an upstream identity header only after verifying a JWT); Pomerium /
   Tailscale Serve (identity headers from a trusted proxy). All verify the signed token, never the
   plain `Cf-Access-Authenticated-User-Email` header. Same here.
2. **Novice-name test.** `cfaccess.New(cfaccess.Config{TeamDomain, Audience}, keys, store, notify)`;
   `cfaccess.NewKeySource(cfaccess.CertsURL(team))`; `auth.ProviderCloudflareAccess`;
   `auth.EventCloudflareAccessRejected`. "cf access" is the product name a reader searches for.
3. **Complexity ledger.** Concepts +3 (`Config`, `KeySource`, the mode) · files an app touches to
   enable it: 1 (its composition root) · call-site lines: ~4 · ways to do the same thing: +1 / −0.
4. **Where it belongs.** An authentication mode → `webtyp/auth`, next to `clientassertion`. Token
   verification stays in `webtyp/jwt`; HTTP in `webtyp/fetch`. Cloudflare-specific names (header,
   certs path, issuer format) live only here.
5. **What it deletes.** Nothing: new capability.

## APIs used

| Symbol | Exact signature | Tag | File |
|---|---|---|---|
| `jwt.KeySet` | opaque struct; zero value = no keys | jwt v0.1.29 | `rs256.go` |
| `jwt.ParseKeySet` | `func ParseKeySet(jwks string) (KeySet, error)` | jwt v0.1.29 | `rs256.go` |
| `jwt.VerifyRS256` | `func VerifyRS256(keys KeySet, token string) (IdentityClaims, Outcome, error)` — error = caller broken; `Forged` also for an unknown `kid` | jwt v0.1.29 | `rs256.go` |
| `jwt.IdentityClaims` | `struct { Iss, Sub, Email string; Aud []string; Iat, Nbf, Exp int64 }` + `func (c IdentityClaims) HasAudience(aud string) bool` | jwt v0.1.29 | `rs256.go` |
| `jwt.Outcome` | `Forged` (zero), `Valid`, `Expired` | jwt v0.1.29 | `jwt.go` |
| `fetch.Get` | `func Get(endpoint any) *Request` | fetch v0.1.29 | `fetch.go` |
| `(*fetch.Request).Send` | `func (r *Request) Send(callback func(*Response, error))` (asynchronous: wait on a channel, as `oauth2/provider/google/google.go:66-98` does) | fetch v0.1.29 | `fetch.go` |
| `fetch.Response` | field `Status int`; `func (r *Response) Text() string` | fetch v0.1.29 | `fetch.go` |
| `auth.IdentityStore` | `UserByID(id) (User, error)`, `UserByEmail(email) (User, error)`, `IdentityByProvider(provider, providerID) (Identity, error)`, `UpsertIdentity(userID, provider, providerID, email) error`, … | this repo | `user.go:278` |
| `auth.Principal` | `struct { UserID string; Assurance model.Assurance; IssuedAt time.Unix }` | this repo | `user.go:231` |
| `auth.RequestIdentifier` | `IdentifyRequest(ctx router.Context) (p Principal, handled bool)` | this repo | `user.go:255` |
| `router.Context` | `GetHeader(name string) string`, … | router (in `go.mod`) | — |
| `fmt.ToLower` | `func ToLower(s string) string` | fmt v1.0.0 | `strings.go` |
| `fmt.Contains` | `func Contains(Conv, search string) bool` | fmt v1.0.0 | `search.go` |
| `fmt.Convert(...).TrimSpace().String()` | trims spaces | fmt v1.0.0 | `replace.go` |
| `time.NowUnix` | as used in `clientassertion.go` | time (in `go.mod`) | — |

If a signature in the published tag differs from this table, stop and name the symbol in the PR;
never adapt it by guessing.

## Stage 1 — provider name and event type (`user.go`)

- Next to `const ProviderTrustedIP = "trusted_ip"` (line ~491) add:
  ```go
  // ProviderCloudflareAccess is the Identity.Provider of an e-mail that
  // Cloudflare Access verified (package cfaccess); ProviderId is that e-mail.
  const ProviderCloudflareAccess = "cloudflare_access"
  ```
- In the `SecurityEventType` const block, add **after** `EventClientAssertionRejected` (never in the
  middle: the values are serialised as integers):
  `EventCloudflareAccessRejected // cfaccess: a Cf-Access-Jwt-Assertion was refused (Reason says why)`
- In `String()`, add `case EventCloudflareAccessRejected: return "cloudflare_access_rejected"`.

## Stage 2 — `cfaccess/keys.go` (new)

```go
package cfaccess

import (
	"sync"

	"webtyp.com/fetch"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
	"webtyp.com/time"
)

const (
	httpsScheme = "https://"
	certsPath   = "/cdn-cgi/access/certs"
	httpOK      = 200

	// KeysMaxAge is how long (seconds) a fetched key set is reused before
	// Keys fetches it again.
	KeysMaxAge = 3600
	// RefreshMinInterval is the minimum time (seconds) between two network
	// fetches, whether forced by Refresh or retried after a failure.
	RefreshMinInterval = 60

	// ErrMsgKeysStatus: the certs endpoint answered with a non-200 status.
	ErrMsgKeysStatus = "cfaccess: certs endpoint status"
)

// CertsURL is where Cloudflare Access publishes the signing keys of a team.
//
// Example: cfaccess.CertsURL("acme.cloudflareaccess.com") → "https://acme.cloudflareaccess.com/cdn-cgi/access/certs"
func CertsURL(teamDomain string) string { return httpsScheme + teamDomain + certsPath }

// KeySource supplies the keys Access signs with. Keys returns the cached set
// (fetching it when absent or older than KeysMaxAge). Refresh fetches again
// unless the last fetch was less than RefreshMinInterval seconds ago; the
// Authenticator calls it once when a token's key is unknown (Access rotated
// its keys).
type KeySource interface {
	Keys() (jwt.KeySet, error)
	Refresh() (jwt.KeySet, error)
}

// NewKeySource fetches the JWKS at certsURL over HTTP(S) with webtyp/fetch.
//
// Example: keys := cfaccess.NewKeySource(cfaccess.CertsURL(team))
func NewKeySource(certsURL string) KeySource { return &remoteKeys{url: certsURL} }

type remoteKeys struct {
	url string

	mu        sync.Mutex
	set       jwt.KeySet
	err       error // last fetch error; nil after a success
	fetchedAt int64 // unix seconds of the last successful fetch; 0 = never
	triedAt   int64 // unix seconds of the last network attempt; 0 = never
}

func (r *remoteKeys) Keys() (jwt.KeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fetchedAt != 0 && now()-r.fetchedAt < KeysMaxAge {
		return r.set, nil
	}
	return r.fetchLocked()
}

func (r *remoteKeys) Refresh() (jwt.KeySet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.fetchLocked()
}

// fetchLocked is the only place the network is used. Within
// RefreshMinInterval of the previous attempt it answers from memory: the
// cached set after a success, the same error after a failure (a failing
// endpoint is never hammered once per request).
func (r *remoteKeys) fetchLocked() (jwt.KeySet, error) {
	if r.triedAt != 0 && now()-r.triedAt < RefreshMinInterval {
		if r.err != nil {
			return jwt.KeySet{}, r.err
		}
		return r.set, nil
	}
	r.triedAt = now()
	body, err := getText(r.url)
	if err == nil {
		var set jwt.KeySet
		set, err = jwt.ParseKeySet(body)
		if err == nil {
			r.set, r.err, r.fetchedAt = set, nil, r.triedAt
			return set, nil
		}
	}
	r.err = err
	return jwt.KeySet{}, err
}

// getText waits for webtyp/fetch's callback (same pattern as
// oauth2/provider/google).
func getText(url string) (string, error) {
	var body string
	var errOut error
	done := make(chan bool)
	fetch.Get(url).Send(func(resp *fetch.Response, err error) {
		defer func() { done <- true }()
		if err != nil {
			errOut = err
			return
		}
		if resp.Status != httpOK {
			errOut = fmt.Err(ErrMsgKeysStatus, resp.Status)
			return
		}
		body = resp.Text()
	})
	<-done
	return body, errOut
}

func now() int64 { return int64(time.NowUnix()) }
```

Check `time.NowUnix()`'s return type in the `webtyp.com/time` version of `go.mod` (it is converted
with `int64(...)` exactly as `jwt.now()` does); do not change the arithmetic.

## Stage 3 — `cfaccess/cfaccess.go` (new)

```go
// Package cfaccess identifies a request by the JWT that Cloudflare Access
// adds to every request it lets through (header Cf-Access-Jwt-Assertion).
// The token is verified (RS256 signature, issuer, audience, expiry) before
// anything in it is believed; the e-mail inside becomes a user of this app.
//
// Mount registers nothing: the credential rides on every request.
package cfaccess

import (
	"webtyp.com/auth"
	"webtyp.com/fmt"
	"webtyp.com/jwt"
	"webtyp.com/model"
	"webtyp.com/router"
	"webtyp.com/time"
)

const (
	// HeaderAssertion is the header Cloudflare Access adds to each request.
	HeaderAssertion = "Cf-Access-Jwt-Assertion"

	ErrMsgEmptyTeamDomain   = "cfaccess: team domain is required"
	ErrMsgTeamDomainFormat  = "cfaccess: team domain must be a bare host such as acme.cloudflareaccess.com"
	ErrMsgEmptyAudience     = "cfaccess: audience (application AUD tag) is required"
	ErrMsgNilKeySource      = "cfaccess: key source is required"
	ErrMsgNilIdentityStore  = "cfaccess: identity store is required"

	statusActive = "active" // auth.User.Status of an enabled account (same literal authority writes)
	pathSeparator = "/"
)

// Reasons recorded in auth.EventCloudflareAccessRejected.
const (
	reasonKeysUnavailable = "keys_unavailable"
	reasonSignature       = "signature"
	reasonExpired         = "expired"
	reasonIssuer          = "issuer"
	reasonAudience        = "audience"
	reasonNoEmail         = "no_email"
	reasonUnknownEmail    = "unknown_email"
	reasonInactive        = "inactive"
)

// Config is what the Access application declares in the Cloudflare
// dashboard. Neither value is a secret.
type Config struct {
	// TeamDomain is the bare host of the Zero Trust team,
	// e.g. "acme.cloudflareaccess.com" (no scheme, no path).
	TeamDomain string
	// Audience is the application's "Application Audience (AUD) Tag".
	Audience string
}

// Authenticator turns a verified Access token into a principal.
type Authenticator struct {
	issuer   string
	audience string
	keys     KeySource
	store    auth.IdentityStore
	notify   func(auth.SecurityEvent)
}

var (
	_ auth.Authenticator     = (*Authenticator)(nil)
	_ auth.RequestIdentifier = (*Authenticator)(nil)
)

// New builds the mode. notify may be nil (no security events).
//
// Example:
//
//	keys := cfaccess.NewKeySource(cfaccess.CertsURL("acme.cloudflareaccess.com"))
//	cfa, err := cfaccess.New(cfaccess.Config{TeamDomain: "acme.cloudflareaccess.com", Audience: aud}, keys, authMod, authMod.Notify)
//	authMod.Enable(cfa)
func New(cfg Config, keys KeySource, store auth.IdentityStore, notify func(auth.SecurityEvent)) (*Authenticator, error) {
	switch {
	case cfg.TeamDomain == "":
		return nil, fmt.Err(ErrMsgEmptyTeamDomain)
	case fmt.Contains(cfg.TeamDomain, pathSeparator):
		return nil, fmt.Err(ErrMsgTeamDomainFormat)
	case cfg.Audience == "":
		return nil, fmt.Err(ErrMsgEmptyAudience)
	case keys == nil:
		return nil, fmt.Err(ErrMsgNilKeySource)
	case store == nil:
		return nil, fmt.Err(ErrMsgNilIdentityStore)
	}
	return &Authenticator{
		issuer:   httpsScheme + cfg.TeamDomain,
		audience: cfg.Audience,
		keys:     keys,
		store:    store,
		notify:   notify,
	}, nil
}

func (a *Authenticator) Name() string { return auth.ProviderCloudflareAccess }

// Mount registers nothing: the token rides on every request.
func (a *Authenticator) Mount(router.Router) {}

// IdentifyRequest: no header → not this kind of request (handled false).
// Any header is final: a failure is anonymous AND handled, so a session
// cookie riding along cannot rescue a bad token.
func (a *Authenticator) IdentifyRequest(ctx router.Context) (auth.Principal, bool) {
	token := ctx.GetHeader(HeaderAssertion)
	if token == "" {
		return auth.Principal{}, false
	}
	keys, err := a.keys.Keys()
	if err != nil {
		return a.reject("", reasonKeysUnavailable)
	}
	claims, outcome, err := jwt.VerifyRS256(keys, token)
	if err == nil && outcome == jwt.Forged {
		// Access may have rotated its keys: one forced refresh, then final.
		if fresh, ferr := a.keys.Refresh(); ferr == nil {
			claims, outcome, err = jwt.VerifyRS256(fresh, token)
		}
	}
	if err != nil || outcome == jwt.Forged {
		return a.reject("", reasonSignature)
	}
	if outcome == jwt.Expired {
		return a.reject("", reasonExpired)
	}
	if claims.Iss != a.issuer {
		return a.reject("", reasonIssuer)
	}
	if !claims.HasAudience(a.audience) {
		return a.reject("", reasonAudience)
	}
	email := fmt.ToLower(fmt.Convert(claims.Email).TrimSpace().String())
	if email == "" {
		return a.reject("", reasonNoEmail)
	}
	userID, ok := a.userFor(email)
	if !ok {
		return a.reject(email, reasonUnknownEmail)
	}
	u, err := a.store.UserByID(userID)
	if err != nil || u.Status != statusActive {
		return a.reject(userID, reasonInactive)
	}
	return auth.Principal{UserID: u.Id, Assurance: model.AssuranceSingleFactor}, true
}

// userFor resolves the e-mail: the linked identity first; otherwise the user
// with that e-mail, linking it now (the oauth2 rule).
func (a *Authenticator) userFor(email string) (string, bool) {
	if id, err := a.store.IdentityByProvider(auth.ProviderCloudflareAccess, email); err == nil {
		return id.UserId, true
	}
	u, err := a.store.UserByEmail(email)
	if err != nil {
		return "", false
	}
	if err := a.store.UpsertIdentity(u.Id, auth.ProviderCloudflareAccess, email, email); err != nil {
		return "", false
	}
	return u.Id, true
}

// reject reports the refusal and answers "handled, anonymous". who is the
// e-mail or user id when known, "" otherwise.
func (a *Authenticator) reject(who, reason string) (auth.Principal, bool) {
	if a.notify != nil {
		a.notify(auth.SecurityEvent{Type: auth.EventCloudflareAccessRejected, UserID: who, Reason: reason, Timestamp: time.NowUnix()})
	}
	return auth.Principal{}, true
}
```

Anti-footguns:
- **Never** read `Cf-Access-Authenticated-User-Email` or any other unsigned header.
- Do not touch `authority`: `authority.Authenticate()` already asks every enabled `RequestIdentifier`
  first (`authority/middleware.go`, `resolve`).

## Stage 4 — `tests/cfaccess_test.go` (new, `//go:build !wasm`, `package tests`)

Use the existing helpers `newTestDB(t)` and `testIDs`, `authority.New(db, auth.Config{IDs: testIDs})`
as the `auth.IdentityStore`, and `&mock.Context{InMethod: "GET", InPath: "/api/x"}` +
`ctx.SetHeader(cfaccess.HeaderAssertion, tok)` (as `clientassertion_test.go` does).

Test helpers in the file (stdlib allowed in tests): `crypto/rsa`, `crypto/rand`, `crypto/sha256`,
`crypto`, `math/big`, `time`, `net/http/httptest`, plus `webtyp.com/base64`:

```go
type fakeKeys struct {
	set       jwt.KeySet
	err       error
	fresh     jwt.KeySet // what Refresh returns when hasFresh
	hasFresh  bool
	refreshed int
}

func (f *fakeKeys) Keys() (jwt.KeySet, error) { return f.set, f.err }

func (f *fakeKeys) Refresh() (jwt.KeySet, error) {
	f.refreshed++
	if f.err != nil {
		return jwt.KeySet{}, f.err
	}
	if f.hasFresh {
		return f.fresh, nil
	}
	return f.set, nil
}
```

- `jwksOf(kid string, k *rsa.PrivateKey) string` → `{"keys":[{"kid":"<kid>","kty":"RSA","e":"<b64url E>","n":"<b64url N>"}]}`, parsed with `jwt.ParseKeySet`.
- `token(t, kid, k, payload string) string` — header `{"alg":"RS256","kid":"<kid>","typ":"JWT"}`,
  RS256 signature with `rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sha256(signingInput))`.
- Constants: `team = "acme.cloudflareaccess.com"`, `iss = "https://acme.cloudflareaccess.com"`,
  `aud = "AUD-TAG-1"`. Payload base: `{"iss":iss,"sub":"cf-sub-1","email":"ana@clinica.cl","aud":[aud],"iat":now,"exp":now+600}`.
- Events captured with `notify := func(e auth.SecurityEvent) { events = append(events, e) }`.

| Test | Setup → call | Expected |
|---|---|---|
| `TestCFAccess_NewValidation` | `New` with: empty TeamDomain; `"https://acme.cloudflareaccess.com"`; empty Audience; nil keys; nil store | errors whose text equals `ErrMsgEmptyTeamDomain`, `ErrMsgTeamDomainFormat`, `ErrMsgEmptyAudience`, `ErrMsgNilKeySource`, `ErrMsgNilIdentityStore` |
| `TestCFAccess_NoHeader` | ctx without the header | `handled == false`, zero principal, no event |
| `TestCFAccess_ValidLinksByEmail` | `m.CreateUser("ana@clinica.cl","Ana","")`; valid token | `handled`, `UserID == user.Id`; then `m.IdentityByProvider(auth.ProviderCloudflareAccess, "ana@clinica.cl")` returns that user |
| `TestCFAccess_EmailCaseInsensitive` | user `ana@clinica.cl`; token e-mail `"  ANA@Clinica.cl "` | `UserID == user.Id` |
| `TestCFAccess_UnknownEmail` | no user with that e-mail | handled, anonymous, one event reason `unknown_email`, `UserID == "ana@clinica.cl"` |
| `TestCFAccess_WrongAudience` | `"aud":["OTHER"]` | reason `audience` |
| `TestCFAccess_WrongIssuer` | `"iss":"https://evil.cloudflareaccess.com"` | reason `issuer` |
| `TestCFAccess_Expired` | `exp: now-3600` | reason `expired` |
| `TestCFAccess_BadSignatureRefreshesOnce` | key set of key A; token signed by key B, same kid | reason `signature`; `fakeKeys.refreshed == 1` |
| `TestCFAccess_RotatedKeyAccepted` | `set` = key A, `fresh` = key B (`hasFresh`); token signed by B | handled, `UserID == user.Id`, `refreshed == 1` |
| `TestCFAccess_KeysUnavailable` | `fakeKeys{err: errors.New("down")}` | reason `keys_unavailable` |
| `TestCFAccess_SuspendedUser` | user created then `m.SuspendUser(id)` | reason `inactive` |
| `TestCFAccess_ThroughAuthority` | `m.Enable(cfa)`; run `m.Authenticate()` around a handler that records `ctx.UserID()` | recorded id == user.Id |
| `TestKeySource_CachesAndThrottles` | `httptest.NewServer` serving `jwksOf(...)` and counting hits; `ks := cfaccess.NewKeySource(srv.URL)`; `Keys()`, `Keys()`, `Refresh()` | 1 hit; all three return a set that verifies a token |
| `TestKeySource_ErrorStatus` | server answers 500 | `Keys()` error text starts with `ErrMsgKeysStatus`; a second `Keys()` within the minute does not hit the server again (hits == 1) |
| `TestCertsURL` | `CertsURL("acme.cloudflareaccess.com")` | `"https://acme.cloudflareaccess.com/cdn-cgi/access/certs"` |

The event `String()` test: if a test enumerates event names (`grep -rn "client_assertion_rejected" tests`),
add `cloudflare_access_rejected` there too.

## Stage 5 — docs

- `README.md`, section **Packages**: add
  `- \`cfaccess\` — Cloudflare Access: identifies each request by the signed \`Cf-Access-Jwt-Assertion\` (RS256, issuer, audience), mapping the verified e-mail to a user.`
- `docs/ARCHITECTURE.md`: in the list/diagram of modes, add `cfaccess` next to `clientassertion`,
  with one paragraph: what it trusts (only the signed token), how the e-mail maps to a user (identity
  row, else `UserByEmail` + link), that it never issues a session, and that an app served both on a
  LAN and through a tunnel enables it only on the tunnel listener when another mode trusts IPs.

## Stage 6 — translations

Run `langc sync .` (root) and fill every empty value it reports (all languages of
`lang.Supported()` minus `en`). If it reports nothing, change nothing.

## Stage 7 — `me` sends the grants as stored (`user.go`, `authority/ops.go`)

**Why.** Today `opMe` asks an `ActionResolver` once per resource of `Permissions.Resources`, a list every app
writes by hand; the admin's wildcard grant (`*`) reaches the browser only for the resources of that list, so a
screen missing from it is hidden even from the admin. From now on `opMe` sends the subject's grants **as stored**
(`*:crud` included) and the browser evaluates them with `model.AnyGrant`, the same rule the server uses.

**Ecosystem search.** `model.Grant`, `model.AnyGrant`, `model.Grant.Matches`, `model.ParseAction`
(`webtyp.com/model` v0.2.6, `rbac.go`) → reuse. `webtyp.com/rbac` v0.0.22 adds
`(*Service).SubjectGrants(projectID, subjectID string) ([]model.Grant, error)`; `auth` must NOT import `rbac`: it
declares the port below and `rbac.Service` satisfies it structurally (the composition root injects it).

**Design gate.**
1. *Prior art:* CASL sends `{action:'manage', subject:'all'}` and its client `can()` understands it; Casbin
   `GetImplicitPermissionsForUser` hands out stored rows; Spring Security exposes `GrantedAuthority` as stored.
2. *Novice names:* `auth.GrantLister` («something that lists grants»), `Permissions.Grants`,
   `profile.Can(resource, action)` — the same verb as `rbac.Service.Can`.
3. *Ledger:* concepts +1 (`GrantLister`) / −2 (`ActionResolver`, `Permissions.Resources`); lines in every app −10
   (the hand list and its adapter); ways to evaluate a wildcard −1 (the browser reuses `model.Grant.Matches`).
4. *Where:* the port lives in its consumer (`auth`), the rows in `rbac`, the rule in `model`.
5. *Deletes:* `ActionResolver`, `Permissions.Resolver`, `Permissions.Resources`, `ProfileDTO.Allows`.

**`user.go`.** Replace the `ActionResolver` interface and the `Permissions` struct (lines 390-403) with:

```go
// GrantLister lists the grants a subject holds within a project, as stored: a
// wildcard grant stays {Resource: model.Wildcard}. rbac.Service satisfies it
// structurally (SubjectGrants); auth never imports rbac — the composition root
// injects it.
type GrantLister interface {
	SubjectGrants(projectID, subjectID string) ([]model.Grant, error)
}

// Permissions configures opMe to send ProfileDTO.Permissions.
// nil (the default) ⇒ opMe sends no permissions — closed by default.
type Permissions struct {
	Grants    GrantLister
	ProjectID string
}
```

Update the comment on `Config.Permissions` to «… composes identity (this module) with authorization (the injected
`GrantLister`) into `ProfileDTO.Permissions`».

Replace `ProfileDTO.Allows` (whole function and its comment) with:

```go
// Can reports whether the profile holds action on resource — the ONLY consumer of
// the wire format. Each entry is parsed back into a model.Grant and evaluated with
// model.Grant.Matches, the same rule the server applies, so "*:crud" means every
// resource on both sides. An illegible entry grants nothing.
func (p ProfileDTO) Can(resource model.Resource, action model.Action) bool {
	for _, perm := range p.Permissions {
		i := fmt.LastIndex(perm, ":")
		if i < 0 {
			continue
		}
		actions, err := model.ParseAction(perm[i+1:])
		if err != nil {
			continue
		}
		if (model.Grant{Resource: model.Resource(perm[:i]), Actions: actions}).Matches(resource, action) {
			return true
		}
	}
	return false
}
```

Change the field comment of `ProfileDTO.Permissions` to `// "resource:actions" entries as stored, e.g. "service:rc", "*:crud"`.
`Grant(resource, actions)` stays unchanged (the only producer).

**`authority/ops.go`, `opMe`.** Replace the block `if p := m.config.Permissions; p != nil && p.Resolver != nil { … }` with:

```go
	if p := m.config.Permissions; p != nil && p.Grants != nil {
		grants, err := p.Grants.SubjectGrants(p.ProjectID, userID)
		if err != nil {
			ctx.WriteStatus(500)
			return
		}
		for _, g := range grants {
			profile.Grant(g.Resource, g.Actions)
		}
	}
```

Check: `grep -rn "ActionResolver\|AllowedActions\|Permissions.Resources\|\.Allows(" --include=*.go .` → empty.

## Stage 8 — tests and docs of Stage 7

**`tests/permissions_me_test.go`.** Replace `fakeResolver` with:

```go
// fakeGrants stands in for rbac.Service, which auth must never import.
type fakeGrants struct {
	grants []model.Grant
	err    error
}

func (f *fakeGrants) SubjectGrants(projectID, subjectID string) ([]model.Grant, error) {
	return f.grants, f.err
}
```

| Test | Setup | Expected |
|---|---|---|
| `TestMeComposesPermissions` (rewrite) | `fakeGrants{grants: {service_catalog, Read\|Update}}` | `Permissions == ["service_catalog:ru"]`; `Can(service_catalog, Read)` true; `Can(service_catalog, Delete)` false; `Can(staff, Read)` false |
| `TestMeSendsWildcardAsStored` (new) | `fakeGrants{grants: {model.Wildcard, model.AllActions}}` | `Permissions == ["*:crud"]`; `Can("anything", model.Delete)` true |
| `TestMeGrantsErrorIs500` (new) | `fakeGrants{err: errors.New("db down")}` | `me` answers status 500 — code below |
| `TestMeClosedByDefault` (keep) | `nil` Permissions; and `&auth.Permissions{ProjectID: "main"}` with nil `Grants` | no permissions |
| `TestGrantCanRoundTrip` (rename of `TestGrantAllowsRoundTrip`) | same table; assert `Can(resCatalog, model.Read)` instead of `Allows` | as today |
| `TestCanIgnoresIllegibleEntry` (new) | `ProfileDTO{Permissions: []string{"service_catalog:xyz", "nocolon"}}` | `Can(service_catalog, Read)` false |

`TestMeGrantsErrorIs500` (same setup as the existing helper `meProfile`, but it reads the status instead of decoding;
`mock.Context` has an exported `Status int` field set by `WriteStatus`):

```go
func TestMeGrantsErrorIs500(t *testing.T) {
	db := newTestDB(t)
	m, err := authority.New(db, auth.Config{IDs: testIDs, Permissions: &auth.Permissions{
		Grants: &fakeGrants{err: errors.New("db down")}, ProjectID: "main",
	}})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.CreateUser("me@test.com", "Me", "")
	if err != nil {
		t.Fatal(err)
	}
	reg := &mockOpRegistry{ops: make(map[string]*mockRoute)}
	m.MountOperations(reg)
	ctx := &mock.Context{}
	ctx.SetUserID(u.Id)
	reg.ops[auth.OpMe].handler(ctx)
	if ctx.Status != 500 {
		t.Fatalf("me with a failing GrantLister: status %d, want 500", ctx.Status)
	}
}
```

Use the stdlib `errors` package in this test file only (tests are not WASM).

`tests/remember_test.go:27`: replace `got.Allows("reservation")` with `got.Can("reservation", model.Read)` (add the
`webtyp.com/model` import if missing).

**Docs.** In `README.md` (the `authority.New` example, ~line 121) and `docs/ARCHITECTURE.md` («In-Library `opMe`
Composition & ProfileDTO»): the example becomes
`Permissions: &auth.Permissions{Grants: rbacSvc /* satisfies auth.GrantLister structurally */, ProjectID: "main"}`
(no `Resources`), and the sentence becomes «`ProfileDTO` provides `Grant(resource, actions)` to produce wire
permissions as stored ("resource:actions", `"*:crud"` for a wildcard) and `Can(resource, action)` to evaluate them
on the client with `model.Grant.Matches` — the same rule as the server».

## Delivery check

```
GOPRIVATE=webtyp.com/*,github.com/veltylabs/* GOFLAGS=-mod=mod gotest
cd tests && GOPRIVATE=webtyp.com/*,github.com/veltylabs/* GOFLAGS=-mod=mod gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission or report progress: when the check passes, commit, push and open
  the PR. Stuck for 30 minutes: open the PR anyway listing what fails.
- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or
  `git stash` on your own work. Never edit a generated file (`models_orm.go`).
- `git diff --stat main` lists: `user.go`, `authority/ops.go`, `tests/permissions_me_test.go`, `tests/remember_test.go`, `cfaccess/keys.go`, `cfaccess/cfaccess.go`,
  `tests/cfaccess_test.go`, `README.md`, `docs/ARCHITECTURE.md`, `go.mod`, `go.sum`, `tests/go.mod`,
  `tests/go.sum`, `AGENTS.md`, this `docs/PLAN.md`, and `lang.json` only if Stage 6 created it.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `user.go` | constant and event present; existing tests pass |
| 2 | `cfaccess/keys.go`, `go.mod`, `go.sum` | compiles |
| 3 | `cfaccess/cfaccess.go` | compiles |
| 4 | `tests/cfaccess_test.go`, `tests/go.mod`, `tests/go.sum` | 16 tests pass |
| 5 | `README.md`, `docs/ARCHITECTURE.md` | sections present |
| 6 | `lang.json` (if any) | `langc sync .` reports no empty value |
| 7 | `user.go`, `authority/ops.go` | `grep -rn "ActionResolver\|AllowedActions\|\.Allows(" --include=*.go .` empty |
| 8 | `tests/permissions_me_test.go`, `tests/remember_test.go`, `README.md`, `docs/ARCHITECTURE.md` | 6 permission tests pass |
