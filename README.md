# webtyp/auth
<img src="docs/img/badges.svg">

Authentication mechanisms, sessions, identities, and OAuth providers for the
WebTyp ecosystem. Authorization belongs to `webtyp/rbac`. Both are siblings
that depend only on `webtyp/user` and never on each other.

> **BREAKING CHANGE**: `StateStore.CreateState` and `StateStore.ConsumeState` changed signatures to support browser-bound OAuth state nonces:
> - `CreateState(provider string) (state, nonce string, err error)`
> - `ConsumeState(state, nonce, provider string) error`
>
> Known consumers to update: `oauth2/oauth.go` (updated in this repo) and any custom implementations of `auth.StateStore`.

```mermaid
flowchart TD
    U[user] --> A[auth]
    U --> R[rbac]
    A --> C[app]
    R --> C
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) — Dependency rules, packages, local simulator

## Packages

- `auth` — Core contracts: `Mode` (one sign-in mode as an app chooses it), `Ports` (the pieces every mode receives),
  `ModeWithTables`, `MigrateModes`, `Authenticator`, `SessionIssuer`, `IdentityStore`, `StateStore`, `SessionRepo`,
  `Config`, OAuth types. Security events go through `webtyp.com/securityevent`.
- `authority` — Concrete module (`Module`) implementing the ports, caches,
  migrations, and middleware. Configures a secure opaque cookie session strategy by default using 256-bit CSPRNG entropy (`webtyp/crypto/rand`) for session IDs and OAuth states.
- `oauth2` + `oauth2/provider/google`, `oauth2/provider/microsoft` — OAuth flow
  and providers.
- `session/cookie` — Session transport: an opaque cookie over the session table, with a per-session `SessionPolicy` (absolute cap, idle limit, assurance).
- `passkey` — WebAuthn authenticator: enrollment and a step-up session (`AssuranceMultiFactor`) after a verified passkey.
- `clientassertion` — Machine clients: `private_key_jwt` (RFC 7523) bearer assertions become principals.
- `cfaccess` — Cloudflare Access: identifies each request by the signed `Cf-Access-Jwt-Assertion` (RS256, issuer, audience), mapping the verified e-mail to a user.
- `trusted_ip` — Sign-in with a RUT from a device the app's register trusts (`trustedip.Mode{Devices}`); owns the RUT
  (`RegisterRUT`, `UnregisterRUT`) and its entry screen.
- `email_password` — Sign-in with e-mail and password; owns the hash (`SetPassword`, `CheckPassword`).
- `local` — Development selector authenticator; no network, no env vars.

## Local door and internet door

An app served on two ports (`webtyp/server`: `Config.Port` is the local door, `Config.InternetPort` the
internet one, e.g. behind Cloudflare Tunnel) marks each request (`router.FromInternet(ctx)`; an unmarked
request counts as internet). On the internet door:

- the RUT login (`auth.PathLoginRUT`) and the first-admin setup (`auth.PathSetup`) answer 404;
- passkey enrolment (`passkey.PathRegisterOptions`, `passkey.PathRegister`) answers 404 — a passkey is
  registered only from the local door, so a stolen RUT on the internet can never add one;
- a passkey alone is a login: `passkey.PathVerifyOptions` and `passkey.PathVerify` work without a prior
  session (the user comes from the stored credential) and issue the step-up session
  (`model.AssuranceMultiFactor`), the only kind the internet door accepts for non-public routes.

`passkey.SignIn`, `passkey.Enroll` and `passkey.Setup` (files built only for the browser) are the browser half. `Enroll` registers a passkey on this device for the person signed in, and it only works on the local door. Both functions call `navigator.credentials` which requires a user gesture, so they must be called from a goroutine started by a click handler.

Login challenges asked for without a session are single use, expire after 5 minutes, and the expired
ones are deleted each time a new one is asked for.

## Sessions

`TokenTTL` is the **absolute** lifetime of the default strategy's sessions: an
active session still ends after it. `IdleTTL` is the idle limit within it.
The default cookie is **host-only** and named `__Host-<CookieName>`, so no
sibling subdomain can set or shadow it. **Upgrade note:** existing sessions are
dropped once on deploy (the cookie name changed and rows carry a new policy).

## Bank-grade setup

An SSO identity shared by every subdomain (single factor), plus a host-only
step-up session proven by a passkey, plus machine clients:

```go
authMod, _ := authority.New(db, auth.Config{IDs: ids}) // host-only default cookie

sso, _ := cookie.New(authMod, cookie.Options{
    Name: "sso", Domain: ".velty.cl",
    Policy: auth.SessionPolicy{Absolute: 43200, Idle: 1800, Assurance: model.AssuranceSingleFactor},
})
authMod.SetStrategy(sso)

stepUp, _ := cookie.New(authMod, cookie.Options{ // host-only: __Host-admin
    Name: "admin",
    Policy: auth.SessionPolicy{Absolute: 8 * 3600, Idle: 900, Assurance: model.AssuranceMultiFactor},
})
authMod.SetStepUpStrategy(stepUp)

pk, _ := passkey.New(db, ids, authMod, "https://iam.velty.cl")
ca, _ := clientassertion.New(db, clientKeys, "https://iam.velty.cl", authMod.Notify)
authMod.Enable(pk, ca)
```


The step-up session exists by default (cookie `__Host-stepup`, same lifetimes as the main one, `AssuranceMultiFactor`) and `SetStepUpStrategy` only changes it.

Routes marked `.RequiresMFA()` answer a single-factor caller with 401 and the
RFC 9470 challenge; the client then runs `passkey` verify to get the step-up
session. Run `passkey.Migrate` and `clientassertion.Migrate` next to
`authority.Migrate`. Logout revokes both sessions.

## Choosing the sign-in modes

An app lists its modes once, in its appkit configuration; appkit builds each one with `authority.Ports()` plus the
pieces only it can give (`MakeAdmin`, `HasAdmin`, `Built`) and never knows which mode it is:

```go
SignIn: []auth.Mode{
	trustedip.Mode{Devices: staffmanager.Definition},       // inside a clinic: RUT from a registered device
	passkey.Mode{Origin: "https://app.example.com"},        // from outside
}
```

Each mode serves its routes and gives its entry screen (`view.EntryScreen`); it asks its own route whether it is open
at the door the visit came through. While no administrator exists, `trusted_ip` offers its first-run setup on the
local network and `passkey` writes a one-time code in the server log: whoever presents it enrolls their passkey and
becomes the administrator. `auth.MigrateModes` creates the tables of the modes that keep them (passkey).

## Local Development

```go
scenarios := []local.Scenario{
    {ID: "user_admin", Name: "Alice", Email: "alice@example.com", Avatar: "", Roles: []string{"Administrator"}},
    {ID: "user_viewer", Name: "Bob", Email: "bob@example.com", Avatar: "", Roles: []string{"Viewer"}},
}
_ = authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))
authMod, _ := authority.New(db, auth.Config{IDs: ids, Events: broker})
rbacSvc, _ := rbac.New(db)
// seed subjects and assignments via rbac before mounting
for _, s := range scenarios { /* ensure user and AssignRole via rbacSvc */ }
localAuth := local.New(scenarios, authMod, authMod, local.WithAfterLogin("/"))
authMod.Enable(localAuth)
```

### LAN RUT Login Example

A LAN app identifies staff by RUT and checks the request's IP. Configure the
module first, then enable the mode — `Enable` registers on the module you built:

```go
authMod, _ := authority.New(db, auth.Config{
    IDs:     ids,
    Events:  broker, // required: every security event is reported on it (webtyp.com/securityevent)
    IdleTTL: 1800, // 30 min without activity ends the session (sliding); TokenTTL (default 24 h) is the absolute cap
    Permissions: &auth.Permissions{
        Grants:    rbacSvc, // satisfies auth.GrantLister structurally
        ProjectID: "main",
    },
})

// trustProxy is explicit, not an Option: behind a reverse proxy every request
// otherwise looks like it came from the proxy's own IP.
authMod.Enable(trustedip.New(authMod, trustedIPStore, authMod, authMod.Ports().Report, false))
```

The client builds its single-field login form from `auth.RUTLoginDataModel` and
posts it to `auth.PathLoginRUT`. `trustedIPStore` is the consumer's
`auth.TrustedIPStore` — answer it per user, not per network, or anyone inside
the LAN can log in as anyone else.

Which RUT belongs to which user is set with `trustedip.RegisterRUT` and removed with `trustedip.UnregisterRUT`;
registering a RUT mints a login credential, so only an administrator flow should call it.

> **Not yet supported: users without an email.** `CreateUser("", …)` writes an
> empty string, and a second one fails with `ErrEmailTaken` because the column
> is `Unique`. See `docs/PLAN.md` stage 4 — it is blocked on the
> `NULLABLE_COLUMNS` wave, not on this module.

Production builds use `oauth2.New` with a real `google.GoogleProvider` and never
register `local`.

## Development auto-login

In development environments, setting `DEV_AUTOLOGIN` automatically opens a real session on unauthenticated requests so you don't have to re-login every time the server restarts or times out.

The value must be the **exact JSON body** that the login form POSTs:
- For `trusted_ip`: `DEV_AUTOLOGIN={"code":"12345678-5"}`
- For `email_password`: `DEV_AUTOLOGIN={"email":"admin@example.com","password":"secretpassword"}`

The auto-login goes through the exact same validation path as a normal POST request (including IP allowlists, active account status, and rate limits). If logging in from that machine would fail, auto-login fails too.

Once rejected, auto-login latches off in that process to prevent rate limit starvation; to retry, restart the server. To view the actual login form, clear the variable and restart the server.

`DEV_AUTOLOGIN` is opt-in at build time: the dev server must be built with `-tags dev` (the `webtyp` dev environment does this). Any other build ignores the variable entirely.
