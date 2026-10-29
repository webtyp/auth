---
PLAN: "feat: the internet door — RUT login, first-admin setup and passkey enrolment refuse it; a passkey alone is a login (no prior session)"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 11813570761818200614
---

> Read AGENTS.md at the repo root before any change.

# PLAN — `auth` on the internet door

## Why

`veltylabs/mjosefa-cms` will serve the same app on two ports (decisions D8 and D25 of
`veltylabs/mjosefa-cms/docs/MVP_DEPLOYMENT_ROADMAP.md`): the clinic's network, where a person logs
in with their RUT on a registered device and, once, registers a passkey on their phone; and the
internet (Cloudflare Tunnel), where **only** that passkey works and nothing can be registered.
Through the tunnel every visit arrives from `127.0.0.1`, which the first-admin setup assigned to
the admin's device: today anyone who knows the admin's RUT would log in as admin from the internet.
`webtyp.com/router` v0.4.12 lets code ask `router.FromInternet(ctx)` (unmarked = internet);
`webtyp.com/server` marks each listener (plan in flight) and demands a passkey session for every
non-public route on the internet door. This plan does the `auth` part:

1. `trusted_ip` (RUT login and first-admin setup) does not exist on the internet door: 404.
2. Passkey enrolment (`PathRegisterOptions`, `PathRegister`) does not exist on the internet door: 404.
3. A passkey **is** a login: `PathVerifyOptions`/`PathVerify` work **without** a prior session
   (discoverable credential; the user comes from the stored credential) and issue the step-up
   session (`model.AssuranceMultiFactor`). With a session, they keep working as today (step-up).

## Design gate (api-design)

1. **Prior art.** Microsoft Entra Conditional Access lets an organization block «register
   security info» outside trusted locations
   (https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration).
   `go-webauthn/webauthn` offers a discoverable (usernameless) login where the user is found from
   the credential (`BeginDiscoverableLogin`/`FinishDiscoverableLogin`,
   https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn). Here the stored challenge is found
   by its own value (`server.UnverifiedChallenge`), because there is no session before login.
2. **Names.** No new exported name: the routes keep their paths; only who may call them changes.
3. **Ledger.** Concepts +0, ways to log in from the internet: 1 (passkey).
4. **Where.** `auth/trusted_ip` and `auth/passkey`, the owners of those routes.
5. **Deletes.** Nothing.

## APIs used

| Symbol | Exact | Tag |
|---|---|---|
| `router.FromInternet` | `func FromInternet(ctx Context) bool` (true unless the request is marked `router.NetworkLocal`) | router v0.4.12 |
| `router.ContextKeyNetwork`, `router.NetworkLocal`, `router.NetworkInternet` | `"Network"`, `"local"`, `"internet"` | router v0.4.12 |
| `server.UnverifiedChallenge` | `func UnverifiedChallenge(rawResponse string) ([]byte, error)` (package `webtyp.com/webauthn/server`) | webauthn v0.1.16 |

Both are already required in `go.mod` (auth v0.0.86).

## Stage 1 — `trusted_ip/`

In `(*Authenticator).Mount`, the `auth.PathLoginRUT` handler and **every** handler mounted by
`mountSetup` start with:

```go
if router.FromInternet(ctx) {
	ctx.WriteStatus(statusNotFound) // the RUT login and the setup do not exist on the internet door
	return
}
```

`statusNotFound = 404` as a named constant in that package if none exists. `Login` (the method the
handler calls, also used by `DEV_AUTOLOGIN`) is not changed.

## Stage 2 — `passkey/routes.go`

- `registerOptions` and `register` start with the same `router.FromInternet` → 404 check (before
  `enrollmentAllowed`).
- `Mount`: `PathVerifyOptions` and `PathVerify` change from `.Authenticated()` to `.Public()`
  (they decide inside). `PathRegisterOptions`, `PathRegister` stay `.Authenticated()`;
  `PathList`, `PathDelete` unchanged.
- `verifyOptions`: if `ctx.UserID() != ""` → exactly today's behaviour. Otherwise (login):
  `challenge, err := m.newChallenge(anonymous, purposeVerify)` with `const anonymous = ""`, and
  answer `verifyOptions{Challenge, RPID}` with **no** `AllowCredentials` (the browser offers the
  passkeys it has for this site).
- `verify`: if `ctx.UserID() != ""` → today's behaviour. Otherwise (login):
  1. `rawID` via `server.UnverifiedCredentialID(raw)`; `cred, found := m.credential(...)`; not
     found → `m.reject(ctx, 401, reasonForeignCredential)`.
  2. `chal, err := server.UnverifiedChallenge(raw)`; error → 401 `reasonChallenge`.
  3. New `func (m *Module) consumeAnonymousChallenge(chal []byte) bool`: reads the row with
     `Id == base64.URLEncode(chal)`, `UserId == anonymous`, `Purpose == purposeVerify`; deletes it;
     returns true only if it existed and `ExpiresAt > now()`. False → 401 `reasonChallenge`.
  4. `m.rp.VerifyAssertion(raw, chal, stored)` as today; update sign count and `LastUsedAt` as
     today.
  5. `m.sessions.IssueStepUpSession(ctx, cred.UserId)`, event `auth.EventPasskeyVerified` with
     `UserID: cred.UserId`, 204.
- Factor the shared tail of both branches (verify assertion → update count → issue → event) into
  one unexported function; do not duplicate it.

## Stage 3 — tests (`tests/`)

Reuse `setupPasskeyEnv`, `buildGetResponse`, `buildCreateResponse` from `tests/passkey_test.go`.
Mark a request's network with `ctx.SetValue(router.ContextKeyNetwork, router.NetworkLocal)` (or
`NetworkInternet`). **Existing tests that exercise RUT login, setup or passkey registration through
`mock.Context` must mark their contexts `router.NetworkLocal`** (they model the local door); do
not change what they assert.

| Test | Door | Does | Expected |
|---|---|---|---|
| `TestInternetDoor_RUTLoginNotFound` | internet | `POST auth.PathLoginRUT` with a valid RUT body | 404, no session cookie |
| `TestInternetDoor_SetupNotFound` | internet | the setup route on a fresh db | 404 |
| `TestLocalDoor_RUTLoginStillWorks` | local | same as the first | 302 (as today) |
| `TestInternetDoor_RegisterNotFound` | internet | `PathRegisterOptions` with a fresh session | 404 |
| `TestPasskeyLogin_WithoutSession` | internet | enrol on the local door (as K3), then with **no cookie**: `PathVerifyOptions` → take its challenge → `PathVerify` with an assertion signed for it | 204; step-up cookie set; `Authenticate` with only that cookie gives `UserID` = the user and `model.AssuranceMultiFactor`; event `EventPasskeyVerified` |
| `TestPasskeyLogin_ChallengeSingleUse` | internet | repeat the same `PathVerify` body | 401 |
| `TestPasskeyLogin_UnknownCredential` | internet | assertion with an unregistered credential id | 401, no cookie |
| `TestPasskeyLogin_ExpiredChallenge` | internet | challenge row with `ExpiresAt` in the past | 401 |

## Stage 4 — docs

- `README.md`: a section «Local door and internet door»: what refuses the internet door (RUT login,
  setup, passkey enrolment), that a passkey alone is a login there, and that the app marks the
  doors through `webtyp/server` (`Config.InternetPort`).
- `docs/` (the auth architecture file): why enrolment is local only (a stolen RUT on the internet
  must not be able to add a passkey) and why the challenge is found by its value.
- `lang.json`: if any user-facing text was added, add its translations (`langc sync .` with 0
  pending); none is expected.

## Delivery check

```
gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission: when the check passes, commit, push and open the PR. Stuck 30
  minutes: open the PR listing what fails.
- `git diff --stat main` lists only: files under `trusted_ip/`, `passkey/`, `tests/`, `README.md`,
  the docs file, this plan.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `trusted_ip/*` | compiles; existing tests marked local and green |
| 2 | `passkey/routes.go`, `passkey/passkey.go` | compiles; existing passkey tests green |
| 3 | `tests/*` | 8 new tests pass |
| 4 | `README.md`, docs | sections present |
