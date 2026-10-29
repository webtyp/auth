---
PLAN: "feat(passkey/browser): SignIn and Enroll — the browser half of passkey login and enrolment"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 11517745204721890457
---

> Read AGENTS.md at the repo root before any change.

# PLAN — `auth/passkey/browser`: sign in and enrol from the page

## Why

`auth` v0.0.87 serves passkey login without a prior session (`passkey.PathVerifyOptions`,
`passkey.PathVerify`, both public) and passkey enrolment on the local door only
(`passkey.PathRegisterOptions`, `passkey.PathRegister`). Nothing in the browser calls them yet, so a
person cannot register the passkey of their phone at the clinic nor sign in with it from home
(decision D25 of `veltylabs/mjosefa-cms/docs/MVP_DEPLOYMENT_ROADMAP.md`, phase M1e). This plan adds
the two calls a screen needs; the app adds the buttons (next plan, `mjosefa-cms`).

## Design gate (api-design)

1. **Prior art.** `webtyp/keyring/browser` already wraps `webtyp/webauthn` for the page
   (`keyring/browser/passkey.go`); SimpleWebAuthn ships a browser half with `startAuthentication`
   and `startRegistration` that fetch the options, call `navigator.credentials` and return the
   response for the server (not checked against its docs for this plan).
2. **Names.** `browser.SignIn()` — «sign in with a passkey»; `browser.Enroll()` — «register a
   passkey on this device». Same package name as `keyring/browser`.
3. **Ledger.** Concepts +2 functions; call site: one line per button.
4. **Where.** A sub-package `auth/passkey/browser` with `//go:build wasm`, next to the server half it
   talks to (paths and wire types come from `auth/passkey`).
5. **Deletes.** Nothing.

## APIs used

| Symbol | Exact | Where |
|---|---|---|
| `webauthn.Get` | `func Get(opts GetOptions) (*Assertion, error)`; `GetOptions{RPID string; Challenge []byte; AllowCredentials [][]byte; UserVerification string; PRFSalt []byte}`; `Assertion{CredentialID []byte; RawResponse string; PRFOutput []byte}` | `webtyp.com/webauthn` (`get.go`) |
| `webauthn.Create` | `func Create(opts CreateOptions) (*Credential, error)`; `CreateOptions{RPID, RPName string; UserID []byte; UserName, UserDisplayName string; Challenge []byte; ResidentKey bool; UserVerification string; EnablePRF bool}`; `Credential{ID []byte; RawResponse string; PRFEnabled bool}` — both block and **must** run in a goroutine started by a user-gesture handler | `webtyp.com/webauthn` (`create.go`) |
| `fetch.Post` | `fetch.Post(url).Body(b).Send(func(*fetch.Response, error))`; `Response.Status int`, `Response.Body() []byte` | `webtyp.com/fetch` (`fetch.go`) |
| `base64.URLDecode` | `func URLDecode(s string) ([]byte, error)` | `webtyp.com/base64` |

Check each signature in the version in `go.mod` before using it; if one differs, stop and name it in
the PR.

## Stage 1 — `passkey/dto.go`: the options travel both ways

Export the two option types and give them `DecodeFields` (same JSON names they already write):
`registerOptions` → `RegisterOptions`, `verifyOptions` → `VerifyOptions` (update their uses in
`routes.go`). `DecodeFields(r model.FieldReader)` reads `challenge`, `rpId`, `userId`, `userName`,
`excludeCredentials` / `challenge`, `rpId`, `allowCredentials` (arrays of strings with
`r.Array(name)` and `arr.String(i)`).

## Stage 2 — `passkey/browser/browser.go` (new, `//go:build wasm`, `package browser`)

```go
// SignIn signs in with a passkey of this device: no session is needed. It blocks,
// so call it from a goroutine started by a click (webauthn.Get requires it):
//
//	button.OnClick(func(Event) { go func() { if err := browser.SignIn(); err == nil { reload() } }() })
func SignIn() error

// Enroll registers a passkey for the person signed in, on this device. The server
// accepts it only on the local door (on the internet door it answers 404). Same
// blocking rule as SignIn.
func Enroll() error
```

- A small unexported `post(path string, body []byte) (status int, data []byte, err error)` that
  wraps `fetch.Post(path).Body(body).Send(...)` and waits for the callback with a channel (one
  goroutine, as `keyring/browser` does with `await`; follow whichever that file uses).
- `SignIn`: `post(passkey.PathVerifyOptions, nil)` → status 200 or return an error with the
  status → decode `passkey.VerifyOptions` with `webtyp.com/json` → `webauthn.Get` with the decoded
  `RPID`, `Challenge` (base64url-decoded), `AllowCredentials` (each base64url-decoded; empty = any),
  `UserVerification: "required"` → `post(passkey.PathVerify, []byte(assertion.RawResponse))` →
  204 = nil, otherwise an error with the status.
- `Enroll`: `post(passkey.PathRegisterOptions, nil)` → decode `passkey.RegisterOptions` →
  `webauthn.Create{RPID, UserID: base64url-decoded UserID, UserName, Challenge, ResidentKey: true,
  UserVerification: "required"}` → `post(passkey.PathRegister, []byte(cred.RawResponse))` → 204 =
  nil.
- Errors: named constants in the file (`errStatus = "passkey: server answered "` + status). A
  cancelled ceremony returns `webauthn`'s own error unchanged (the caller tells «cancelled» apart).

## Stage 3 — tests

- `tests/passkey_dto_test.go` (stdlib): encode a `VerifyOptions` and a `RegisterOptions` with
  `webtyp.com/json`, decode them back, fields equal (the wire both halves share).
- `passkey/browser` cannot run `navigator.credentials` in headless tests; add a `_wasm_test.go` only
  if `webtyp/webauthn` already has a pattern for faking it (grep its tests); otherwise none, and say
  so in the PR.

## Stage 4 — docs

`README.md`, section «Local door and internet door»: one paragraph on `passkey/browser.SignIn` and
`Enroll`, the click rule, and that enrolment works only on the local door.

## Delivery check

```
gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission: when the check passes, commit, push and open the PR. Stuck 30
  minutes: open the PR listing what fails.
- `git diff --stat main` lists only: `passkey/dto.go`, `passkey/routes.go`,
  `passkey/browser/browser.go`, files under `tests/`, `README.md`, this plan.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `passkey/dto.go`, `passkey/routes.go` | compiles, suite green |
| 2 | `passkey/browser/browser.go` | `GOOS=js GOARCH=wasm go vet ./passkey/browser/` clean |
| 3 | `tests/*` | green |
| 4 | `README.md` | paragraph present |
