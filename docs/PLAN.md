---
PLAN: "feat(auth): passkey works out of the box — authority ships a default step-up session; passkey.New takes the app's origin"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 2287960177013435179
---

## Executor notes
Added the default step-up strategy to authority module, updating the tests as requested. I also had to update `lang.json` to avoid issues with langc missing translation. All tests passed successfully.

> Read AGENTS.md at the repo root before any change.

# PLAN — passkey without app glue

## Why

Today an app that wants passkey login writes ~25 lines of glue: a second `cookie.New` with
`Assurance: model.AssuranceMultiFactor`, `SetStepUpStrategy`, a `server.RelyingParty{ID, Origin}` built
by hand (with its own host parser), then `passkey.New` + `Enable`. `veltylabs/iam` writes it twice
(`iam/config/auth.go:104-130`, `iam/config/auth_local.go:62-81`, plus `OriginHost` at
`iam/config/auth.go:40-57`) and `mjosefa-cms` was about to write it a third time. Worse, the glue is a
trap: `passkey.New` accepts an `authority.Module` with no step-up strategy, and the first passkey
login then fails at run time with `authority.ErrNoStepUpStrategy` (`authority/module.go:106-111`).

The fix belongs here, not in `appkit`: `authority.New` already builds its **default main session**
from `auth.Config` (`authority/module.go:62-73`); the step-up session is the same mechanism with a
stronger assurance, so it gets the same treatment. And `passkey` owns the relying party, so it
derives `rp.id` from the origin itself.

## Ecosystem search

- `grep -rn "SetStepUpStrategy\|passkey.New\|OriginHost"` over `webtyp` and `veltylabs`: only `auth`
  (tests), `veltylabs/iam/config/auth.go`, `veltylabs/iam/config/auth_local.go`. **Extend** `auth`.
- Host from an origin: only `iam/config/auth.go:41` (`OriginHost`). **New** unexported helper in
  `passkey`; `iam` deletes its copy when it adopts this tag (not in this plan).
- `webtyp/appkit` has no auth code (`appkit/server.go`); it is not the owner.

## Design gate (api-design)

1. **Prior art** (behaviour of these frameworks not re-verified in this session): Django's
   `SessionMiddleware` and Rails' `cookie_store` give a working session with zero code; ASP.NET Core
   Identity registers its cookie schemes by default; GitHub "sudo mode" is a second, shorter-lived
   elevated session. Same here: both sessions exist by default, the app overrides only to change
   lifetimes (`iam` keeps its admin policy through `SetStepUpStrategy`).
2. **Names**: `passkey.New(db, ids, sessions, origin)` — "origin" is the WebAuthn and browser word
   (`clientDataJSON.origin`). `StepUpCookieName` reads as what it is.
3. **Ledger**: concepts −2 (`server.RelyingParty`, `SetStepUpStrategy` for the common case); lines at
   the call site −10 per app; ways to do the same thing 0 (override stays the single way to change it).
4. **Where**: `authority` (default sessions) and `passkey` (relying party) — their owners.
5. **Deletes**: `authority.ErrNoStepUpStrategy`, the `nil` branch of `IssueStepUpSession`,
   `TestAuthenticate_StepUpNoStrategy`; the `server.RelyingParty` parameter of `passkey.New`.

## APIs used

| Symbol | Exact | Where |
|---|---|---|
| `cookie.New` | `func New(repo auth.SessionRepo, o Options) (*Strategy, error)`; `Options{Name, Domain string; Policy auth.SessionPolicy; TrustProxy bool}` | `session/cookie/cookie.go:39` |
| `auth.SessionPolicy` | `{Absolute, Idle time.Unix; Assurance model.Assurance}` | `user.go:225` |
| `server.RelyingParty` | `{ID, Origin string}` | `webtyp.com/webauthn/server` |
| `fmt.HasPrefix` | `func HasPrefix(s, prefix string) bool` | `webtyp.com/fmt` |

## Stage 1 — default step-up session (`authority/module.go`)

- New exported constant next to the module: `StepUpCookieName = "stepup"` (the browser sees
  `__Host-stepup`, because the cookie is host-only).
- In `New`, right after the default main strategy (lines 62-73), build the step-up strategy the
  same way and assign it to `m.stepUp`:
  `cookie.New(m, cookie.Options{Name: StepUpCookieName, Policy: auth.SessionPolicy{Absolute: cfg.TokenTTL, Idle: cfg.IdleTTL, Assurance: model.AssuranceMultiFactor}, TrustProxy: cfg.TrustProxy})`
  — same lifetimes as the main session (the defaults `New` already applies to `TokenTTL` hold).
- Delete `ErrNoStepUpStrategy` and the `if m.stepUp == nil` branch of `IssueStepUpSession`; delete
  `domainErr` if nothing else uses it. The `m.stepUp != nil` checks in `authority/middleware.go:51`
  and `authority/mount.go:18` go too (it is never nil now).
- Comments: `stepUp` field (`module.go:28`), `SetStepUpStrategy` (now "overrides the default step-up
  session", nil ignored like `SetStrategy`), `auth.SessionStrategy` doc (`user.go:243-246`: "one main
  and one step-up strategy, both built by default").

## Stage 2 — origin instead of relying party (`passkey/passkey.go`)

- `func New(db *orm.DB, ids model.IDGenerator, sessions Sessions, origin string) (*Module, error)`.
  It builds `server.RelyingParty{ID: hostOf(origin), Origin: origin}`.
- Unexported `hostOf(origin string) string`: strip `https://` (or `http://`), then cut at the first
  `:` or `/`. Example comment: `"https://app.example.com" → "app.example.com"`,
  `"https://localhost:6060" → "localhost"`.
- `ErrMsgRelyingParty` becomes `ErrMsgOrigin = "passkey: origin is required, e.g. https://app.example.com"`;
  returned when `origin == ""` or `hostOf(origin) == ""`.
- Package and `New` comments: the origin must be **exactly** what the browser shows in the address
  bar, port included (`https://localhost:6060` in development) — WebAuthn compares it byte for byte.

## Stage 3 — tests (`tests/`)

- Delete `TestAuthenticate_StepUpNoStrategy`.
- `tests/passkey_test.go` `setupPasskeyEnv`: drop the hand-built `stepUpStrat`/`SetStepUpStrategy`
  and the `server.RelyingParty`; call `passkey.New(db, testIDs, m, "https://app.example.com")`. Every
  existing passkey test must still pass — that is the proof the default works. Where a test reads
  the step-up cookie by name, use `"__Host-" + authority.StepUpCookieName`.
- Keep one test that **overrides** the step-up policy with `SetStepUpStrategy` and checks the
  override's cookie name is the one issued.
- New `TestPasskey_OriginRequired`: `New(..., "")` and `New(..., "https://")` → error text
  `passkey.ErrMsgOrigin`.
- New `TestPasskey_OriginWithPort`: `New(..., "https://localhost:6060")`; the verify options answer
  `RPID == "localhost"`.
- Replace every other `server.RelyingParty` + `passkey.New` in `tests/` the same way.

## Stage 4 — docs

- `README.md:88` example: `pk, _ := passkey.New(db, ids, authMod, "https://app.example.com")`; say the
  step-up session exists by default (cookie `__Host-stepup`, same lifetimes as the main one,
  `AssuranceMultiFactor`) and that `SetStepUpStrategy` only changes it.
- `docs/ARCHITECTURE.md` (passkey bullet, line 46): same two facts.

## Delivery check

```
GOPRIVATE=webtyp.com/* GOFLAGS=-mod=mod gotest
```

- A PR that does not compile, or whose tests could not run, is a failed delivery.
- Never pause to ask permission: when the check passes, commit, push and open the PR. Stuck 30
  minutes: open the PR listing what fails.
- `git diff --stat main` lists only: `authority/module.go`, `authority/middleware.go`,
  `authority/mount.go`, `user.go`, `passkey/passkey.go`, files under `tests/`, `README.md`,
  `docs/ARCHITECTURE.md`, this plan. No real domain in tests: `app.example.com`, `localhost`.

## Stages

| # | Files | Done when |
|---|---|---|
| 1 | `authority/*.go`, `user.go` | compiles |
| 2 | `passkey/passkey.go` | compiles |
| 3 | `tests/*` | suite green |
| 4 | `README.md`, `docs/ARCHITECTURE.md` | text present |
