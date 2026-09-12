---
PLAN: "feat: LAN RUT login contract, me+RBAC composition, sliding idle sessions, email-less users"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 12105204108956950385
PR: https://github.com/webtyp/auth/pull/4
---

> This plan is dispatched via the CodeJob workflow. See skill: agents-workflow.
>
> **Phase A (GATE)** of
> [`LAN_RUT_AUTH_MASTER_PLAN.md`](https://github.com/tinywasm/app/blob/main/docs/LAN_RUT_AUTH_MASTER_PLAN.md).
> `veltylabs/mjosefa-cms` (phase D) may not start before this ships a tag.
> Doctrine: [`CONSTRUCTION_HARNESS.md`](https://github.com/tinywasm/app/blob/main/docs/CONSTRUCTION_HARNESS.md) —
> the rules quoted below ("glue is written once, in the library that owns it",
> "closed by default", "loud development diagnostic") come from there.
>
> **Depends on phase R1** (`webtyp.com/router` publishing
> `router.ContextKeyRemoteAddr`): as the first line of work,
> `go get webtyp.com/router@latest`. Never add a `replace`, never invent a
> version.

# Plan — `webtyp.com/auth`: what a LAN app must not have to re-implement

## 0. Context (verified against the repo at v0.0.46 — do not re-diagnose)

`mjosefa-cms` is the first real consumer combining `authority` + `rbac` +
`trusted_ip`. Its superseded local plan had to write, **inside the app**:

1. a `profileOps` module composing `opMe` (identity) with `rbac.Service`
   (authorization), because `authority/ops.go` deliberately returns
   `ProfileDTO` with empty `Permissions` ("un consumidor… lo compone en su
   propia raíz de composición"). Every app that combines auth+rbac would
   write the identical composition → per the harness, that glue belongs
   **here**, not at the leaf.
2. hand-built `"resource:actions"` strings — the wire format of
   `ProfileDTO.Permissions` is documented in `user.go` but has no typed
   producer/consumer, so the app re-encoded it with string concatenation.
3. a prose rule ("do not harvest `authMod` twice or `me` duplicates") — a
   "thing you have to remember" is a harness hole (phase C of the master plan
   closes it in `webtyp.com/mcp`; nothing to do here).

And for the LAN RUT login the app needs (single RUT field, IP-checked):

4. `trusted_ip` decodes a **private** `loginRUTData` and hardcodes
   `"/login/rut"` — the client has no exported contract to build its form
   from, and the route has no constant next to `PathLogin`/`PathLogout`.
5. failed RUT attempts (bad checksum, unknown RUT) return 401 **without a
   security event** — the owner requires every rejected attempt logged
   (`EventIPMismatch` already covers the IP case).
6. `CreateUser(email, …)` cannot create two users without email — `email` is
   `Unique` and an empty string collides. LAN staff have no email.
7. sessions have a fixed `TokenTTL` (24 h default) with no sliding expiry —
   the owner requires "30 min without mouse/keyboard closes the session",
   which server-side is a sliding idle TTL.
8. LAN identity administration (`RegisterLAN`/`UnregisterLAN`) exists as Go
   methods but has **no MCP ops** — an admin UI cannot manage RUTs through
   the same transport everything else uses.

All eight are library defects by the harness definition (missing contract at
a seam / glue a consumer would repeat / silent failure). Fix them here.

## Design gate (api-design — five answers)

### 1. Prior art

| Concern | Frameworks | Why we differ |
|---|---|---|
| Custom credential field + form contract | **Devise** (parameter sanitizer for custom keys), **Django allauth** (login form fields), **Keycloak** (credential providers per realm) | They configure a framework that owns the form; here the model definition (`RUTLoginDataModel`) **is** the contract: it drives server decode AND client form generation from one declaration. |
| userinfo + authorization claims | **Keycloak** userinfo (roles/scopes claims), **Auth0** `/userinfo` + RBAC permissions claim, **Spring Security** (authorities in the principal) | They embed the policy engine in the identity server. We keep `authority` unaware of `rbac`: the consumer injects an `ActionResolver` port; nil = no permissions (closed by default). |
| Sliding sessions | **PHP** `gc_maxlifetime` + cookie params, **Rails** `ActionDispatch::Session` `expire_after`, **ASP.NET** `slidingExpiration` | Same semantics (expiry slides on activity); ours is one explicit `IdleTTL` field, 0 = disabled — no implicit default change. |
| Email-less users | **Keycloak** username-only realms, **Django** custom `USERNAME_FIELD`, **Auth0** phone-only passwordless | We do not add a username concept: `email` simply becomes optional (NULL when empty, unique only when present); the RUT lives in the existing `Identity` table, provider `"trusted_ip"`. |

### 2. Novice-name test

- `auth.RUTLoginData` — "the data of a RUT login" (mirrors existing `LoginData`).
- `auth.PathLoginRUT` — sits next to `PathLogin`, `PathLogout`, `PathAfterLogin`.
- `auth.ActionResolver.AllowedActions(projectID, subjectID, resource)` — "which actions are allowed here" (mirrors `rbac.Service.Can` vocabulary and `model.Action`).
- `auth.Permissions{Resolver, ProjectID, Resources}` — "the permissions configuration of `me`".
- `ProfileDTO.Grant(resource, actions)` / `ProfileDTO.Allows(resource)` — producer/consumer of the same format, named as sentences.
- `Config.IdleTTL` — "the session dies after this long idle" (mirrors `TokenTTL`).
- `OpRegisterLAN`/`OpUnregisterLAN`/`OpGetLAN` — match the existing Go methods `RegisterLAN`/`UnregisterLAN` they expose.

### 3. Complexity ledger

```
Concepts the developer must learn   +4 (ActionResolver, Permissions, IdleTTL, RUTLoginData) / −2 (app-side profile composition, app-side permission-string parsing)
Files they must touch to do X       +0 / −1 (mjosefa-cms deletes config/profile.go)
Lines at the call site              +5 (Config fields) / −60 (leaf composition + parsing)
Ways to do the same thing           +0 / −1 (one producer of "resource:actions", in-library)
```

### 4. Where it belongs

`authority` owns `me` and the profile DTO; the permission **format** is
`ProfileDTO`'s contract, so its producer (`Grant`) and parser (`Allows`) live
in `auth`. The policy itself stays the consumer's (injected `ActionResolver`)
— exactly the AUTH_POLICY wave's doctrine. `trusted_ip` owns the RUT login
route, so its path constant and request contract live in `auth` next to the
other path constants. No second concern enters any package.

### 5. What it deletes

- `trusted_ip.loginRUTData` (private duplicate of the new exported contract).
- The hardcoded `"/login/rut"` literal (replaced by `auth.PathLoginRUT`).
- The "Roles/Permissions se quedan sin poblar aquí a propósito" comment in
  `authority/ops.go` (replaced by the `Permissions` config path).
- Downstream (phase D, not this plan): `mjosefa-cms/config/profile.go` and
  its hand-rolled `"resource:actions"` concatenation.

## Quality rules (apply to every stage)

```
RULE: Every repeated string (route, op name, provider, event) MUST be a named
constant in this library. String literals are forbidden in logic.
RULE: No stdlib in wasm-shared files — webtyp/fmt, webtyp/time only.
RULE: closed by default — every new capability is inert at its zero value
(Permissions nil, IdleTTL 0 ⇒ behavior identical to today).
```

## Stage 1 — exported RUT login contract + path/provider/key constants

**Files:** `user.go`, `models.go`, `models_orm.go` (regenerate),
`trusted_ip/trusted_ip.go`, `authority/credentials_lan.go`.

1. `user.go`, in the `const` block with `PathLogin`:
   ```go
   PathLoginRUT = "/login/rut"
   ```
2. `user.go`, new exported constant (the provider name is a cross-package
   contract — `trusted_ip.Name()`, `authority.RegisterLAN/UnregisterLAN/
   LoginLAN` and composition roots seeding identities all agree on it; today
   it is a bare literal in three files):
   ```go
   // ProviderTrustedIP is the auth.Identity provider name under which the
   // normalized RUT of a LAN user is stored.
   const ProviderTrustedIP = "trusted_ip"
   ```
   Replace every `"trusted_ip"` literal in `trusted_ip/trusted_ip.go` and
   `authority/credentials_lan.go` with `auth.ProviderTrustedIP`.
3. `user.go`, `ClientIP`: `ctx.Value("RemoteAddr")` →
   `ctx.Value(router.ContextKeyRemoteAddr)` (constant from phase R1;
   `router` is already a dependency).
4. `models.go`, next to `LoginDataModel`:
   ```go
   var RUTLoginDataModel = model.Definition{
       Name: "rut_login_data",
       Fields: model.Fields{
           {Name: "rut", Type: input.Text(), NotNull: true},
       },
   }
   ```
5. Regenerate `models_orm.go` with `ormc` (run at the repo root; the file
   header is `DO NOT EDIT. generated by webtyp.com/ormc`). The generated
   struct is `RUTLoginData` with field `RUT string`, `ModelName()
   "rut_login_data"`, `Schema()`, `Pointers()`, `IsNil()` — same shape as
   `LoginData`.
6. `trusted_ip/trusted_ip.go`:
   - `r.Post("/login/rut", …)` → `r.Post(auth.PathLoginRUT, …)`.
   - Delete `type loginRUTData` and its methods; decode into
   `&auth.RUTLoginData{}` and read `.RUT`.

## Stage 2 — security events for rejected RUT attempts

**Files:** `user.go`, `trusted_ip/trusted_ip.go`.

1. `user.go`, extend the `SecurityEventType` iota block after
   `EventRateLimited`:
   ```go
   EventInvalidRUT // trusted_ip: the typed value is not a checksum-valid RUT (probe or typo)
   EventUnknownRUT // trusted_ip: valid RUT, no identity registered for it
   ```
2. `trusted_ip/trusted_ip.go` handler, keep every response status exactly as
   today (400/401/302 unchanged) and add notifications:
   - `ValidateRUT` error → before the 401:
     `a.notify.Notify(auth.SecurityEvent{Type: auth.EventInvalidRUT, IP: ip})`.
   - `IdentityByProvider` error and `UserByID` error → before their 401:
     `a.notify.Notify(auth.SecurityEvent{Type: auth.EventUnknownRUT, IP: ip})`.
   - the `u.Status != "active"` and IP-mismatch branches already notify —
     do not touch them.

## Stage 3 — `me` composes identity + authorization in-library

**Files:** `user.go`, `authority/ops.go`.

1. `user.go`:
   ```go
   // ActionResolver resolves which actions a subject holds on one resource.
   // rbac.Service satisfies it structurally (AllowedActions); auth never
   // imports rbac — the composition root injects it.
   type ActionResolver interface {
       AllowedActions(projectID, subjectID string, resource model.Resource) model.Action
   }

   // Permissions configures opMe to populate ProfileDTO.Permissions.
   // nil (the default) ⇒ opMe returns no permissions — closed by default.
   type Permissions struct {
       Resolver  ActionResolver
       ProjectID string
       Resources []model.Resource
   }
   ```
   Add to `Config`:
   ```go
   // Permissions, when set, makes opMe compose identity (this module) with
   // authorization (the injected resolver) into ProfileDTO.Permissions.
   Permissions *Permissions
   ```
   Add to `ProfileDTO` (same file that documents the `"resource:actions"`
   format — the format now has exactly one producer and one consumer, both
   here):
   ```go
   // Grant appends one "resource:actions" entry — the ONLY producer of the
   // wire format documented on Permissions.
   func (p *ProfileDTO) Grant(resource model.Resource, actions model.Action) {
       if actions == 0 { return }
       p.Permissions = append(p.Permissions, string(resource)+":"+actions.String())
   }

   // Allows reports whether the profile carries any action on resource —
   // the ONLY consumer of the format. Clients call this instead of parsing
   // Permissions themselves.
   func (p ProfileDTO) Allows(resource string) bool { … split on ":", compare prefix, actions non-empty … }
   ```
2. `authority/ops.go`, `opMe`: replace the "a propósito" comment block with:
   ```go
   profile := auth.ProfileDTO{Id: u.Id, Name: u.Name, Email: u.Email, Avatar: u.Avatar}
   if p := m.config.Permissions; p != nil && p.Resolver != nil {
       for _, res := range p.Resources {
           profile.Grant(res, p.Resolver.AllowedActions(p.ProjectID, userID, res))
       }
   }
   ```
   (`Grant` already skips empty action sets.)

## Stage 4 — email-less users

**Files:** `models.go`, `models_orm.go` (regenerate), `authority/users.go`.

1. `models.go`, `UserModel` email field: add `OmitEmpty: true` so an empty
   email is omitted on insert (NULL in Postgres; unique allows many NULLs):
   ```go
   {Name: "email", Type: input.Email(), OmitEmpty: true, DB: &model.FieldDB{Unique: true}},
   ```
   Regenerate with `ormc`.
2. `authority/users.go` `createUser`: when `email == ""`, skip nothing — the
   unique-violation mapping to `ErrEmailTaken` stays for real emails; NULLs
   never collide. Verify `getUserByEmail("")` cannot match (it queries
   `Eq("")`, NULL never equals) — no code change, but add the case to tests.
3. No schema migration needed: the column was already nullable (no
   `NotNull`). State this in the commit body.

## Stage 5 — sliding idle sessions

**Files:** `user.go`, `authority/sessions.go`.

1. `user.go`, `Config`:
   ```go
   // IdleTTL, when > 0, makes sessions expire after IdleTTL seconds WITHOUT
   // activity, sliding: every authenticated GetSession pushes ExpiresAt to
   // now+IdleTTL. It supersedes TokenTTL for both initial and renewed
   // lifetime. 0 (default) ⇒ today's fixed-TokenTTL behavior, unchanged.
   IdleTTL int
   ```
2. `authority/sessions.go`:
   - `CreateSession`: `ttl := m.config.TokenTTL; if m.config.IdleTTL > 0 { ttl = m.config.IdleTTL }; if ttl == 0 { ttl = 86400 }`.
   - `GetSession`: after a session passes the expiry check (both cache and DB
     paths), if `m.config.IdleTTL > 0`: compute `newExpiry := now +
     int64(m.config.IdleTTL)`; if `newExpiry > s.ExpiresAt`, update the row
     (`m.db.Update`) and the cache entry. Extend-only — never shorten.

## Stage 6 — LAN identity ops

**Files:** `user.go`, `models.go`, `models_orm.go` (regenerate),
`authority/ops.go`, `authority/ops_lan.go` (new).

1. `user.go` op-name constants (next to `OpMe`…`OpDeleteUser`):
   ```go
   OpRegisterLAN   = "register_lan"   // admin: link a RUT to a user (trusted_ip identity)
   OpUnregisterLAN = "unregister_lan" // admin: remove the user's trusted_ip identity
   OpGetLAN        = "get_lan"        // admin: read the user's normalized RUT
   ```
2. `models.go` transport-only definitions (no `DB:` on any field), then
   `ormc`:
   ```go
   RegisterLANArgsModel  {user_id: model.Text(), rut: input.Text()}
   LANUserArgsModel      {user_id: model.Text()}
   LANIdentityModel      {user_id: model.Text(), rut: model.Text()}
   ```
3. `authority/ops.go` `MountOperations`, append:
   ```go
   reg.Operation(auth.OpRegisterLAN, m.opRegisterLAN).Requires("users", model.Create|model.Update).Accepts(&auth.RegisterLANArgs{})
   reg.Operation(auth.OpUnregisterLAN, m.opUnregisterLAN).Requires("users", model.Update).Accepts(&auth.LANUserArgs{})
   reg.Operation(auth.OpGetLAN, m.opGetLAN).Requires("users", model.Read).Accepts(&auth.LANUserArgs{})
   ```
4. `authority/ops_lan.go` (new): the three handlers, thin wrappers over the
   existing methods — `m.RegisterLAN(args.UserId, args.Rut)`,
   `m.UnregisterLAN(args.UserId)`, `m.IdentityFor(args.UserId,
   "trusted_ip")` → encode `auth.LANIdentity{UserId, Rut:
   identity.ProviderId}`. Error mapping: decode failure → 400;
   `auth.ErrInvalidRUT`/`ErrRUTTaken` → 409 with the error text;
   `auth.ErrNotFound` (get/unregister) → 404; anything else → 500.
   Success → 200 (`register`/`unregister` encode `LANIdentity`/empty ok per
   existing op conventions in this file — follow `opUpsertUser`'s shape).

## Stage 7 — consumer-shaped tests (the publication rule)

**Files (new, in `tests/`):** `lan_login_test.go`, `permissions_me_test.go`,
`sliding_session_test.go`, `emailless_users_test.go`. Follow the harness of
`tests/production_wiring_test.go` (real `authority` over in-memory storage,
fake only at the edge).

1. `lan_login_test.go`: wire `authority` + `trusted_ip.New(…, trustProxy
   false)` with a fake `TrustedIPStore`; POST `PathLoginRUT` with (a) valid
   RUT + trusted IP → 302 + session cookie; (b) valid RUT + untrusted IP →
   401 + `EventIPMismatch` published; (c) `"12345678-0"` (bad checksum) →
   401 + `EventInvalidRUT`; (d) well-formed unknown RUT → 401 +
   `EventUnknownRUT`.
2. `permissions_me_test.go`: `Config.Permissions` with a fake resolver
   returning `model.Read|model.Update` for one resource → `me` encodes
   `"that_resource:ru"`; `Permissions nil` → `Permissions` empty (closed by
   default); `ProfileDTO.Allows` round-trips every `Grant`.
3. `sliding_session_test.go`: `IdleTTL` small (e.g. 2 s); session valid,
   `GetSession` pushes `ExpiresAt`; with `IdleTTL 0` `ExpiresAt` never moves.
4. `emailless_users_test.go`: two `CreateUser("", …)` succeed; duplicate
   real email still → `ErrEmailTaken`; `UserByEmail("")` → `ErrNotFound`.

## Stage 8 — docs

Update `docs/ARCHITECTURE.md` (opMe composition via `Permissions`, `IdleTTL`
semantics, LAN ops, RUT events) and `README.md` (one short "LAN RUT login"
example: `Enable(trustedip.New(...))` + `Config.Permissions`). VERIFY against
the implemented code — do not describe intentions.

## Acceptance criteria

1. `go build ./...`, `go vet ./...`, `gotest ./...` green.
2. `grep -rn "loginRUTData" .` → empty. `grep -rn '"/login/rut"' .` → only
   the `PathLoginRUT` constant definition. `grep -rn '"trusted_ip"' .` →
   only the `ProviderTrustedIP` constant definition. `grep -rn
   '"RemoteAddr"' .` → empty (the router constant replaced it).
3. `grep -rn "a propósito\|componer en su propia raíz" authority/` → empty
   (the composition now lives here).
4. All four new test files exercise the real stack (no double stands in for
   `authority` itself).

## Out of scope

- `AssignLANIP`/`RevokeLANIP`/`GetLANIPs` and the `LANIP` table stay as they
  are — framework capability for other systems; mjosefa-cms will implement
  `TrustedIPStore` via `staff_manager` instead (master plan phases S/D).
- No change to `email_password`, `oauth2`, `local`, `session/*` beyond the
  seams named above.
- Duplicate-tool harvesting diagnostics — that is `webtyp.com/mcp` (phase C).

| Stage | Files | Action |
|---|---|---|
| 1 | `user.go`, `models.go`, `models_orm.go`, `trusted_ip/trusted_ip.go`, `authority/credentials_lan.go` | `PathLoginRUT`, `ProviderTrustedIP`, `router.ContextKeyRemoteAddr` in `ClientIP`, `RUTLoginData(Model)`, delete `loginRUTData` |
| 2 | `user.go`, `trusted_ip/trusted_ip.go` | `EventInvalidRUT`/`EventUnknownRUT` + notify on every rejected attempt |
| 3 | `user.go`, `authority/ops.go` | `ActionResolver`, `Config.Permissions`, `Grant`/`Allows`, composed `opMe` |
| 4 | `models.go`, `models_orm.go`, `authority/users.go` | email `OmitEmpty` (NULL-able unique) |
| 5 | `user.go`, `authority/sessions.go` | `Config.IdleTTL` sliding expiry |
| 6 | `user.go`, `models.go`, `models_orm.go`, `authority/ops.go`, `authority/ops_lan.go` | `register_lan`/`unregister_lan`/`get_lan` ops |
| 7 | `tests/lan_login_test.go` + 3 files | consumer-shaped proofs |
| 8 | `docs/ARCHITECTURE.md`, `README.md` | verify docs against implementation |
