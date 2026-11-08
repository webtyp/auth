---
PLAN: "refactor!: auth/authority on crud tables — /me as an Infra route, users through orm.GlobalStore, LAN identity through its own repository"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 3666154311299940771
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work. Commit after every stage.
> Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
> Never edit `model_orm.go` or `model_crud.go`: a build error there means the hand-written code is wrong.

# Plan: `auth/authority` on crud tables (D2, D8, D14, D19, D20, D21 of `webtyp/docs/ARCHITECTURE_MASTER_PLAN.md`)

Starts from `main` as it is: `authority/ops.go` mounts seven operations on `router.OperationRegistry` (`me`, `list_users`, `upsert_user`,
`delete_user` with resource `"users"`; `register_lan`, `unregister_lan`, `get_lan` with `auth.ResourceLANIdentity`), and `view.go` still uses the
removed `view.Ops{List, Save, Delete}` strings.

## Tools

```bash
go install webtyp.com/devflow/cmd/gotest@latest
go install webtyp.com/lang/cmd/langc@latest
go install webtyp.com/ormc/cmd/ormc@latest
go get webtyp.com/model@latest webtyp.com/crud@latest webtyp.com/orm@latest webtyp.com/view@latest webtyp.com/rpc@latest
```
These must contain `Definition.Allow`/`model.TableSlice` (model), `crud.Table`/`crud.Store` (crud), `orm.GlobalStore` (orm) and
`NewCallerLister(…, func() model.TableSlice)` (view). If `go doc webtyp.com/orm GlobalStore` fails, stop. No `replace`; `go mod tidy`; run `ormc`.

## Why

`/me` is not an operation on a table: it is the session's own route, mounted by the app through `access.Infra` (D8, D14). Users persist through
`orm.GlobalStore` (the `user` table has no `tenant_id`: users belong to the installation) and the users cache is invalidated in `Committed`.
A LAN identity is not a row of its own: it is the `identity` row with provider `trusted_ip`, written by `RegisterLAN`/`UnregisterLAN`. So
(D21, Repository) `authority` writes its own `crud.Store` for it.

## Tables, stores and rules

| Model | Store | `Allow` | Hooks |
|---|---|---|---|
| `User` (`user`) | `orm.GlobalStore(db, ids)` | `model.Create \| model.Read \| model.Update \| model.Delete` | `Create`: the checks of `createUser` (`authority/users.go:12`: email normalized and unique via `tx.ReadAll` — a duplicate is a field error on `email`, never a 500 as `opUpsertUser` answers today); `Update`: only `name` and `phone` are editable (what `updateUser` writes; any other field → field error); `Committed`: `m.ucache.Delete(id)` on update and delete (the cache `deleteUser`/`updateUser` clear today) |
| `LANIdentity` (`lan_identity`) | `lanStore` (new, over `RegisterLAN`, `UnregisterLAN`, `IdentityFor`) | `model.Create \| model.Read \| model.Delete` | none (the RUT rules live in `RegisterLAN`) |
| `Session`, `Identity`, `LANIP`, `OAuthState` | — (internal, no `Allow`) | — | unchanged |

## Stage 1 — `models.go`

- `UserModel`: `Allow: model.Create | model.Read | model.Update | model.Delete`; server-filled fields (`created_at`, `updated_at`, password hash,
  anything today's create sets) `ServerOnly: true`.
- `LANIdentityModel` (name `lan_identity`; today `user_id`, `rut`): rename `user_id` to `id` (the user id, `DB: &model.FieldDB{PK: true}`, NotNull) so `ormc`
  generates `MountLANIdentity` (D21 — it is **never** added to `authority/migrate.go`); `Allow: model.Create | model.Read | model.Delete`.
- Run `ormc`: `model_crud.go` has `MountUser` and `MountLANIdentity`; the four functions per entity of the earlier contract are gone.

## Stage 2 — `authority/stores.go` (new): `lanStore`

Implements `crud.Store` (`ReadOne`, `ReadAll`, `Create`, `UpdateFields`, `Delete`, `NewID`), **not** `crud.Transactional`:

| Method | Body |
|---|---|
| `ReadOne(rec, id)` | `m.IdentityFor(id, auth.ProviderTrustedIP)`; not found → error of kind `model.ErrorNotFound`; fills `Id`, `Rut` |
| `ReadAll(newRow, q, onRow)` | the `identity` rows with provider `trusted_ip` (read with `m.db`), as `LANIdentity`; only `storage.Eq` on `id` is supported (other conditions → `ErrUnsupportedCondition = fmt.Err("auth: LAN identities filter only by user")`); order by id, `After`/`Limit` in memory |
| `Create(rec)` | `m.RegisterLAN(rec.Id, rec.Rut)`; then re-read so `rec.Rut` is the normalized RUT; `auth.IsInvalidRUT` / `auth.IsRUTTaken` → `&model.FieldError{Field: "rut", Err: err}` |
| `UpdateFields` | `crud.ErrInvalidField` (Allow has no Update; never reached) |
| `Delete(rec, id)` | `m.UnregisterLAN(id)`; `auth.IsNotFound` → kind `model.ErrorNotFound` |
| `NewID()` | `""` is never used: a LAN identity's id is the user id the client sends; return `m.ids.NewID()` to satisfy the contract |

## Stage 3 — `authority/ops.go` and `authority/mount.go`

`me` leaves `MountOperations`: `MountAPI` (`mount.go`) adds `r.Post("/api/"+auth.ModelName+"/"+auth.OpMe, m.opMe).Authenticated()` (the same
path the browser calls today through `rpc`, so clients do not change), next to logout. The resource `"users"` becomes `"user"` (the `User`
ModelName): grep this repo for `"users"` grants and update them; README notes that apps granting `users` must grant `user`.

```go
var _ crud.Module = (*Module)(nil)

func (m *Module) MountOperations(reg crud.Registry) {
	MountUser(reg, m.userStore, UserRules{Create: m.checkUser, Update: m.checkUserChange, Delete: m.checkUserDelete, Committed: m.userCommitted})
	MountLANIdentity(reg, m.lanStore, LANIdentityRules{})
}
```
`Module` gains `userStore *orm.Store` (`orm.GlobalStore(db, ids)`) and `lanStore crud.Store`, built in `New`. Delete `opListUsers`,
`opUpsertUser`, `opDeleteUser`, the handlers of `ops_lan.go`, `OpListUsers`, `OpUpsertUser`, `OpDeleteUser`, `OpRegisterLAN`, `OpUnregisterLAN`,
`OpGetLAN` (keep `OpMe`), `RegisterLANArgsModel`, `LANUserArgsModel`, `var _ router.OperationModule` (`grep -rn "reg.Operation\|OperationModule\|view.ListArgs"
--include=*.go . | grep -v _test` → empty). `listUsers`, `createUser`, `updateUser`, `deleteUser` keep only what other functions of this repo still call. Keep `UserByID`,
`UserByEmail`, `ListUsers`, `CreateUser` (ports other modules use; bodies through `m.userStore` and the same hooks inside `m.userStore.Atomic`),
`RegisterLAN`, `UnregisterLAN`, `IdentityFor`. `MountAPI` (logout, `/me`) unchanged.

## Stage 4 — `view.go`

First line `//go:build browser`. `NewView` becomes
`view.NewCallerLister(view.NewRecords().Caller(caller), view.Ops{Module: ModelName, Page: view.Page{First: view.All}}, func() model.TableSlice { return &UserList{} })`
(no `List`/`Save`/`Delete` strings, no `Allow`: the screen reads `UserList.Allow()`).

## Stage 5 — tests (`tests/`, through `crud.LoopbackActingAs("admin-1", mod)`; rows in `docs/TESTS.md`)

| Test | Setup → call → expected |
|---|---|
| `TestUser_DuplicateEmailRejected` | two users with the same email → field error on `email` |
| `TestUser_UpdateOnlyListedFields` | update `["name"]` → email unchanged |
| `TestUser_CacheInvalidatedOnUpdate` | `UserByID` (cached), update name → `UserByID` returns the new name |
| `TestUser_ServerOnlyRejected` | create with a `ServerOnly` field → `crud: field written only by the server` |
| `TestLANIdentity_CreateReadDelete` | create `{id:"u1", rut:"12.345.678-5"}` → read `{id:"u1"}` returns the normalized RUT → delete `["u1"]` → read → `model.ErrorNotFound` |
| `TestLANIdentity_InvalidRutIsFieldError` | create with an invalid RUT → field error on `rut` |
| `TestLANIdentity_BatchRejected` | create two in one request → `crud.ErrBatchNotAtomic` |
| `TestMe_IsInfraRoute` | `rpc.Routes("/api", nil, mod)` has no `…/me` route; a router mock after `mod.MountAPI(r)` has `POST /api/auth/me` authenticated |
| `TestUser_ResourceIsUser` | `rpc.Routes("/api", nil, mod)` → `user_r` has resource `user` |

## Stage 6 — translations and documentation

`langc sync .` (zero pending, zero reuse warnings). `README.md`: operations table (`user_r/_c/_u/_d`, `lan_identity_r/_c/_d`) and why LAN
identity has its own repository. `docs/ARCHITECTURE.md` updated.

## Delivery check

`gotest` passes; `langc sync .` clean; every grep of this plan empty. A tree that does not compile or whose tests did not run is a failed delivery.

| Stage | Files |
|---|---|
| 1 | `models.go`, generated files |
| 2 | `authority/stores.go` |
| 3 | `authority/ops.go`, `authority/mount.go`, `authority/module.go`, `authority/users.go`, `authority/ops_lan.go`, `user.go`, `models.go` |
| 4 | `view.go` |
| 5 | `tests/*.go`, `docs/TESTS.md` |
| 6 | `lang.json`, `README.md`, `docs/ARCHITECTURE.md` |
