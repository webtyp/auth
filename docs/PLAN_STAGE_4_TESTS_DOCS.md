← [Stage 3](PLAN_STAGE_3_METHODS_IMPORTERS.md)

# Stage 4 — tests, translations, documentation

## 4.1 Tests (`tests/` is a nested module with its own `go.mod`; run `gotest` there too)

Keep every existing test and fix it with the compiler: `auth.User` → `authority.User` (and the other moved types), a test of a removed handler (`opUpsertUser`, `opListUsers`, `opGetLAN`…, `list_args`-style tests that build a `view.ListArgs`) becomes the crud test below; never delete a test of a kept method. Operations are `router.Operation{Module: authority.ModelName, Entity: (&authority.User{}).ModelName(), Action: model.Create}`, never a string. New tests in `tests/users_crud_test.go`, through `crud.LoopbackActingAs(nil, "admin-1", mod)` with the helpers `call` and `failedField` of the other modules (copy https://github.com/veltylabs/chat_room/blob/main/tests/crud_test.go lines 1–30):

**How to port the old tests (exact, no deletion):** a test never disappears; it is rewritten against the new surface and keeps its name and its assertion.

| Old test file / call | Becomes |
|---|---|
| `list_users_test.go`: `auth.OpListUsers` with a `view.ListArgs` | `router.Operation{Module: authority.ModelName, Entity: "user", Action: model.Read}` with `crud.ReadArgs{Search, After, Limit}` through `crud.LoopbackActingAs(nil, "admin-1", mod)`; same expected rows |
| `permissions_me_test.go`: `auth.OpMe` | the `GET` route `auth.PathMe` (`r.Get(auth.PathMe, m.handleMe)`), called through the router the test already builds for the other routes; same expected permissions |
| any `auth.OpXxx` of a removed user operation | the `user` / `lan_identity` operation of the mapping table in `PLAN.md` |
| a test of `Session`/`Identity`/`LANIP` types | same test, with the type taken from `authority` (`authority.Session`…) and the plain `auth.*` contract type where the port returns it |

If after this table one test still cannot be ported, keep it with a `t.Skip("<the exact symbol that no longer exists>")` and list it in the pull request; never delete it silently.

| Test | setup → call → expected |
|---|---|
| `TestUser_CreateThroughCrud` | `user.create` `&authority.User{Email: "a@x.cl", Name: "Ana"}` → no error; `m.GetUser(id)` has `Status == "active"`, `CreatedAt != 0` |
| `TestUser_DuplicateEmailIsAFieldError` | the same create twice → `failedField(err) == "email"` and `model.KindOf(err) == model.ErrorInvalid` or `ErrorConflict` (whatever `auth.ErrEmailTaken` is), never a 500 |
| `TestUser_EmaillessIsAllowed` | two creates with an empty `Email` → both succeed |
| `TestUser_UpdateOnlyNameAndPhone` | `user.update` `Fields: ["name"]` → ok and `m.GetUser` shows the new name (the cache was invalidated); `Fields: ["status"]` → `failedField(err) == "status"` |
| `TestUser_DeleteForgetsTheCache` | read it with `GetUser` (fills the cache), `user.delete` → `GetUser` answers `auth.ErrNotFound` |
| `TestUser_SearchByName` | two users; `user.read` with `Search: "An"` → only Ana |
| `TestLANIdentity_RegisterReadUnregister` | `lan_identity.create` `{UserId: u.Id, Rut: "<a valid RUT of the tests>"}` → ok, the answer carries the normalized RUT; `lan_identity.read` `ID: u.Id` → the same; `lan_identity.delete` `IDs: [u.Id]` → ok and `IdentityFor` answers `auth.ErrNotFound` |
| `TestLANIdentity_InvalidRutAndTaken` | an invalid RUT → `auth.ErrInvalidRUT`; the RUT of another user → `auth.ErrRUTTaken` |
| `TestMount_MatchesDefinition` | `crud.Mount(nil, nil, nil, m)` returns nil |

`docs/TESTS.md`: one row per `func Test…` of the repo (the tests index of `gotest` fails otherwise): `| [Name](../tests/file_test.go) | rule |` under `| Test | Rule |`, rules in English (`webtyp/*`).

## 4.2 Documentation (English, `webtyp/*`)

`README.md` (≤150 lines, 4 sections) and `docs/ARCHITECTURE.md` say: the root `auth` is the contract; `authority` owns the data models and mounts them through `crud`; the operations table of `PLAN.md` («Today» / «After»), and the permission change `users` → `user`. `langc sync .` with zero untranslated keys for `es` and zero reuse warnings.

## 4.3 Delivery

`gotest` green in the root module and in `tests/`; the greps of `PLAN.md` «Delivery check» empty; the pull request is open.
