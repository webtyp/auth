← [Stage 2](PLAN_STAGE_2_STORES_RULES.md) | Next → [Stage 4](PLAN_STAGE_4_TESTS_DOCS.md)

# Stage 3 — the kept methods on the store; every importer of the moved types

## 3.1 The kept methods (`authority/users.go`, `identities.go`, `sessions.go`, `credentials_*.go`, `export.go`, `cache_users.go`, `migrate.go`)

Every exported method keeps its name and signature (other packages call them: `GetUser`, `GetUserByEmail`, `RegisterLAN`, `IdentityFor`, …). The types they use change package: **inside `authority`, `auth.User` → `User`, `auth.Session` → `Session`, `auth.Identity` → `Identity`, `auth.LANIP` → `LANIP`, `auth.OAuthState` → `OAuthState`, `auth.LANIdentity` → `LANIdentity`, and the column constants `auth.User_` → `User_`, etc.** Do it file by file with the compiler (`go build ./authority`), by hand, no sed/regex scripts. A call to a removed generated helper (`auth.ReadAllUser(qb)`, `ReadOne…`) is translated with this table:

| Old | New |
|---|---|
| `qb := db.Query(&auth.User{}).Where(auth.User_.Id).Eq(id)` + `auth.ReadAllUser(qb)` | `rows, err := allRows(m.users, func() model.Model { return &User{} }, func(r model.Model) string { return r.(*User).Id }, storage.Eq(User_.Id, id))` (a `firstRow` when one row is wanted) |
| `db.Create(&u)` / `db.Update(u, orm.Eq(auth.User_.Id, u.Id))` / `db.Delete(u, orm.Eq(…))` | `m.users.Create(&u)` / `m.users.UpdateFields(&u, u.Id, cols)` / `m.users.Delete(&u, u.Id)` (the columns the old code changed) |
| a write of `Session`, `Identity`, `LANIP`, `OAuthState` | UNCHANGED (`m.db`): they are internal tables written by the module |

`createUser(db, ids, …)` and its siblings (`updateUser`, `deleteUser`, `suspendUser`…) become methods or take `m.users` as the store; their cache invalidation (`ucache.Delete`) stays. `isUniqueViolation` stays: a duplicate e-mail through `createUser` still answers `auth.ErrEmailTaken`. In `migrate.go`: `&auth.User{}` → `&User{}`, etc. (same dependency order).

## 3.2 Importers of the moved types

| File | Change |
|---|---|
| `oauth2/oauth.go:142` | `var u auth.User` → `var u authority.User` (import `webtyp.com/auth/authority`; `authority` does not import `oauth2`: no cycle) |
| root `view.go` (`NewView`) | MOVE it to `authority/view.go` (it presents `User`): `view.Ops{Module: ModelName, Page: view.Page{First: view.All}}`, `func() model.TableSlice { return &UserList{} }`, `view.New(b, &User{}, view.WithTitle("Usuarios"))`; delete the root `view.go` |
| `tests/*.go` (nested module) | Stage 4 |
| other repos (`access`, `misitio`) | NOT in this plan: they change in their own plans |

If a package below `authority` in the import graph (`session/cookie`, `passkey`, `cfaccess`, …) needs a moved type and importing `authority` would create a cycle, do NOT import it: declare in THAT package a narrow interface with plain types (what it needs from a user) and let `authority` satisfy it; name the file and symbol in the PR.

`go build ./...` and `go vet ./...` end clean in the root module. Commit and push.
