---
PLAN: "feat: authority.Module.ListUsers — every user, for screens that pick a person"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 12421134209932989562
---

> Read AGENTS.md at the repo root before any change.

# `authority.Module.ListUsers`

## Context

`webtyp/access` (the role administration) will let an administrator give a role to a person **picked from a list of
the app's users**, instead of typing an e-mail: LAN staff log in with their national ID and have no e-mail. To build
that list, `access` needs to read every user through a method of `*authority.Module`, the same way it already calls
`UserByID`, `UserByEmail` and `CreateUser` (`authority/ports.go`). The list exists today only as the unexported
`listUsers(db)` (`authority/users.go:147`), used by the `list_users` operation. This plan exports it as a method —
nothing else changes.

## Tools

```bash
go install webtyp.com/devflow/cmd/gotest@latest
```

Environment: `GOPRIVATE=webtyp.com/*,github.com/veltylabs/*`, `GOFLAGS=-mod=mod`.

## Ecosystem search

Searched `ListUsers`, `listUsers`, `AllUsers` over `webtyp/` and `veltylabs/`: only the unexported
`authority.listUsers` and the `auth.OpListUsers` operation exist. **Extend** `authority` with one method that calls it.

## Design gate

1. **Prior art.** Django's `User.objects.all()`, Keycloak's admin `GET /users` and Firebase Admin `listUsers()` all
   expose the full user list to administrative code (unverified: pages not read in this session). Same here.
2. **Novice name.** `m.ListUsers()` next to `m.UserByID(id)` and `m.UserByEmail(email)`.
3. **Complexity ledger.** Concepts +0 (a list of the type already returned by `UserByID`) · ways to do the same +0
   (`opListUsers` calls the same function).
4. **Where it belongs.** `authority`, owner of the user table.
5. **Deletes.** Nothing; the stale doc section "Email-less users — not supported yet" is rewritten.

## APIs used

| Symbol | Exact signature | File |
|---|---|---|
| `listUsers` (unexported) | `func listUsers(db *orm.DB) ([]auth.User, error)` | `authority/users.go:147` |
| `authority.New` | `func New(db *orm.DB, cfg auth.Config) (*Module, error)` | `authority/` |
| `(*Module).CreateUser` | `func (m *Module) CreateUser(email, name, phone string) (auth.User, error)` | `authority/ports.go` |
| `newTestDB` (test helper) | `func newTestDB(t *testing.T) *orm.DB` — sqlite in memory, migrated | `tests/suite_back_test.go:21` |
| `sqlite.Open` | `func Open(dsn string) (...)` as used in `tests/suite_back_test.go:22`; the returned connection has `Close()` | `webtyp.com/sqlite` |

If a signature differs, stop and name the symbol in the PR; never adapt it by guessing.

## Stage 1 — tests first: `tests/list_users_test.go` (new)

`//go:build !wasm`, `package tests`. Imports: `testing`, `webtyp.com/auth`, `webtyp.com/auth/authority`,
`webtyp.com/ddl`, `webtyp.com/orm`, `webtyp.com/sqlite`. After this stage `gotest` does not compile (`ListUsers` missing) — expected.

| Test | Setup | Call | Expected |
|---|---|---|---|
| `TestListUsers_Empty` | `m, _ := authority.New(newTestDB(t), auth.Config{IDs: testIDs})` | `m.ListUsers()` | `err == nil`, `len == 0` |
| `TestListUsers_WithAndWithoutEmail` | same `m`; `a, _ := m.CreateUser("", "Staff One", "")`; `b, _ := m.CreateUser("ana@example.com", "Ana", "")` | `m.ListUsers()` | `err == nil`, `len == 2`, the ids `a.Id` and `b.Id` both present (order not asserted), each with its `Name` |
| `TestListUsers_DatabaseClosed` | `conn, _ := sqlite.Open(":memory:")`; `db := orm.New(conn)`; `authority.Migrate(db.RawConn(), db.RawConn().(ddl.Compiler))`; `m, _ := authority.New(db, auth.Config{IDs: testIDs})`; `conn.Close()` | `m.ListUsers()` | `err != nil` and the returned slice is `nil` |

Commit after this stage.

## Stage 2 — `authority/ports.go`

Add, right after `UserByEmail`:

```go
// ListUsers returns every user of the app, with or without e-mail — what a
// screen that picks a person (e.g. "give this role to…") lists.
// Example: users, err := authMod.ListUsers()
func (m *Module) ListUsers() ([]auth.User, error) { return listUsers(m.db) }
```

Run `gotest`: the three tests pass. Commit after this stage.

## Stage 3 — docs

- `docs/ARCHITECTURE.md`: replace the section `## Email-less users — not supported yet` (its text is obsolete:
  `tests/emailless_users_test.go` proves two users without e-mail coexist) with `## Email-less users` and two
  sentences: LAN staff are users without e-mail (the column stores NULL, so it stays unique); `UserByEmail("")` always
  returns `ErrNotFound`, because an empty e-mail is not a lookup key (keep the existing explanation about `oauth2`).
  Add one line: `ListUsers()` lists every user, with or without e-mail.
- `README.md`: if it lists the `Module` methods, add `ListUsers`.

Commit after this stage.

## Delivery check

1. `gotest` passes. A PR that does not compile, or whose tests could not run, is a failed delivery.
2. `grep -n "func (m \*Module) ListUsers" authority/ports.go` → one match.
3. `git diff --stat main` lists only `tests/list_users_test.go`, `authority/ports.go`, `docs/ARCHITECTURE.md` and possibly `README.md`.

## Delivery rules

- Never pause to ask permission or report progress: when the delivery check passes, commit, push and open the PR. Stuck
  for 30 minutes: open the PR anyway, listing what fails.
- Commit after every stage. Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
- Do not change `listUsers`, `opListUsers` or any other file.

## Stages

| # | Files | Result |
|---|---|---|
| 1 | `tests/list_users_test.go` | Empty, two users (with and without e-mail), closed database |
| 2 | `authority/ports.go` | `ListUsers`; green |
| 3 | `docs/ARCHITECTURE.md`, `README.md` | Docs current |

## Executor notes

- `README.md` did not list the `Module` methods, so no additions were made to it.
