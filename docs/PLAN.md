---
PLAN: "refactor!: authority on the closed crud contract (users, LAN identity); /me as an Infra route; view.go browser-only"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 8600479642742704008
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit after every stage and stop. Never ask whether to
> proceed. This plan runs **locally**: do not tag, push or publish anything; the owner reviews first.
> Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.

# Plan: `webtyp/auth` on `crud.Registry`

Context: master `webtyp/docs/ARCHITECTURE_MASTER_PLAN.md` D2, D3, D7–D14. Runs after the appkit, ormc and view plans, before access.

## Tools and local dependencies

```bash
go install webtyp.com/devflow/cmd/gotest@latest
go install webtyp.com/lang/cmd/langc@latest
(cd ../ormc && go install ./cmd/ormc)
```
`go.mod`: `replace` for `webtyp.com/model`, `router`, `crud`, `rpc`, `view` to the sibling folders; `go mod tidy`; run `ormc`. Never edit generated files.

## APIs used

Same `crud.Registry` / `crud.Caller` / `crud.ReadArgs` table as the access plan (`webtyp/access/docs/PLAN.md`); generated
`MountUserCreate/Read/Update/Delete` in `model_crud.go` (check the exact names after `ormc`).

## Operation mapping

| Today (`authority/ops.go`) | After | Resource / action |
|---|---|---|
| `me` (`.Authenticated()`) | **not an operation**: `MountAPI` registers `r.Post("/api/"+m.ModelName()+"/"+auth.OpMe, m.opMe).Authenticated()` (same path the browser calls today, so clients do not change) | authenticated |
| `list_users` (`Requires("users", Read)`) | `user_r` (`ReadArgs.ID` = one user) | `user` / Read |
| `upsert_user` (Create\|Update) | `user_c` + `user_u` | `user` / Create, Update |
| `delete_user` | `user_d` | `user` / Delete |
| `register_lan` | `lan_identity_c` over a wire Definition `LANIdentityModel` (`Name: "lan_identity"`, fields `id` = user id PK Text NotNull, `rut` Text NotNull; replaces `RegisterLANArgsModel`) | `lan_identity` / Create |
| `unregister_lan` | `lan_identity_d` (`ids` = user ids) | Delete |
| `get_lan` | `lan_identity_r` (`ReadArgs.ID` = user id) | Read |

Resource names change: `"users"` → `"user"` (the `User` ModelName). Grep every app grant/policy in this repo for `"users"`
and update it; record the change in README (apps granting `users` explicitly must grant `user`).

## Explicit deletions

`OpListUsers`, `OpUpsertUser`, `OpDeleteUser`, `OpRegisterLAN`, `OpUnregisterLAN`, `OpGetLAN` (`user.go`); `RegisterLANArgsModel`,
`LANUserArgsModel` and their generated types; handlers `opListUsers`, `opUpsertUser`, `opDeleteUser` and `ops_lan.go` handlers;
`var _ router.OperationModule`. Keep `OpMe` (now a path segment). Renames (D2): `listUsers`→`readUsers(db, id, search, after, limit)`;
`tests/list_users_test.go`→`tests/read_users_test.go`. Grep: `grep -rn "reg.Operation\|OperationModule\|view.ListArgs" --include=*.go .` → empty.

## Stage 1 — `authority/ops.go`, `authority/ops_lan.go`, `authority/mount.go`

`MountOperations(reg crud.Registry)` mounts the six rows above (`var _ crud.Module = (*Module)(nil)`); creating a LAN identity
calls the existing register logic with `rec.Id`, `rec.Rut`; the actor is `c.UserID` where today's code reads `ctx.UserID()`.
`MountAPI` (`mount.go`) keeps logout and adds `/me` as in the table. `authority` must not be mounted by `appkit` as an API module
automatically any more: the app adds it through `access.Infra` (access plan).

## Stage 2 — `view.go` (`//go:build browser`), tests, translations, docs

`view.go` first line `//go:build browser`; `view.Ops{Module: ModelName, Allow: model.Create | model.Update | model.Delete, Page: view.Page{First: view.All}}`.
Tests through `crud.LoopbackActingAs`; new (rows in `docs/TESTS.md`):
- `TestMe_IsInfraRoute`: `rpc.Routes("/api", nil, mod)` has no `.../me` route; a router mock after `mod.MountAPI(r)` has `POST /api/<ModelName>/me` authenticated.
- `TestLANIdentity_CreateReadDelete`: create `{id:"u1", rut:"12.345.678-5"}` → read `ID:"u1"` returns the normalized RUT → delete `["u1"]` → read returns not found.
`langc sync .` clean; `README.md` (4 sections, ≤150 lines) and `docs/ARCHITECTURE.md` updated with the mapping.

## Delivery check

`gotest` passes; `langc sync .` clean; grep criteria empty.

| Stage | Files |
|---|---|
| 1 | `authority/ops.go`, `authority/ops_lan.go`, `authority/mount.go`, `authority/users.go`, `user.go`, `models.go`, generated files |
| 2 | `view.go`, `tests/*.go`, `docs/TESTS.md`, `lang.json`, `README.md`, `docs/ARCHITECTURE.md` |
