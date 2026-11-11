---
PLAN: "refactor!: auth/authority on the crud-by-declaration framework — the data models move to authority, users and LAN identities through crud, /me as an Infra route"
EXECUTOR: jules
REVIEWER: none
STATUS: review
SESSION: 12452980448774497843
PR: https://github.com/webtyp/auth/pull/16
REVIEWED_COMMIT: 1f7773501850ba9b77cb190366695e4f9a4aa4fa
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work. Commit after every stage.
> Never run `git reset`, `git restore`, `git checkout -- <file>`, `git checkout HEAD <path>` or `git stash` on your own work: a previous session lost its whole migration with a `git checkout HEAD tests`.
> **Publishing:** you publish only by OPENING THE PULL REQUEST (a `git push` from your sandbox does not reach GitHub, and work not submitted is lost when the session ends). Open the PR after Stage 3 with whatever compiles and keep committing to it.
> **Never ask a yes/no question about progress** («am I on the right track?», «shall I proceed?», «does this approach sound correct?»): the answer is always yes. Ask only when a compile error or a signature in this plan is wrong, and name the symbol.
> Never edit `definition_gen.go`. Never write `go.mod`/`go.sum` lines by hand: only `go get` and `go mod tidy` do. No scratch files and no sed/regex/python scripts over the source: edit by hand, file by file, and run `gotest` after each file.

# Plan: `auth` — the data models move to `authority`, which mounts them through `crud`

Decided by the owner: the root package `auth` keeps only the **contract** (interfaces, `Config`, errors, security events, `ProfileDTO`, the form models `LoginData`… and `Path*`/`Provider*` constants). The data models and everything that serves them live in `authority`, next to `Module`. Why: `definitionc` writes `MountOperations()` as a method of `Module`, in the package that holds `definition.go`; today `Module` is in `authority` and the models in the root, so `definitionc .` finished without error and generated nothing (a previous session found it). The root cannot import `authority` (`authority` imports the root), so the models cannot stay in the root and reference `User`. **Nothing consumes this repo yet**: renaming is free; do it in one pass.

What moves: `User`, `Session`, `Identity`, `LANIP`, `OAuthState` (their `definition.go` models, with their foreign keys `Ref: &UserModel`, unchanged) and `LANIdentity` (a projection, not a table). The old argument models (`RegisterLANArgs`, `LANUserArgs`) and the old op constants (`OpListUsers`, `OpUpsertUser`, `OpDeleteUser`, `OpRegisterLAN`, `OpUnregisterLAN`, `OpGetLAN`, `OpMe`) and the root `ModelName` die.

## Stages

| # | File | What | Files touched |
|---|---|---|---|
| 1 | [PLAN_STAGE_1_MOVE_MODELS.md](PLAN_STAGE_1_MOVE_MODELS.md) | tools; move the models; `authority/definition.go`; generate | `definition.go` (root), `authority/definition.go`, `authority/definition_gen.go`, `go.mod`, `go.sum` |
| 2 | [PLAN_STAGE_2_STORES_RULES.md](PLAN_STAGE_2_STORES_RULES.md) | stores, `lanStore`, the rule files, `/me` route | `authority/store.go`, `authority/rows.go`, `authority/lan_store.go`, `authority/rule_*.go`, `authority/mount.go` |
| 3 | [PLAN_STAGE_3_METHODS_IMPORTERS.md](PLAN_STAGE_3_METHODS_IMPORTERS.md) | the kept methods on the store; every importer of the moved types | `authority/*.go`, `oauth2/oauth.go`, `view.go` |
| 4 | [PLAN_STAGE_4_TESTS_DOCS.md](PLAN_STAGE_4_TESTS_DOCS.md) | tests (`tests/` is a nested module), `docs/TESTS.md`, README, architecture | `tests/*.go`, `docs/*`, `README.md` |

## Operation mapping

| Today | After |
|---|---|
| `me` (`OpMe`) | an authenticated GET route mounted in `authority/mount.go` (not an operation) |
| `list_users`, `upsert_user`, `delete_user` | `user.read`, `user.create` / `user.update`, `user.delete` (permission resource `user`; it was `users`: apps re-grant) |
| `register_lan`, `unregister_lan`, `get_lan` | `lan_identity.create`, `lan_identity.delete`, `lan_identity.read` (permission resource `lan_identity`, unchanged: it stays separate from user administration because registering a RUT mints a login credential) |

## Delivery check

1. `gotest` ends green on EVERY destination, in the root module AND in `tests/` (nested module, its own `go.mod`).
2. `grep -rn "auth\.User\b\|auth\.Session\b\|auth\.Identity\b\|auth\.LANIP\b\|auth\.OAuthState\b\|auth\.LANIdentity\b\|OpUpsertUser\|OpListUsers\|reg.Operation\|router.OperationRegistry" --include=*.go . | grep -v "definition_gen"` → empty.
3. `ls authority/definition_gen.go` exists and contains `func (m *Module) MountOperations(`.
4. `git diff --stat main --diff-filter=D` lists only the deleted old files named in the stages.
