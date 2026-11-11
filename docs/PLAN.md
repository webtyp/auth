---
PLAN: "refactor!: auth/authority on the crud-by-declaration framework — the data models move to authority, users and LAN identities through crud, /me as an Infra route"
EXECUTOR: jules
REVIEWER: none
STATUS: running
SESSION: 4625306544415130904
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work. Commit after every stage.
> Never run `git reset`, `git restore`, `git checkout -- <file>`, `git checkout HEAD <path>` or `git stash` on your own work: a previous session lost its whole migration with a `git checkout HEAD tests`.
> **Publishing:** you publish only by OPENING THE PULL REQUEST (a `git push` from your sandbox does not reach GitHub, and work not submitted is lost when the session ends). Open the PR after Stage 3 with whatever compiles and keep committing to it.
> **Never ask a yes/no question about progress** («am I on the right track?», «shall I proceed?», «does this approach sound correct?»): the answer is always yes. Ask only when a compile error or a signature in this plan is wrong, and name the symbol.
> **Before you submit:** `git status` must be clean and `git diff --stat main` must list the stage files (definition.go, rule_*.go, call_*.go, store.go, module.go, tests, docs). A pull request that carries only go.mod, go.sum or docs/PLAN.md is a failed delivery: if that is what your submit shows, `git add -A`, commit and submit again.
> Never edit `definition_gen.go`. Never write `go.mod`/`go.sum` lines by hand: only `go get` and `go mod tidy` do. No scratch files and no sed/regex/python scripts over the source: edit by hand, file by file, and run `gotest` after each file.

# Plan: `auth` — the data models move to `authority`, which mounts them through `crud`

Decided by the owner: the root package `auth` keeps only the **contract** (interfaces, `Config`, errors, security events, `ProfileDTO`, the form models `LoginData`… and `Path*`/`Provider*` constants). The data models and everything that serves them live in `authority`, next to `Module`. Why: `definitionc` writes `MountOperations()` as a method of `Module`, in the package that holds `definition.go`; today `Module` is in `authority` and the models in the root, so `definitionc .` finished without error and generated nothing (a previous session found it). The root cannot import `authority` (`authority` imports the root), so the models cannot stay in the root and reference `User`. **Nothing consumes this repo yet**: renaming is free; do it in one pass.

What moves: `User`, `Session`, `Identity`, `LANIP`, `OAuthState` (their `definition.go` models, with their foreign keys `Ref: &UserModel`, unchanged) and `LANIdentity` (a projection, not a table). The old argument models (`RegisterLANArgs`, `LANUserArgs`) and the old op constants (`OpListUsers`, `OpUpsertUser`, `OpDeleteUser`, `OpRegisterLAN`, `OpUnregisterLAN`, `OpGetLAN`, `OpMe`) and the root `ModelName` die.

## Rules learned from the failed sessions of this wave (read before starting)

1. **Do not write, summarize or iterate on a plan.** This index and the stage files are the finished spec. Start Stage 1 now.
2. **Read files by ranges** (`sed -n 1,80p file`, then `sed -n 81,160p file`); never one huge `cat`: its output is cut.
3. **A field a rule uses is the one in `definition_gen.go`:** `grep -n "type <Entity> struct" -A25 definition_gen.go`. `ServerOnly` only blocks the CLIENT: a rule may set any field of its receiver and of rows it creates with `tx.Create`. A field that does not exist is a question for the PR (name it), never an invention.
4. **No python, sed or regex over the source, ever** (two sessions died of a broken replacement in `credentials_lan.go`): open each file, edit it function by function with the editor, `go build ./authority/` after each file.

## Stages

| # | File | What | Files touched |
|---|---|---|---|
| 1 | [PLAN_STAGE_1_MOVE_MODELS.md](PLAN_STAGE_1_MOVE_MODELS.md) | tools; move the models; `authority/definition.go`; generate | `definition.go` (root), `authority/definition.go`, `authority/definition_gen.go`, `go.mod`, `go.sum` |
| 2 | [PLAN_STAGE_2_STORES_RULES.md](PLAN_STAGE_2_STORES_RULES.md) | stores, `lanStore`, the rule files, `/me` route | `authority/store.go`, `authority/rows.go`, `authority/lan_store.go`, `authority/rule_*.go`, `authority/mount.go` |
| 3 | [PLAN_STAGE_3_METHODS_IMPORTERS.md](PLAN_STAGE_3_METHODS_IMPORTERS.md) | the kept methods on the store; every importer of the moved types | `authority/*.go`, `oauth2/oauth.go`, `view.go` |

## Operation mapping

| Today | After |
|---|---|
| `me` (`OpMe`) | an authenticated GET route mounted in `authority/mount.go` (not an operation) |
| `list_users`, `upsert_user`, `delete_user` | `user.read`, `user.create` / `user.update`, `user.delete` (permission resource `user`; it was `users`: apps re-grant) |
| `register_lan`, `unregister_lan`, `get_lan` | `lan_identity.create`, `lan_identity.delete`, `lan_identity.read` (permission resource `lan_identity`, unchanged: it stays separate from user administration because registering a RUT mints a login credential) |

## Delivery check (part 1 of 2)

This plan is only Stages 1–3; the files `PLAN_STAGE_4_*.md` and later belong to the NEXT plan: ignore them. In this part you ALSO delete every test in `tests/` that calls a method or constant this migration removes (`go vet ./tests/` lists them) together with its row in `docs/TESTS.md`; the new tests are written in part 2. `gotest` passes on every destination (it builds, vets, races and runs every destination) — the root module must compile with no test of the removed code left. A tree that does not compile is a failed delivery. Submit as soon as it is green (git add -A; `git diff --stat main` lists the stage files).
