---
PLAN: "chore: auth after the authority/crud migration — translations and documentation check (part 2 of 2)"
EXECUTOR: jules
REVIEWER: none
---

> Read AGENTS.md at the repo root before any change.
> **Finish by yourself:** when the delivery check passes, commit, push and open the pull request. Never ask whether to
> proceed or finalize — nobody answers, and a session that waits ends without your work. Commit after every stage.
> Never run `git reset`, `git restore`, `git checkout -- <file>` or `git stash` on your own work.
> **Publishing:** you publish only by OPENING THE PULL REQUEST. Submit after the first stage and keep committing.
> **Never ask a yes/no question about progress.**
> **Before you submit:** `git status` must be clean and `git diff --stat main` must list the files you changed.

# Plan: `auth` — translations and documentation check

The migration itself is done and `gotest` is green: the data models live in `authority` (`definition.go`, generated `definition_gen.go`), users and LAN identities are mounted through `crud` (`rule_user_*.go`, `store.go`, `lan_store.go`), `/me` is the authenticated route `GET auth.PathMe`, and the root package keeps the contract (plain `User`, `Identity`, `Session`). Do NOT change code. Two small stages:

## Tools

```bash
go install webtyp.com/lang/cmd/langc@latest
export PATH="$PATH:$(go env GOPATH)/bin"
```

## Stage 1 — translations

Run `langc sync .` at the root. It must report zero untranslated keys and zero reuse warnings: fill every empty value it lists (all languages of `lang.json`) and reuse words already there. Commit.

## Stage 2 — documentation

`README.md` (≤150 lines) and `docs/ARCHITECTURE.md` must describe: the root `auth` is the contract; `authority` owns the data models and mounts `user` and `lan_identity` through `crud`; the permission resource of user administration is `user` (it was `users`: apps re-grant it); `GET /me` replaces the `me` operation. Check with `grep -n "list_users\|upsert_user\|delete_user\|users\"" README.md docs/ARCHITECTURE.md`: any remaining old name is replaced. Keep each file's section order. Commit.

## Delivery check

`gotest` passes; `langc sync .` is clean; the pull request is open.
