# AGENTS.md — webtyp/auth

Constraints for agents changing this library. Read before touching any file.

## What this repo is

Authentication and sessions for WebTyp applications (users, identities per provider, LAN/RUT login
over trusted IPs, OAuth2, email+password, JWT sessions). Authorization (roles, grants) belongs to
`webtyp/rbac`.

## It compiles to WASM

Parts of it (models such as `RUTLoginData`, the `authority` operations) compile for the server
**and** for `GOOS=js GOARCH=wasm` (TinyGo). Code that reaches the browser binary follows TinyGo's
constraints:

- **No `map`** in code compiled to wasm: use a slice with a linear scan, or `[]fmt.KeyValue`.
- **No reflection, ever**: no `reflect`, no `errors.Is` / `errors.As`, no `sort.Slice`, and no
  `==` / `!=` / `switch` between interface values with non-nil operands. Under TinyGo each of them
  pulls `internal/reflectlite` into the binary (`err == ErrX` included: `error` is an interface).
  Detect sentinels with their `IsX(err)` function (`auth.IsNotFound`, `orm.IsNotFound`, `storage.IsNoRows`).
- Strings and conversions through `webtyp.com/fmt`, not the standard library's `fmt`/`strconv`.

## Reuse before writing

Persistence goes through `webtyp.com/orm` / `webtyp.com/storage` (backend-agnostic `storage.Conn`);
never import a concrete backend outside tests. A missing piece in a base library is fixed there,
never re-implemented here.

## The build that defines "done"

```bash
go install webtyp.com/devflow/cmd/gotest@latest   # once
gotest
```

## Rules

- Tests live in `tests/`. A root-level test is allowed only with a top-of-file comment justifying the
  unexported identifier it needs. Never export a symbol so a test can reach it.
- Every repeated string (error text, keys) is a named constant.
